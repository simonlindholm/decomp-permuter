import argparse
import copy
import difflib
from enum import Enum
import functools
import itertools
import multiprocessing
import os
import threading
import random
from random import Random
import re
import sys
import time
import traceback
from typing import (
    Any,
    List,
    Dict,
    Optional,
    Callable,
    Optional,
    Tuple,
    Iterable,
    Iterator,
    Union,
)

import attr
import pycparser
from pycparser import CParser, c_ast as ca

from .candidate import Candidate, CandidateResult
from .compiler import Compiler
from .error import CandidateConstructionFailure
from .net.auth import get_servers_and_grant, run_vouch, setup
from .net.client import connect_to_servers
from .perm import perm_eval, perm_gen
from .perm.perm import EvalState
from .preprocess import preprocess
from .profiler import Profiler
from .scorer import Scorer

# The probability that the randomizer continues transforming the output it
# generated last time.
DEFAULT_RAND_KEEP_PROB = 0.6


@attr.s
class Options:
    directories: List[str] = attr.ib()
    show_errors: bool = attr.ib(default=False)
    show_timings: bool = attr.ib(default=False)
    print_diffs: bool = attr.ib(default=False)
    stack_differences: bool = attr.ib(default=False)
    abort_exceptions: bool = attr.ib(default=False)
    stop_on_zero: bool = attr.ib(default=False)
    keep_prob: float = attr.ib(default=DEFAULT_RAND_KEEP_PROB)
    force_seed: Optional[str] = attr.ib(default=None)
    threads: int = attr.ib(default=1)
    use_network: bool = attr.ib(default=False)
    network_priority: float = attr.ib(default=1.0)


def restricted_float(lo: float, hi: float) -> Callable[[str], float]:
    def convert(x: str) -> float:
        try:
            ret = float(x)
        except ValueError:
            raise argparse.ArgumentTypeError(f"invalid float value: '{x}'")

        if ret < lo or ret > hi:
            raise argparse.ArgumentTypeError(
                f"value {x} is out of range (must be between {lo} and {hi})"
            )
        return ret

    return convert


def find_fns(source: str) -> List[str]:
    fns = re.findall(r"(\w+)\([^()\n]*\)\s*?{", source)
    return [
        fn
        for fn in fns
        if not fn.startswith("PERM") and fn not in ["if", "for", "switch", "while"]
    ]


@attr.s
class EvalError:
    exc_str: str = attr.ib()
    seed: Optional[Tuple[int, int]] = attr.ib()


EvalResult = Union[CandidateResult, EvalError]


class Permuter:
    """
    Represents a single source from which permutation candidates can be generated,
    and which keeps track of good scores achieved so far.
    """

    def __init__(
        self,
        dir: str,
        fn_name: Optional[str],
        compiler: Compiler,
        scorer: Scorer,
        source_file: str,
        source: str,
        *,
        force_rng_seed: Optional[int],
        keep_prob: float,
        need_all_sources: bool,
    ) -> None:
        self.dir = dir
        self.random = Random()
        self.compiler = compiler
        self.scorer = scorer
        self.source_file = source_file

        if fn_name is None:
            fns = find_fns(source)
            if len(fns) == 0:
                raise Exception(f"{self.source_file} does not contain any function!")
            if len(fns) > 1:
                raise Exception(
                    f"{self.source_file} must contain only one function, "
                    "or have a function.txt next to it with a function name."
                )
            self.fn_name = fns[0]
        else:
            self.fn_name = fn_name
        self.unique_name = self.fn_name

        self.parser = pycparser.CParser()
        self.permutations = perm_gen.perm_gen(source)

        self.force_rng_seed = force_rng_seed
        self.cur_seed: Optional[Tuple[int, int]] = None

        self.keep_prob = keep_prob
        self.need_all_sources = need_all_sources

        self.base, base_score, self.base_hash = self.create_and_score_base()
        self.hashes = {self.base_hash}
        self.cand: Optional[Candidate] = None
        self.base_score: int = base_score
        self.best_score: int = base_score
        self._last_score: Optional[int] = None

    def reseed_random(self) -> None:
        self.random = Random()

    def create_and_score_base(self) -> Tuple[Candidate, int, str]:
        base_source = perm_eval.perm_evaluate_one(self.permutations)
        base_cand = Candidate.from_source(
            base_source, self.fn_name, self.parser, rng_seed=0
        )
        o_file = base_cand.compile(self.compiler, show_errors=True)
        if not o_file:
            raise Exception(f"Unable to compile {self.source_file}")
        base_result = base_cand.score(self.scorer, o_file)
        return base_cand, base_result.score, base_result.hash

    def need_to_send_source(self, result: CandidateResult) -> bool:
        if self.need_all_sources:
            return True
        if result.score < self.base_score:
            return True
        if result.score == self.base_score:
            return result.hash != self.base_hash
        return False

    def eval_candidate(self, seed: int) -> CandidateResult:
        t0 = time.time()

        # Determine if we should keep the last candidate.
        # Don't keep 0-score candidates; we'll only create new, worse, zeroes.
        keep = (
            self.permutations.is_random()
            and self.random.uniform(0, 1) < self.keep_prob
            and self._last_score != 0
        ) or self.force_rng_seed

        self._last_score = None

        # Create a new candidate if we didn't keep the last one (or if the last one didn't exist)
        # N.B. if we decide to keep the previous candidate, we will skip over the provided seed.
        # This means we're not guaranteed to test all seeds, but it doesn't really matter since
        # we're randomizing anyway.
        if not self.cand or not keep:
            cand_c = self.permutations.evaluate(seed, EvalState())
            rng_seed = self.force_rng_seed or random.randrange(1, 10 ** 20)
            self.cur_seed = (seed, rng_seed)
            self.cand = Candidate.from_source(
                cand_c, self.fn_name, self.parser, rng_seed=rng_seed
            )

        # Randomize the candidate
        if self.permutations.is_random():
            self.cand.randomize_ast()

        t1 = time.time()

        self.cand.get_source()

        t2 = time.time()

        o_file = self.cand.compile(self.compiler)

        t3 = time.time()

        result = self.cand.score(self.scorer, o_file)

        t4 = time.time()

        profiler: Profiler = result.profiler
        profiler.add_stat(Profiler.StatType.perm, t1 - t0)
        profiler.add_stat(Profiler.StatType.stringify, t2 - t1)
        profiler.add_stat(Profiler.StatType.compile, t3 - t2)
        profiler.add_stat(Profiler.StatType.score, t4 - t3)

        self._last_score = result.score

        if not self.need_to_send_source(result):
            result.source = None

        return result

    def try_eval_candidate(self, seed: int) -> EvalResult:
        try:
            return self.eval_candidate(seed)
        except Exception:
            return EvalError(exc_str=traceback.format_exc(), seed=self.cur_seed)

    def base_source(self) -> str:
        return self.base.get_source()

    def diff(self, other_source: str) -> str:
        # Return a unified white-space-ignoring diff
        class Line(str):
            def __eq__(self, other: Any) -> bool:
                return isinstance(other, str) and self.strip() == other.strip()

            def __hash__(self) -> int:
                return hash(self.strip())

        a = list(map(Line, self.base_source().split("\n")))
        b = list(map(Line, other_source.split("\n")))
        return "\n".join(
            difflib.unified_diff(a, b, fromfile="before", tofile="after", lineterm="")
        )


@attr.s
class EvalContext:
    options: Options = attr.ib()
    iteration: int = attr.ib(default=0)
    errors: int = attr.ib(default=0)
    overall_profiler: Profiler = attr.ib(factory=Profiler)
    permuters: List[Permuter] = attr.ib(factory=list)


def write_candidate(perm: Permuter, result: CandidateResult) -> None:
    """Write the candidate's C source and score to the next output directory"""
    ctr = 0
    while True:
        ctr += 1
        try:
            output_dir = os.path.join(perm.dir, f"output-{result.score}-{ctr}")
            os.mkdir(output_dir)
            break
        except FileExistsError:
            pass
    source = result.source
    assert source is not None, "need_to_send_source is wrong!"
    with open(os.path.join(output_dir, "source.c"), "x", encoding="utf-8") as f:
        f.write(source)
    with open(os.path.join(output_dir, "base.c"), "x", encoding="utf-8") as f:
        f.write(perm.base_source())
    with open(os.path.join(output_dir, "score.txt"), "x", encoding="utf-8") as f:
        f.write(f"{result.score}\n")
    with open(os.path.join(output_dir, "diff.txt"), "x", encoding="utf-8") as f:
        f.write(perm.diff(source) + "\n")
    print(f"wrote to {output_dir}")


def post_score(context: EvalContext, permuter: Permuter, result: EvalResult) -> bool:
    if isinstance(result, EvalError):
        print(f"\n[{permuter.unique_name}] internal permuter failure.")
        print(result.exc_str)
        if result.seed is not None:
            seed_str = str(result.seed[1])
            if result.seed[0] != 0:
                seed_str = f"{result.seed[0]},{seed_str}"
            print(f"To reproduce the failure, rerun with: --seed {seed_str}")
        if context.options.abort_exceptions:
            sys.exit(1)
        else:
            return False

    profiler = result.profiler
    score_value = result.score
    score_hash = result.hash

    if context.options.print_diffs:
        assert result.source is not None, "need_to_send_source is wrong"
        print()
        print(permuter.diff(result.source))
        input("Press any key to continue...")

    context.iteration += 1
    if score_value is None:
        context.errors += 1
    disp_score = "inf" if score_value == permuter.scorer.PENALTY_INF else score_value
    timings = ""
    if context.options.show_timings:
        for stattype in profiler.time_stats:
            context.overall_profiler.add_stat(stattype, profiler.time_stats[stattype])
        timings = "  \t" + context.overall_profiler.get_str_stats()
    status_line = f"iteration {context.iteration}, {context.errors} errors, score = {disp_score}{timings}"

    # Note: when updating this if condition, need_to_send_source may also need
    # to be updated, or else assertion failures will result.
    if (
        score_value is not None
        and score_hash is not None
        and score_value <= permuter.base_score
        and score_hash not in permuter.hashes
    ):
        if score_value != 0:
            permuter.hashes.add(score_hash)
        print("\r" + " " * (len(status_line) + 10) + "\r", end="")
        if score_value < permuter.best_score:
            print(
                f"\u001b[32;1m[{permuter.unique_name}] found new best score! ({score_value} vs {permuter.base_score})\u001b[0m"
            )
        elif score_value == permuter.best_score:
            print(
                f"\u001b[32;1m[{permuter.unique_name}] tied best score! ({score_value} vs {permuter.base_score})\u001b[0m"
            )
        elif score_value < permuter.base_score:
            print(
                f"\u001b[33m[{permuter.unique_name}] found a better score! ({score_value} vs {permuter.base_score})\u001b[0m"
            )
        else:
            print(
                f"\u001b[33m[{permuter.unique_name}] found different asm with same score ({score_value})\u001b[0m"
            )
        permuter.best_score = min(permuter.best_score, score_value)
        write_candidate(permuter, result)
    print("\b" * 10 + " " * 10 + "\r" + status_line, end="", flush=True)
    return score_value == 0


def cycle_seeds(
    permuters: List[Permuter], force_seed: Optional[int]
) -> Iterable[Tuple[int, int]]:
    """
    Return all possible (permuter index, seed) pairs, cycling over permuters.
    If a permuter is randomized, it will keep repeating seeds infinitely.
    """
    iterators: List[Iterator[Tuple[int, int]]] = []
    for perm_ind, permuter in enumerate(permuters):
        it: Iterable[int]
        if not force_seed:
            it = perm_eval.perm_gen_all_seeds(permuter.permutations, Random())
        elif permuter.permutations.is_random():
            it = itertools.repeat(force_seed)
        else:
            it = [force_seed]
        iterators.append(zip(itertools.repeat(perm_ind), it))

    i = 0
    while iterators:
        i %= len(iterators)
        item = next(iterators[i], None)
        if item is None:
            del iterators[i]
            i -= 1
        else:
            yield item
            i += 1


class NeedMoreWork:
    pass


class Finished:
    pass


Task = Union[Finished, Tuple[int, int]]
Feedback = Union[NeedMoreWork, Finished, Tuple[int, EvalResult]]


def multiprocess_worker(
    permuters: List[Permuter],
    input_queue: "multiprocessing.Queue[Task]",
    output_queue: "multiprocessing.Queue[Feedback]",
) -> None:
    input_queue.cancel_join_thread()
    output_queue.cancel_join_thread()

    # Don't use the same RNGs as the parent
    for permuter in permuters:
        permuter.reseed_random()

    try:
        should_block = False
        while True:
            # Read a work item from the queue. If none is immediately available,
            # tell the main thread to fill the queues more, and then block on
            # the queue.
            queue_item = input_queue.get(block=should_block)
            if queue_item is None:
                output_queue.put(NeedMoreWork())
                should_block = True
                continue
            should_block = False
            if isinstance(queue_item, Finished):
                output_queue.put(queue_item)
                break
            permuter_index, seed = queue_item
            permuter = permuters[permuter_index]
            result = permuter.try_eval_candidate(seed)
            output_queue.put((permuter_index, result))
    except KeyboardInterrupt:
        # Don't clutter the output with stack traces; Ctrl+C is the expected
        # way to quit and sends KeyboardInterrupt to all processes.
        # A heartbeat thing here would be good but is too complex.
        pass


def run(options: Options) -> List[int]:
    last_time = time.time()
    try:

        def heartbeat() -> None:
            nonlocal last_time
            last_time = time.time()

        return run_inner(options, heartbeat)
    except KeyboardInterrupt:
        if time.time() - last_time > 5:
            print()
            print("Aborting stuck process.")
            traceback.print_exc()
            sys.exit(1)
        print()
        print("Exiting.")
        sys.exit(0)


def run_inner(options: Options, heartbeat: Callable[[], None]) -> List[int]:
    print("Loading...")

    context = EvalContext(options)

    force_rng_seed: Optional[int] = None
    force_seed: Optional[int] = None
    if options.force_seed:
        seed_parts = list(map(int, options.force_seed.split(",")))
        force_rng_seed = seed_parts[-1]
        force_seed = 0 if len(seed_parts) == 1 else seed_parts[0]

    name_counts: Dict[str, int] = {}
    for i, d in enumerate(options.directories):
        heartbeat()
        compile_cmd = os.path.join(d, "compile.sh")
        target_o = os.path.join(d, "target.o")
        base_c = os.path.join(d, "base.c")
        for fname in [compile_cmd, target_o, base_c]:
            if not os.path.isfile(fname):
                print(f"Missing file {fname}", file=sys.stderr)
                sys.exit(1)
        if not os.stat(compile_cmd).st_mode & 0o100:
            print(f"{compile_cmd} must be marked executable.", file=sys.stderr)
            sys.exit(1)

        fn_name: Optional[str] = None
        try:
            with open(os.path.join(d, "function.txt"), encoding="utf-8") as f:
                fn_name = f.read().strip()
        except FileNotFoundError:
            pass

        if fn_name:
            print(f"{base_c} ({fn_name})")
        else:
            print(base_c)

        compiler = Compiler(compile_cmd, options.show_errors)
        scorer = Scorer(target_o, stack_differences=options.stack_differences)
        c_source = preprocess(base_c)

        try:
            permuter = Permuter(
                d,
                fn_name,
                compiler,
                scorer,
                base_c,
                c_source,
                force_rng_seed=force_rng_seed,
                keep_prob=options.keep_prob,
                need_all_sources=options.print_diffs,
            )
        except CandidateConstructionFailure as e:
            print(e.message, file=sys.stderr)
            sys.exit(1)

        context.permuters.append(permuter)
        name_counts[permuter.fn_name] = name_counts.get(permuter.fn_name, 0) + 1
    print()

    for permuter in context.permuters:
        if name_counts[permuter.fn_name] > 1:
            permuter.unique_name += f" ({permuter.dir})"
        print(f"[{permuter.unique_name}] base score = {permuter.best_score}")

    found_zero = False
    perm_seed_iter = iter(cycle_seeds(context.permuters, force_seed))
    if options.threads == 1 and not options.use_network:
        # Simple single-threaded mode. This is not technically needed, but
        # makes the permuter easier to debug.
        for permuter_index, seed in perm_seed_iter:
            heartbeat()
            permuter = context.permuters[permuter_index]
            result = permuter.try_eval_candidate(seed)
            if post_score(context, permuter, result):
                found_zero = True
                if options.stop_on_zero:
                    break
    else:
        # Create queues
        task_queue: "multiprocessing.Queue[Task]" = multiprocessing.Queue()
        feedback_queue: "multiprocessing.Queue[Feedback]" = multiprocessing.Queue()
        task_queue.cancel_join_thread()
        feedback_queue.cancel_join_thread()

        # Connect to network and create client threads
        net_threads: List[threading.Thread] = []
        if options.use_network:
            config = setup()
            servers, grant = get_servers_and_grant(config)
            net_threads = connect_to_servers(
                config, servers, grant  # , task_queue, feedback_queue
            )

        # Start local worker threads
        processes: List[multiprocessing.Process] = []
        for i in range(options.threads):
            p = multiprocessing.Process(
                target=multiprocess_worker,
                args=(context.permuters, task_queue, feedback_queue),
            )
            p.start()
            processes.append(p)

        def process_result(result: Tuple[int, EvalResult]) -> bool:
            permuter_index, res = result
            permuter = context.permuters[permuter_index]
            return post_score(context, permuter, res)

        # Feed the task queue with work and read from results queue.
        # We generally match these up one-by-one to avoid overfilling queues,
        # but workers can ask us to add more tasks into the system if they run
        # out of work. (This will happen e.g. at the very beginning, when the
        # queues are empty.)
        while True:
            heartbeat()
            feedback = feedback_queue.get()
            assert not isinstance(feedback, Finished), "threads can't finish yet"
            if isinstance(feedback, NeedMoreWork):
                # No result to process, just put a task in the queue.
                pass
            elif process_result(feedback):
                # Found score 0!
                found_zero = True
                if options.stop_on_zero:
                    break
            task = next(perm_seed_iter, None)
            if task is None:
                break
            task_queue.put(task)

        active_workers = options.threads

        # Signal workers to stop.
        for i in range(active_workers):
            task_queue.put(Finished())

        # Await final results.
        while active_workers > 0:
            heartbeat()
            feedback = feedback_queue.get()
            if isinstance(feedback, Finished):
                active_workers -= 1
            elif isinstance(feedback, NeedMoreWork):
                pass
            elif not (options.stop_on_zero and found_zero):
                if process_result(feedback):
                    found_zero = True

        # Wait for workers to finish.
        for p in processes:
            p.join()

    if found_zero:
        print("\nFound zero score! Exiting.")
    return [permuter.best_score for permuter in context.permuters]


def main() -> None:
    multiprocessing.freeze_support()
    sys.setrecursionlimit(10000)

    # Ideally we would do:
    #  multiprocessing.set_start_method('spawn')
    # here, to make multiprocessing behave the same across operating systems.
    # However, that means that arguments to Process are passed across using
    # pickling, which mysteriously breaks with pycparser...
    # (AttributeError: 'CParser' object has no attribute 'p_abstract_declarator_opt')
    # So, for now we live with the defaults, which make multiprocessing work on Linux,
    # where it uses fork and don't pickle arguments, and break on Windows. Sigh.

    parser = argparse.ArgumentParser(
        description="Randomly permute C files to better match a target binary."
    )
    parser.add_argument(
        "directories",
        nargs="+",
        metavar="directory",
        help="Directory containing base.c, target.o and compile.sh. Multiple directories may be given.",
    )
    parser.add_argument(
        "--show-errors",
        dest="show_errors",
        action="store_true",
        help="Display compiler error/warning messages, and keep .c files for failed compiles.",
    )
    parser.add_argument(
        "--show-timings",
        dest="show_timings",
        action="store_true",
        help="Display the time taken by permuting vs. compiling vs. scoring.",
    )
    parser.add_argument(
        "--print-diffs",
        dest="print_diffs",
        action="store_true",
        help="Instead of compiling generated sources, display diffs against a base version.",
    )
    parser.add_argument(
        "--abort-exceptions",
        dest="abort_exceptions",
        action="store_true",
        help="Stop execution when an internal permuter exception occurs.",
    )
    parser.add_argument(
        "--stop-on-zero",
        dest="stop_on_zero",
        action="store_true",
        help="Stop after producing an output with score 0.",
    )
    parser.add_argument(
        "--stack-diffs",
        dest="stack_differences",
        action="store_true",
        help="Take stack differences into account when computing the score.",
    )
    parser.add_argument(
        "--keep-prob",
        dest="keep_prob",
        metavar="PROB",
        type=restricted_float(0.0, 1.0),
        default=DEFAULT_RAND_KEEP_PROB,
        help="Continue randomizing the previous output with the given probability "
        f"(float in 0..1, default %(default)s).",
    )
    parser.add_argument("--seed", dest="force_seed", type=str, help=argparse.SUPPRESS)
    parser.add_argument(
        "-j",
        dest="threads",
        type=int,
        default=0,
        help="Number of own threads to use (default: 1 without -J, 0 with -J).",
    )
    parser.add_argument(
        "-J",
        dest="use_network",
        action="store_true",
        help="Harness extra compute power through cyberspace (permuter@home).",
    )
    parser.add_argument(
        "--priority",
        dest="network_priority",
        metavar="PRIORITY",
        type=restricted_float(0.01, 2.0),
        default=1.0,
        help="Proportion of server resources to use when multiple people "
        "are using -J at the same time. "
        "Defaults to 1.0, meaning resources are split equally, but can be "
        "set to any value within [0.01, 2.0]. "
        "Each server runs with a priority threshold, which defaults to 0.1, "
        "below which they will not run permuter jobs at all.",
    )
    parser.add_argument(
        "--vouch",
        dest="vouch",
        action="store_true",
        help="Give someone access to the permuter@home server.",
    )

    args = parser.parse_args()

    threads = args.threads
    if not threads and not args.use_network:
        threads = 1

    if args.vouch:
        run_vouch(args.directories[0])
        return

    options = Options(
        directories=args.directories,
        show_errors=args.show_errors,
        show_timings=args.show_timings,
        print_diffs=args.print_diffs,
        abort_exceptions=args.abort_exceptions,
        stack_differences=args.stack_differences,
        stop_on_zero=args.stop_on_zero,
        keep_prob=args.keep_prob,
        force_seed=args.force_seed,
        threads=threads,
        use_network=args.use_network,
        network_priority=args.network_priority,
    )

    run(options)


if __name__ == "__main__":
    main()
