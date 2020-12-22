import argparse
from dataclasses import dataclass, field
import itertools
import multiprocessing
import os
from random import Random
import sys
import time
from typing import (
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Tuple,
)

from .error import CandidateConstructionFailure
from .preprocess import preprocess
from .candidate import CandidateResult
from .compiler import Compiler
from .scorer import Scorer
from .permuter import EvalError, EvalResult, Permuter
from .profiler import Profiler

# The probability that the randomizer continues transforming the output it
# generated last time.
DEFAULT_RAND_KEEP_PROB = 0.6


@dataclass
class Options:
    directories: List[str]
    show_errors: bool = False
    show_timings: bool = False
    print_diffs: bool = False
    stack_differences: bool = False
    abort_exceptions: bool = False
    better_only: bool = False
    best_only: bool = False
    stop_on_zero: bool = False
    keep_prob: float = DEFAULT_RAND_KEEP_PROB
    force_seed: Optional[str] = None
    threads: int = 1


@dataclass
class EvalContext:
    options: Options
    iteration: int = 0
    errors: int = 0
    overall_profiler: Profiler = field(default_factory=Profiler)
    permuters: List[Permuter] = field(default_factory=list)


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
    assert source is not None, "Permuter._need_to_send_source is wrong!"
    with open(os.path.join(output_dir, "source.c"), "x", encoding="utf-8") as f:
        f.write(source)
    with open(os.path.join(output_dir, "score.txt"), "x", encoding="utf-8") as f:
        f.write(f"{result.score}\n")
    with open(os.path.join(output_dir, "diff.txt"), "x", encoding="utf-8") as f:
        f.write(perm.diff(source) + "\n")
    print(f"wrote to {output_dir}")


def post_score(context: EvalContext, permuter: Permuter, result: EvalResult) -> bool:
    if isinstance(result, EvalError):
        if result.exc_str is not None:
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
        assert result.source is not None, "Permuter._need_to_send_source is wrong"
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

    # Note: when updating this if condition, Permuter._need_to_send_source may
    # also need to be updated, or else assertion failures will result.
    if (
        score_value is not None
        and score_hash is not None
        and not (score_value > permuter.best_score and context.options.best_only)
        and (
            score_value < permuter.base_score
            or (score_value == permuter.base_score and not context.options.better_only)
        )
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


def cycle_seeds(permuters: List[Permuter]) -> Iterable[Tuple[int, int]]:
    """
    Return all possible (permuter index, seed) pairs, cycling over permuters.
    If a permuter is randomized, it will keep repeating seeds infinitely.
    """
    iterators: List[Iterator[Tuple[int, int]]] = []
    for perm_ind, permuter in enumerate(permuters):
        it = permuter.seed_iterator()
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


def multiprocess_worker(
    permuters: List[Permuter],
    input_queue: "multiprocessing.Queue[Optional[Tuple[int, int]]]",
    output_queue: "multiprocessing.Queue[Tuple[int, EvalResult]]",
) -> None:
    input_queue.cancel_join_thread()
    output_queue.cancel_join_thread()

    try:
        while True:
            queue_item = input_queue.get()
            if queue_item is None:
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
            raise
        print()
        print("Exiting.")
        sys.exit(0)


def run_inner(options: Options, heartbeat: Callable[[], None]) -> List[int]:
    print("Loading...")

    context = EvalContext(options)

    force_seed: Optional[int] = None
    force_rng_seed: Optional[int] = None
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

        compiler = Compiler(compile_cmd, show_errors=options.show_errors)
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
                force_seed=force_seed,
                force_rng_seed=force_rng_seed,
                keep_prob=options.keep_prob,
                need_all_sources=options.print_diffs,
                show_errors=options.show_errors,
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
    perm_seed_iter = iter(cycle_seeds(context.permuters))
    if options.threads == 1:
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
        task_queue: "multiprocessing.Queue[Optional[Tuple[int, int]]]" = (
            multiprocessing.Queue()
        )
        results_queue: "multiprocessing.Queue[Tuple[int, EvalResult]]" = (
            multiprocessing.Queue()
        )
        task_queue.cancel_join_thread()
        results_queue.cancel_join_thread()

        def wait_for_result() -> bool:
            heartbeat()
            permuter_index, result = results_queue.get()
            permuter = context.permuters[permuter_index]
            return post_score(context, permuter, result)

        # Begin workers
        processes: List[multiprocessing.Process] = []
        for i in range(options.threads):
            p = multiprocessing.Process(
                target=multiprocess_worker,
                args=(context.permuters, task_queue, results_queue),
            )
            p.start()
            processes.append(p)

        # Feed the task queue with work, but not too much work at a time
        active_tasks = 0
        for perm_seed in perm_seed_iter:
            if active_tasks >= options.threads + 2:
                active_tasks -= 1
                if wait_for_result():
                    # Found score 0!
                    found_zero = True
                    if options.stop_on_zero:
                        break
            task_queue.put(perm_seed)
            active_tasks += 1

        # Await final results
        for i in range(active_tasks):
            wait_for_result()

        # Stop workers
        for i in range(options.threads):
            task_queue.put(None)
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
        "--better-only",
        dest="better_only",
        action="store_true",
        help="Only report scores better than the base.",
    )
    parser.add_argument(
        "--best-only",
        dest="best_only",
        action="store_true",
        help="Only report ties or new high scores.",
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
        type=float,
        default=DEFAULT_RAND_KEEP_PROB,
        help="Continue randomizing the previous output with the given probability "
        f"(float in 0..1, default {DEFAULT_RAND_KEEP_PROB}).",
    )
    parser.add_argument("--seed", dest="force_seed", type=str, help=argparse.SUPPRESS)
    parser.add_argument(
        "-j",
        dest="threads",
        type=int,
        default=1,
        help="Number of threads (default: %(default)s).",
    )
    args = parser.parse_args()

    options = Options(
        directories=args.directories,
        show_errors=args.show_errors,
        show_timings=args.show_timings,
        print_diffs=args.print_diffs,
        abort_exceptions=args.abort_exceptions,
        better_only=args.better_only,
        best_only=args.best_only,
        stack_differences=args.stack_differences,
        stop_on_zero=args.stop_on_zero,
        keep_prob=args.keep_prob,
        force_seed=args.force_seed,
        threads=args.threads,
    )

    run(options)


if __name__ == "__main__":
    main()
