from typing import List, Dict, Optional, Callable, Optional, Tuple, Iterable, Union
import argparse
import difflib
import itertools
import functools
import os
from random import Random
import random
import re
import sys
import time
import traceback
import multiprocessing
from enum import Enum

import attr
import pycparser
from preprocess import preprocess
import copy

from compiler import Compiler
from scorer import Scorer
from perm.perm import EvalState, Perm
import perm
import ast_util
from pycparser import CParser
from pycparser import c_ast as ca
from candidate import Candidate
from profiler import Profiler

# The probability that the randomizer continues transforming the output it
# generated last time.
RANDOMIZER_KEEP_PROB = 0.25

@attr.s
class Options:
    directories: List[str] = attr.ib()
    show_errors: bool = attr.ib(default=False)
    show_timings: bool = attr.ib(default=False)
    print_diffs: bool = attr.ib(default=False)
    force_seed: Optional[str] = attr.ib(default=None)
    threads: int = attr.ib(default=1)

def find_fns(source: str) -> List[str]:
    fns = re.findall(r'(\w+)\([^()\n]*\)\s*?{', source)
    return [fn for fn in fns if not fn.startswith('PERM')
            and fn not in ['if', 'for', 'switch', 'while']]

@attr.s
class EvalError:
    exc_str: str = attr.ib()
    seed: Optional[Tuple[int, int]] = attr.ib()

EvalResult = Union[Tuple[Candidate, Profiler], EvalError]

class Permuter:
    '''
    Represents a single source from which permutation candidates can be generated,
    and which keeps track of good scores achieved so far.
    '''
    def __init__(self, dir: str, compiler: Compiler, scorer: Scorer, source_file: str, source: str, force_seed: Optional[str]):
        self.dir = dir
        self.random = Random()
        self.compiler = compiler
        self.scorer = scorer
        self.source_file = source_file

        fns = find_fns(source)
        if len(fns) == 0:
            raise Exception(f"{self.source_file} does not contain any function!")
        if len(fns) > 1:
            raise Exception(f"{self.source_file} must contain only one function. (Use strip_other_fns.py.)")
        self.fn_name = fns[0]
        self.unique_name = self.fn_name

        self.parser = pycparser.CParser()
        self.permutations = perm.perm_gen(source)

        self.cur_seed: Optional[Tuple[int, int]] = None
        if force_seed:
            seed, rng_seed = map(int, force_seed.split())
            self.force_rng_seed: Optional[int] = rng_seed
            self._seed_iterator = itertools.repeat(seed) if self.permutations.is_random() else iter([seed])
        else:
            self.force_rng_seed = None
            self._seed_iterator = iter(perm.perm_gen_all_seeds(self.permutations, self.random))

        self.base, base_score, base_hash = self.create_and_score_base()
        self.hashes = {base_hash}
        self.cand: Optional[Candidate] = None
        self.base_score: int = base_score
        self.best_score: int = base_score

    def create_and_score_base(self) -> Tuple[Candidate, int, str]:
        base_source = perm.perm_evaluate_one(self.permutations)
        base_cand = Candidate.from_source(base_source, self.parser, rng_seed=0)
        o_file = base_cand.compile(self.compiler, show_errors=True)
        if not o_file:
            raise Exception(f"Unable to compile {self.source_file}")
        base_score, base_hash = base_cand.score(self.scorer, o_file)
        return base_cand, base_score, base_hash

    def get_next_seed(self) -> Optional[int]:
        return next(self._seed_iterator, None)

    def eval_candidate(self, seed: int) -> Tuple[Candidate, Profiler]:
        t0 = time.time()

        # Determine if we should keep the last candidate
        keep = ((self.permutations.is_random()
            and self.random.uniform(0, 1) >= RANDOMIZER_KEEP_PROB)
            or self.force_rng_seed)

        # Create a new candidate if we didn't keep the last one (or if the last one didn't exist)
        # N.B. if we decide to keep the previous candidate, we will skip over the provided seed.
        # This means we're not guaranteed to test all seeds, but it doesn't really matter since
        # we're randomizing anyway.
        if not self.cand or not keep:
            cand_c = self.permutations.evaluate(seed, EvalState())
            # TODO: this doesn't match the provided return type...
            if cand_c is None:
                return None
            rng_seed = self.force_rng_seed or random.randrange(1, 10**20)
            self.cur_seed = (seed, rng_seed)
            self.cand = Candidate.from_source(cand_c, self.parser, rng_seed=rng_seed)

        # Randomize the candidate
        if self.permutations.is_random():
            self.cand.randomize_ast()

        t1 = time.time()

        o_file = self.cand.compile(self.compiler)

        t2 = time.time()

        self.cand.score(self.scorer, o_file)

        t3 = time.time()

        profiler: Profiler = Profiler()
        profiler.add_stat(Profiler.StatType.perm, t1 - t0)
        profiler.add_stat(Profiler.StatType.compile, t2 - t1)
        profiler.add_stat(Profiler.StatType.score, t3 - t2)

        return self.cand, profiler

    def try_eval_candidate(self, seed: int) -> EvalResult:
        try:
            cand, profiler = self.eval_candidate(seed)
            return cand, profiler
        except:
            return EvalError(exc_str=traceback.format_exc(), seed=self.cur_seed)

    def print_diff(self, cand: Candidate) -> None:
        a = self.base.get_source().split('\n')
        b = cand.get_source().split('\n')
        for line in difflib.unified_diff(a, b, fromfile='before', tofile='after', lineterm=''):
            print(line)

@attr.s
class EvalContext():
    iteration = 0
    errors = 0
    overall_profiler = Profiler()
    permuters: List[Permuter] = []

def write_candidate(perm: Permuter, source: str) -> None:
    ctr = 0
    while True:
        ctr += 1
        try:
            fname = f'output-{perm.fn_name}-{ctr}.c'
            with open(fname, 'x') as f:
                f.write(source)
            break
        except FileExistsError:
            pass
    print(f"wrote to {fname}")

def post_score(context: EvalContext, permuter: Permuter, result: EvalResult) -> None:
    if isinstance(result, EvalError):
        print(f"[{permuter.unique_name}] internal permuter failure.")
        print(result.exc_str)
        seed = result.seed
        if seed is not None:
            print(f"To reproduce the failure, rerun with: --seed {seed[0]},{seed[1]}")
        sys.exit(1)

    cand, profiler = result
    score_value = cand.score_value
    score_hash = cand.score_hash
    assert score_value is not None
    assert score_hash is not None

    if options.print_diffs:
        permuter.print_diff(cand)
        input("Press any key to continue...")

    context.iteration += 1
    if cand.score_value is None:
        context.errors += 1
    disp_score = 'inf' if cand.score_value == permuter.scorer.PENALTY_INF else cand.score_value
    timings = ''
    if options.show_timings:
        for stattype in profiler.time_stats:
            context.overall_profiler.add_stat(stattype, profiler.time_stats[stattype])
        timings = '\t' + context.overall_profiler.get_str_stats()
    status_line = f"iteration {context.iteration}, {context.errors} errors, score = {disp_score}{timings}"

    if score_value and score_value <= permuter.base_score and score_hash not in permuter.hashes:
        permuter.hashes.add(score_hash)
        permuter.best_score = min(permuter.best_score, score_value)
        print("\r" + " " * (len(status_line) + 10) + "\r", end='')
        if score_value < permuter.base_score:
            print(f"[{permuter.unique_name}] found a better score! ({score_value} vs {permuter.base_score})")
        else:
            print(f"[{permuter.unique_name}] found different asm with same score")

        source = cand.get_source()
        write_candidate(permuter, source)
    print("\b"*10 + " "*10 + "\r" + status_line, end='', flush=True)

def gen_all_seeds(permuters: List[Permuter]) -> Iterable[Tuple[int, int]]:
    '''
    Return all possible (permuter index, seed) pairs, cycling over permuters.
    '''
    i = 0
    avail = list(range(len(permuters)))
    while avail:
        perm_ind = avail[i]
        seed = permuters[perm_ind].get_next_seed()
        if seed is None:
            del avail[i]
            i -= 1
        else:
            yield perm_ind, seed
        i = (i + 1) % len(avail)

def main(options: Options) -> List[int]:
    last_time = time.time()
    try:
        def heartbeat() -> None:
            nonlocal last_time
            last_time = time.time()
        return wrapped_main(options, heartbeat)
    except KeyboardInterrupt:
        if time.time() - last_time > 5:
            print()
            print("Aborting stuck process.")
            traceback.print_exc()
            sys.exit(1)
        print()
        print("Exiting.")
        # The lru_cache sometimes uses a lot of memory, making normal exit slow
        # due to GC. But since we're sane people and don't use finalizers for
        # cleanup, we can just skip GC and exit immediately.
        os._exit(0)

# This has to be a global since we need to access the permuters.
# multiprocessing fork()'s the main thread and it works out that the permuters
# are unmodified because we are simply passing in pre-calculated seeds from the
# main thread. In theory, we should be able to pass in the context as an argument
# but haven't been able to get pass various exceptions (probably related to pickling).
# TODO: test this. Candidates can be sent through task queues, so why not contexts?
context = EvalContext()

def wrapped_main(options: Options, heartbeat: Callable[[], None]) -> List[int]:
    print("Loading...")

    force_seed = options.force_seed

    name_counts: Dict[str, int] = {}
    for i, d in enumerate(options.directories):
        heartbeat()
        compile_cmd = os.path.join(d, 'compile.sh')
        target_o = os.path.join(d, 'target.o')
        base_c = os.path.join(d, 'base.c')
        for fname in [compile_cmd, target_o, base_c]:
            if not os.path.isfile(fname):
                print(f"Missing file {fname}", file=sys.stderr)
                sys.exit(1)
        if not os.stat(compile_cmd).st_mode & 0o100:
            print(f"{compile_cmd} must be marked executable.", file=sys.stderr)
            sys.exit(1)

        print(base_c)

        compiler = Compiler(compile_cmd, options.show_errors)
        scorer = Scorer(target_o)
        c_source = preprocess(base_c)

        # TODO: catch special-purpose permuter exceptions from this
        permuter = Permuter(d, compiler, scorer, base_c, c_source, force_seed=force_seed)

        context.permuters.append(permuter)
        name_counts[permuter.fn_name] = name_counts.get(permuter.fn_name, 0) + 1
    print()

    for permuter in context.permuters:
        if name_counts[permuter.fn_name] > 1:
            permuter.unique_name += f" ({permuter.dir})"
        print(f"[{permuter.unique_name}] base score = {permuter.best_score}")

    perm_seed_iter = gen_all_seeds(context.permuters)
    if options.threads == 1:
        for permuter_index, seed in perm_seed_iter:
            heartbeat()
            permuter = context.permuters[permuter_index]
            result = permuter.try_eval_candidate(seed)
            post_score(context, permuter, result)
    else:
        # Create queues
        InputQueue = multiprocessing.Queue[Optional[Tuple[int, int]]]
        OutputQueue = multiprocessing.Queue[Tuple[int, EvalResult]]
        task_queue: InputQueue = multiprocessing.Queue()
        results_queue: OutputQueue = multiprocessing.Queue()

        def worker(input_queue: InputQueue, output_queue: OutputQueue) -> None:
            global context
            while True:
                queue_item = input_queue.get()
                if queue_item is None:
                    break
                permuter_index, seed = queue_item
                permuter = context.permuters[permuter_index]
                result = (permuter_index, permuter.try_eval_candidate(seed))
                output_queue.put(result)

        def wait_for_result() -> None:
            heartbeat()
            permuter_index, result = results_queue.get()
            permuter = context.permuters[permuter_index]
            post_score(context, permuter, result)

        # Begin workers
        for i in range(options.threads):
            multiprocessing.Process(target=worker, args=(task_queue, results_queue)).start()

        # Feed the task queue with work, but not too much work at a time
        active_tasks = 0
        for perm_seed in perm_seed_iter:
            if active_tasks >= options.threads + 2:
                wait_for_result()
                active_tasks -= 1
            task_queue.put(perm_seed)
            active_tasks += 1

        # Tell child processes to stop
        for i in range(options.threads):
            task_queue.put(None)

        # Await final results
        for i in range(active_tasks):
            wait_for_result()

    return [permuter.best_score for permuter in context.permuters]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description="Randomly permute C files to better match a target binary.")
    parser.add_argument('directory', nargs='+',
            help="Directory containing base.c, target.o and compile.sh. Multiple directories may be given.")
    parser.add_argument('--show-errors', dest='show_errors', action='store_true',
            help="Display compiler error/warning messages, and keep .c files for failed compiles.")
    parser.add_argument('--show-timings', dest='show_timings', action='store_true',
            help="Display the time taken by permuting vs. compiling vs. scoring.")
    parser.add_argument('--print-diffs', dest='print_diffs', action='store_true',
            help="Instead of compiling generated sources, display diffs against a base version.")
    parser.add_argument('--seed', dest='force_seed', type=str, help=argparse.SUPPRESS)
    parser.add_argument('-j', dest='threads', type=int, default=1,
            help="Number of threads.")
    args = parser.parse_args()

    options = Options(
            directories=args.directory,
            show_errors=args.show_errors,
            show_timings=args.show_timings,
            print_diffs=args.print_diffs,
            force_seed=args.force_seed,
            threads=args.threads)
    main(options)
