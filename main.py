from typing import List, Dict, Optional, Callable, Optional, Tuple, Iterable
import argparse
import difflib
import functools
import os
from random import Random
import random
import re
import sys
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, Future
from enum import Enum

import attr
import pycparser
from preprocess import preprocess
import copy

from compiler import Compiler
from randomizer import Randomizer
from scorer import Scorer
from perm.perm import EvalState, Perm
import perm
import ast_util
from pycparser import CParser
from pycparser import c_ast as ca
from candidate import Candidate

@attr.s
class Options:
    directories: List[str] = attr.ib()
    show_errors: bool = attr.ib(default=False)
    show_timings: bool = attr.ib(default=False)
    print_diffs: bool = attr.ib(default=False)
    seed: Optional[int] = attr.ib(default=None)
    threads: Optional[int] = attr.ib(default=1)

class Profiler():
    class StatType(Enum):
        perm = 1
        compile = 2
        score = 3

    def __init__(self):
        self.time_stats = {x: 0.0 for x in Profiler.StatType}
        
    def add_stat(self, stat: StatType, time_taken: float) -> None:
        self.time_stats[stat] += time_taken

    def get_str_stats(self) -> str:
        total_time = sum([self.time_stats[e] for e in self.time_stats])
        timings = ", ".join([f'{round(100 * self.time_stats[e] / total_time)}% {e}' for e in self.time_stats])
        return timings

def find_fns(source: str) -> List[str]:
    fns = re.findall(r'(\w+)\([^()\n]*\)\s*?{', source)
    return [fn for fn in fns if not fn.startswith('PERM')
            and fn not in ['if', 'for', 'switch', 'while']]

class Permuter:
    def __init__(self, dir: str, compiler: Compiler, scorer: Scorer, source_file: str, source: str, seed: int):
        self.dir = dir
        self.random = Random()
        self.randomizer = Randomizer()
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

        self.seed = seed
        self.random.seed(self.seed)

        self.parser = pycparser.CParser()
        self.permutations = perm.perm_gen(source)
        self.base = self.create_and_score_base()
        self.hashes = {self.base.score_hash}

        #Move outside?
        self._seed_iterator = iter(perm.get_all_seeds(self.permutations.perm_count, self.random))

    def create_and_score_base(self) -> Candidate:
        base_source = perm.perm_evaluate_one(self.permutations)
        base_cand = Candidate.from_source(base_source, self.parser)
        if not base_cand.compile(self.compiler):
            raise Exception(f"Unable to compile {self.source_file}")
        base_cand.score(self.scorer)
        return base_cand

    def get_next_seed(self) -> int:
        if self.permutations.is_random():
            max_ran = max([self.permutations.perm_count, 10**9])
            seed = self.random.randint(0, max_ran)
        else:
            seed = next(self._seed_iterator, None)
            
        return seed

    def eval_candidate(self, seed: int) -> Tuple[Candidate, Profiler]:
        cand_c = self.permutations.evaluate(seed, EvalState())
        if cand_c is None:
            return None

        t0 = time.time()

        cand = Candidate.from_source(cand_c, self.parser, seed)

        if self.permutations.is_random():
            cand.randomize_ast(self.randomizer)

        t1 = time.time()

        comp_success = cand.compile(self.compiler)

        t2 = time.time()

        if comp_success:
            cand.score(self.scorer)
            new_score, new_hash = cand.score_value, cand.score_hash
        else:
            new_hash = None
            new_score = self.scorer.PENALTY_INF

        t3 = time.time()

        profiler: Profiler = Profiler()
        profiler.add_stat(Profiler.StatType.perm, t1 - t0)
        profiler.add_stat(Profiler.StatType.compile, t2 - t1)
        profiler.add_stat(Profiler.StatType.score, t3 - t2)

        return cand, profiler

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
    high_scores = {}
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
    
def post_score(context: EvalContext, permuter: Permuter, cand: Candidate, exception: BaseException, profiler: Profiler) -> None:
    with cand:
        if exception != None:
            print(f"[{permuter.unique_name}] internal permuter failure.")
            traceback.print_exc()
            print(f"To reproduce the failure, rerun with: --seed {permuter.seed}")
            exit(1)

        if options.print_diffs:
            permuter.print_diff(cand)
            yn = input("Press any key to continue...")

        context.iteration += 1
        if cand.score_value is None:
            context.errors += 1
        disp_score = 'inf' if cand.score_value == permuter.scorer.PENALTY_INF else cand.score_value
        timings = ''
        if options.show_timings:
            assert(profiler)
            for stattype in profiler.time_stats:
                context.overall_profiler.add_stat(stattype, profiler.time_stats[stattype])
            timings = context.overall_profiler.get_str_stats()
        status_line = f"iteration {context.iteration}, {context.errors} errors, score = {disp_score}\t{timings}"

        if cand.score_value and cand.score_value <= permuter.base.score_value and cand.score_hash and cand.score_hash not in permuter.hashes and cand.score_value < 20000:
            permuter.hashes.add(cand.score_hash)
            print("\r" + " " * (len(status_line) + 10) + "\r", end='')
            if cand.score_value < permuter.base.score_value:
                context.high_scores[permuter] = cand.score_hash
                print(f"[{permuter.unique_name}] found a better score! ({cand.score_value} vs {permuter.base.score_value})")
            else:
                print(f"[{permuter.unique_name}] found different asm with same score")

            source = cand.get_source()
            write_candidate(permuter, source)
        print("\b"*10 + " "*10 + "\r" + status_line, end='', flush=True)

def gen_all_seeds(permuters: List[Permuter], heartbeat: Callable[[], None]) -> Iterable[Tuple[int, Permuter]]:
    i = -1
    avail_permuters = [(p, p_i) for p, p_i in zip(permuters, range(len(permuters)))]

    while len(avail_permuters) > 0:
        heartbeat()
        i = (i + 1) % len(avail_permuters)
        permuter_item = avail_permuters[i]
        permuter, perm_ind = permuter_item
        seed = permuter.get_next_seed()
        if seed is None:
            avail_permuters.remove(permuter_item)
        else:
            yield perm_ind, seed

def batch(it, batch_size):
    while True:
        batch = []
        for i in range(batch_size):
            v = next(it, None)
            if v == None:
                if len(batch) != 0:
                    yield batch
                return

            batch.append(v)
        yield batch
        
def main(options: Options) -> int:
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
            exit(1)
        print()
        print("Exiting.")
        # The lru_cache sometimes uses a lot of memory, making normal exit slow
        # due to GC. But since we're sane people and don't use finalizers for
        # cleanup, we can just skip GC and exit immediately.
        os._exit(0)

context = EvalContext()

def wrap_eval(permuter_seeds):
    global context
    permuter_index, seed = permuter_seeds
    permuter = context.permuters[permuter_index]
    #print(seed)
    sys.stdout.flush()
    return permuter.eval_candidate(seed)

def wrapped_main(options: Options, heartbeat: Callable[[], None]) -> int:
    print("Loading...")

    if options.seed is not None:
        start_seed = options.seed
    else:
        start_seed = random.randrange(sys.maxsize) # Random seed from default random

    name_counts: Dict[str, int] = {}
    for d in options.directories:
        heartbeat()
        compile_cmd = os.path.join(d, 'compile.sh')
        target_o = os.path.join(d, 'target.o')
        base_c = os.path.join(d, 'base.c')
        for fname in [compile_cmd, target_o, base_c]:
            if not os.path.isfile(fname):
                print(f"Missing file {fname}", file=sys.stderr)
                exit(1)
        if not os.stat(compile_cmd).st_mode & 0o100:
            print(f"{compile_cmd} must be marked executable.", file=sys.stderr)
            exit(1)

        print(base_c)

        compiler = Compiler(compile_cmd, options.show_errors)
        scorer = Scorer(target_o)
        c_source = preprocess(base_c)

        # TODO: catch special-purpose permuter exceptions from this
        permuter = Permuter(d, compiler, scorer, base_c, c_source, start_seed)
        print(f'perm count: {permuter.permutations.perm_count}')

        context.permuters.append(permuter)
        name_counts[permuter.fn_name] = name_counts.get(permuter.fn_name, 0) + 1
    print()

    for permuter in context.permuters:
        if name_counts[permuter.fn_name] > 1:
            permuter.unique_name += f" ({permuter.dir})"
        print(f"[{permuter.unique_name}] base score = {permuter.base.score_value}")

    context.high_scores = dict([(p.base.score_value, p) for p in context.permuters])

    with ProcessPoolExecutor(max_workers=options.threads) as executor:
        perm_seed_iter = gen_all_seeds(context.permuters, heartbeat)
        if options.threads == 1:
            for permuter_index, seed in perm_seed_iter:
                permuter = context.permuters[permuter_index]
                # Run single threaded
                exception = None
                try:
                    cand, profiler = permuter.eval_candidate(seed)
                except Exception as e:
                    cand = None
                    profiler = None
                    exception = e
                post_score(context, permuter, cand, exception, profiler)
        else:
            # Run multi-threaded
            for bat in batch(iter(perm_seed_iter), options.threads * 100):
                ps = [context.permuters[i] for i,_ in bat]
                for f, permuter in zip(executor.map(wrap_eval, bat), ps):
                    cand, profiler = f
                    post_score(context, permuter, cand, None, profiler)

    return context.high_scores

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
    parser.add_argument('--seed', dest='seed', type=int,
            help="Base all randomness on this initial seed.")
    parser.add_argument('-j', dest='threads', type=int, default=1,
            help="Number of threads.")
    args = parser.parse_args()

    options = Options(
            directories=args.directory,
            show_errors=args.show_errors,
            show_timings=args.show_timings,
            print_diffs=args.print_diffs,
            seed=args.seed,
            threads=args.threads)
    main(options)
