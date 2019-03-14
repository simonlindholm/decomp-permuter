from typing import List, Dict, Optional, Callable, Optional, Tuple
import argparse
import difflib
import functools
import os
from random import Random
import re
import sys
import time
import traceback

import attr
import pycparser
from preprocess import preprocess

from compiler import Compiler
from randomizer import Randomizer
from scorer import Scorer
import perm

# The probability that the randomizer continues transforming the output it
# generated last time it was given the same initial C code.
RANDOMIZER_KEEP_PROB = 0.25

@attr.s
class Options:
    directories: List[str] = attr.ib()
    show_errors: bool = attr.ib(default=False)
    show_timings: bool = attr.ib(default=False)
    print_diffs: bool = attr.ib(default=False)
    seed: Optional[int] = attr.ib(default=None)

def find_fns(source: str) -> List[str]:
    fns = re.findall(r'(\w+)\(.*\)\s*?{', source)
    return [fn for fn in fns if not fn.startswith('PERM')]

class Permuter:
    def __init__(self, dir: str, compiler: Compiler, scorer: Scorer, source_file: str, source: str, seed: int):
        self.dir = dir
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

        self.random = Random()
        self.random.seed(seed)
        self.parser = pycparser.CParser()
        self.permutations = perm.perm_gen(source)
        self.base_source, self.base_score, base_hash = self.score_base()
        self.hashes = {base_hash}

        self.iterator = iter(perm.perm_evaluate_all(self.permutations, self.random))

    @functools.lru_cache(maxsize=1024)
    def _get_randomizer(self, source: str) -> Randomizer:
        ast = self.parser.parse(source)
        return Randomizer(ast, self.random)

    def score_base(self) -> Tuple[str, int, str]:
        base_source = perm.perm_evaluate_one(self.permutations)

        # Normalize the C code by e.g. stripping whitespace and pragmas
        randomizer = self._get_randomizer(base_source)
        base_source = randomizer.get_current_source()

        start_o = self.compiler.compile(base_source)
        if start_o is None:
            raise Exception(f"Unable to compile {self.source_file}")

        return (base_source, *self.scorer.score(start_o))

    def permutate_next(self) -> bool:
        cand_c = next(self.iterator, None)
        if cand_c is None:
            return False

        randomizer = self._get_randomizer(cand_c)
        if self.random.uniform(0, 1) >= RANDOMIZER_KEEP_PROB:
            randomizer.reset()
        if self.permutations.is_random():
            randomizer.randomize()
        self.cur_cand = randomizer.get_current_source()
        return True

    def get_source(self) -> str:
        return self.cur_cand

    def compile(self) -> Optional[str]:
        return self.compiler.compile(self.get_source())

    def score(self, cand_o: str) -> Tuple[int, str]:
        return self.scorer.score(cand_o)

    def print_diff(self) -> None:
        a = self.base_source.split('\n')
        b = self.get_source().split('\n')
        for line in difflib.unified_diff(a, b, fromfile='before', tofile='after', lineterm=''):
            print(line)

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

def wrapped_main(options: Options, heartbeat: Callable[[], None]) -> int:
    print("Loading...")

    random = Random()
    if options.seed != None:
    random.seed(options.seed)

    name_counts: Dict[str, int] = {}
    permuters: List[Permuter] = []
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

        perm_start_seed = random.randrange(sys.maxsize)
        # TODO: catch special-purpose permuter exceptions from this
        permuter = Permuter(d, compiler, scorer, base_c, c_source, perm_start_seed)

        permuters.append(permuter)
        name_counts[permuter.fn_name] = name_counts.get(permuter.fn_name, 0) + 1
    print()

    for perm in permuters:
        if name_counts[perm.fn_name] > 1:
            perm.unique_name += f" ({perm.dir})"
        print(f"[{perm.unique_name}] base score = {perm.base_score}")

    iteration = 0
    errors = 0
    perm_ind = -1

    time_perm = 0.0
    time_compile = 0.0
    time_score = 0.0

    high_scores = [p.base_score for p in permuters]
    while len(permuters) > 0:
        heartbeat()
        perm_ind = (perm_ind + 1) % len(permuters)
        perm = permuters[perm_ind]

        try:
            t0 = time.time()
            if not perm.permutate_next():
                permuters.remove(perm)
                continue
            t1 = time.time()

            if options.print_diffs:
                perm.print_diff()
                yn = input("More? [Yn]")
                if yn.lower() == 'n':
                    break
                continue

            o_file = perm.compile()
            t2 = time.time()

            if o_file is None:
                new_score = scorer.PENALTY_INF
                new_hash = None
            else:
                new_score, new_hash = perm.score(o_file)
            t3 = time.time()
        except Exception:
            print(f"[{perm.unique_name}] internal permuter failure.")
            traceback.print_exc()
            print(f"To reproduce the failure, rerun with: --seed {rand_seed}")
            exit(1)

        iteration += 1
        if new_hash is None:
            errors += 1
        disp_score = 'inf' if new_score == scorer.PENALTY_INF else new_score
        timings = ''
        if options.show_timings:
            time_perm += t1 - t0
            time_compile += t2 - t1
            time_score += t3 - t2
            time_total = time_perm + time_compile + time_score
            timings = ", {}% perm, {}% compile, {}% score".format(
                round(100 * time_perm / time_total),
                round(100 * time_compile / time_total),
                round(100 * time_score / time_total)
            )
        status_line = f"iteration {iteration}, {errors} errors, score = {disp_score}{timings}"

        if new_score <= perm.base_score and new_hash and new_hash not in perm.hashes:
            perm.hashes.add(new_hash)
            print("\r" + " " * (len(status_line) + 10) + "\r", end='')
            if new_score < perm.base_score:
                high_scores[perm_ind] = new_score
                print(f"[{perm.unique_name}] found a better score! ({new_score} vs {perm.base_score})")
            else:
                print(f"[{perm.unique_name}] found different asm with same score")

            source = perm.get_source()
            write_candidate(perm, source)
        print("\b"*10 + " "*10 + "\r" + status_line, end='', flush=True)
    
    return min(high_scores)

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
    args = parser.parse_args()

    options = Options(
            directories=args.directory,
            show_errors=args.show_errors,
            show_timings=args.show_timings,
            print_diffs=args.print_diffs,
            seed=args.seed)
    main(options)
