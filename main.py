import sys
import time
import os
import argparse
import traceback
import re
from pycparser import CParser, preprocess_file

from compiler import Compiler
from randomizer import Randomizer
from scorer import Scorer
import perm

def find_fns(source):
    fns = re.findall(r'(\w+)\(.*\)\s*?{', source)
    return fns

class Permuter:
    def __init__(self, dir, compiler, scorer, source_file, source):
        self.dir = dir
        self.compiler = compiler
        self.scorer = scorer
        self.source_file = source_file
        self.original_source = source

        fns = find_fns(self.original_source)
        if len(fns) != 1:
            raise Exception(f"{self.source_file} must contain exactly one function. (Use strip_other_fns.py.)")
        self.fn_name = fns[0]
        self.unique_name = self.fn_name

        self.permutations = perm.perm_gen(source)
        self.base_score, self.base_hash = self.score_base()
        self.hashes = {self.base_hash}

        self.parser = CParser()
        self.iterator = perm.perm_evaluate_all(self.permutations)

    def score_base(self):
        base_seed = [0] * len(self.permutations.get_counts())
        base_source = self.permutations.evaluate(base_seed)

        start_o = self.compiler.compile(base_source)
        if start_o is None:
            raise Exception(f"Unable to compile {self.source_file}")

        return self.scorer.score(start_o)

    def permutate_next(self):
        cand_c = next(self.iterator, None)
        if cand_c == None:
            return False

        ast = self.parser.parse(cand_c)
        randomizer = Randomizer(ast)
        randomizer.randomize()
        self.cur_cand = randomizer.get_current_source()
        return True

    def get_source(self):
        return self.cur_cand

    def compile(self):
        return self.compiler.compile(self.cur_cand)

    def score(self):
        cand_o = self.compile()
        return self.scorer.score(cand_o)

def write_candidate(perm, source):
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

def main(directories, display_errors):
    last_time = time.time()
    try:
        def heartbeat():
            nonlocal last_time
            last_time = time.time()
        wrapped_main(directories, display_errors, heartbeat)
    except KeyboardInterrupt:
        if time.time() - last_time > 5:
            print()
            print("Aborting stuck process.")
            traceback.print_exc()
            exit(1)
        print()
        print("Exiting.")

def wrapped_main(directories, display_errors, heartbeat):
    print("Loading...")

    name_counts = {}
    permuters = []
    for d in directories:
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

        compiler = Compiler(compile_cmd, display_errors)
        scorer = Scorer(target_o)
        c_source = preprocess_file(base_c)

        try:
            permuter = Permuter(d, compiler, scorer, base_c, c_source)
        except Exception as e:
            print(f"{e}", file=sys.stderr)
            exit(1)

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
    while len(permuters) > 0:
        heartbeat()
        perm_ind = (perm_ind + 1) % len(permuters)
        perm = permuters[perm_ind]

        try:
            if not perm.permutate_next():
                permuters.remove(perm)

            new_score, new_hash = perm.score()
        except Exception:
            print(f"[{perm.unique_name}] internal permuter failure.")
            traceback.print_exc()
            exit(1)

        iteration += 1
        if new_hash is None:
            errors += 1
        disp_score = 'inf' if new_score == scorer.PENALTY_INF else new_score
        sys.stdout.write("\b"*10 + " "*10 + f"\riteration {iteration}, {errors} errors, score = {disp_score}")
        sys.stdout.flush()

        if new_score <= perm.base_score and new_hash not in perm.hashes:
            perm.hashes.add(new_hash)
            print()
            if new_score < perm.base_score:
                print(f"[{perm.unique_name}] found a better score!")
            else:
                print(f"[{perm.unique_name}] found different asm with same score")

            source = perm.get_source()
            write_candidate(perm, source)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description="Randomly permute C files to better match a target binary.")
    parser.add_argument('directory', nargs='+',
            help="Directory containing base.c, target.o and compile.sh. Multiple directories may be given.")
    parser.add_argument('--display-errors', dest='display_errors', action='store_true',
            help="Display compiler error/warning messages, and keep .c files for failed compiles.")
    args = parser.parse_args()

    main(args.directory, args.display_errors)
