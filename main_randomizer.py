import sys
import os
from randomizer import Randomizer, find_fns
import argparse
import traceback
from pycparser import parse_file

from compiler import Compiler
from scorer import Scorer

class Permuter:
    def __init__(self, dir, fn_name, compiler, scorer, randomizer, base_score, base_hash):
        self.dir = dir
        self.fn_name = fn_name
        self.unique_name = fn_name
        self.compiler = compiler
        self.scorer = scorer
        self.base_score = base_score
        self.base_hash = base_hash
        self.hashes = {base_hash}
        self.randomizer = randomizer

    def compile(self):
        return self.compiler.compile(self.randomizer.get_current_source())

    def score(self):
        cand_o = self.compile()
        return self.scorer.score(cand_o)

ctr = 0
def write_candidate(source):
    global ctr
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

def main():
    parser = argparse.ArgumentParser(
            description="Randomly permute C files to better match a target binary.")
    parser.add_argument('directory', nargs='+',
            help="Directory containing base.c, target.o and compile.sh. Multiple directories may be given.")
    parser.add_argument('--display-errors', dest='display_errors', action='store_true',
            help="Display compiler error/warning messages, and keep .c files for failed compiles.")
    args = parser.parse_args()

    name_counts = {}
    permuters = []
    sys.stdout.write("Loading...")
    sys.stdout.flush()
    for d in args.directory:
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

        compiler = Compiler(compile_cmd, args.display_errors)
        scorer = Scorer(target_o)

        start_ast = parse_file(base_c, use_cpp=False)

        fns = find_fns(start_ast)
        if len(fns) != 1:
            print(f"{base_c} must contain exactly one function. (Use strip_other_fns.py.)", file=sys.stderr)
            exit(1)
        randomizer = Randomizer(start_ast)
        fn_name = fns[0].decl.name
        sys.stdout.write(f" {base_c}")
        sys.stdout.flush()
        start_o = compiler.compile(randomizer.get_current_source())
        if start_o is None:
            print(f"Unable to compile {base_c}", file=sys.stderr)
            exit(1)
        base_score, base_hash = scorer.score(start_o)

        permuters.append(Permuter(d, fn_name, compiler, scorer, randomizer, base_score, base_hash))
        name_counts[fn_name] = name_counts.get(fn_name, 0) + 1
    print()

    for perm in permuters:
        if name_counts[perm.fn_name] > 1:
            perm.unique_name += f" ({perm.dir})"
        print(f"[{perm.unique_name}] base score = {perm.base_score}")

    iteration = 0
    errors = 0
    perm_ind = 0
    while True:
        perm = permuters[perm_ind]
        perm_ind = (perm_ind + 1) % len(permuters)

        try:
            perm.randomizer.randomize()
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

            source = perm.randomizer.get_current_source()
            write_candidate(source)

main()
