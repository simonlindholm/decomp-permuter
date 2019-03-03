import perm
from pathlib import Path
import argparse
from compiler import Compiler
from scorer import Scorer
import os
import sys
import re

def get_perm_candiates(context):
    permutations = perm.perm_gen(context.c_source)
    for cand_c in perm.perm_evaluate_all(permutations):
        try:
            cand_o = context.compiler.compile(cand_c)
            score = context.scorer.score(cand_o)
            yield (score, cand_c, cand_o)
        finally:
            #os.remove(cand_o)
            pass

ctr = 0
def write_candidate(fn_name, source):
    global ctr
    while True:
        ctr += 1
        try:
            fname = f'output-{fn_name}-{ctr}.c'
            with open(fname, 'x') as f:
                f.write(source)
            break
        except FileExistsError:
            pass
    print(f"wrote to {fname}")

def find_fns(source):
    fns = re.findall(r'(\w+)\(.*\)\s*?{', source)
    return fns

class Context():
    def __init__(self, dir, fn_name, compiler, scorer, c_source):
        self.dir = dir
        self.fn_name = fn_name
        self.unique_name = fn_name
        self.compiler = compiler
        self.scorer = scorer
        self.c_source = c_source
        self.hashes = []

    def run(self):
        iteration = 0
        errors = 0
        perm_ind = 0
        cur_score = self.scorer.PENALTY_INF
        for (new_score, new_hash), cand_c, cand_o in get_perm_candiates(self):
            iteration += 1
            if new_hash is None:
                errors += 1
            disp_score = 'inf' if new_score == self.scorer.PENALTY_INF else new_score
            print("\b"*10 + " "*10 + f"\riteration {iteration}, {errors} errors, score = {disp_score}")

            if new_score <= cur_score and new_hash not in self.hashes:
                self.hashes.append(new_hash)
                print()
                if new_score < cur_score:
                    cur_score = new_score
                    print(f"[{self.unique_name}] found a better score!")
                else:
                    print(f"[{self.unique_name}] found different asm with same score")

                write_candidate(self.unique_name, cand_c)

def init_contexts(dir):
    name_counts = {}
    contexts = []

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

        c_source = Path(base_c).read_text()

        fns = find_fns(c_source)
        if len(fns) != 1:
            raise Exception(f"{base_c} must contain exactly one function. (Use strip_other_fns.py.)")
            
        fn_name = fns[0]
        print(f"\t{base_c}")

        contexts.append(Context(d, fn_name, compiler, scorer, c_source))
        name_counts[fn_name] = name_counts.get(fn_name, 0) + 1

    for c in contexts:
        if name_counts[c.fn_name] > 1:
            c.unique_name += f" ({c.dir})"

    return contexts

def main(dirs, display_errors):
    print("Loading...")
    contexts = init_contexts(dirs)  

    for context in contexts:
        context.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Permutate')
    parser = argparse.ArgumentParser(
            description="Randomly permute C files to better match a target binary.")
    parser.add_argument('directory', nargs='+',
            help="Directory containing base.c, target.o and compile.sh. Multiple directories may be given.")
    parser.add_argument('--display-errors', dest='display_errors', action='store_true',
            help="Display compiler error/warning messages, and keep .c files for failed compiles.")
    args = parser.parse_args()

    main(args.directory, args.display_errors)