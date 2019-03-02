import sys
import os
import random
import copy
import argparse
import traceback

from compiler import Compiler
from scorer import Scorer

from pycparser import parse_file, c_ast, c_parser, c_generator

class Permuter:
    def __init__(self, dir, fn_name, compiler, scorer, ast, base_score, base_hash):
        self.dir = dir
        self.fn_name = fn_name
        self.unique_name = fn_name
        self.compiler = compiler
        self.scorer = scorer
        self.ast = ast
        self.base_score = base_score
        self.base_hash = base_hash
        self.hashes = {base_hash}

    def compile(self, ast):
        source = to_c(ast)
        return self.compiler.compile(source)

    def score(self, ast):
        cand_o = self.compile(ast)
        return self.scorer.score(cand_o)


def to_c(ast):
    source = c_generator.CGenerator().visit(ast)
    if '#pragma' not in source:
        return source
    lines = source.split('\n')
    out = []
    same_line = 0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('#pragma'):
            if stripped == '#pragma sameline start':
                same_line += 1
                continue
            elif stripped == '#pragma sameline end':
                same_line -= 1
                if same_line == 0:
                    out.append('\n')
                continue
        if not same_line:
            line += '\n'
        out.append(line)
    assert same_line == 0
    return ''.join(out).rstrip() + '\n'

def compile_ast(compiler, ast):
    source = to_c(ast)
    return compiler.compile(source)

def find_fns(ast):
    ret = []
    for node in ast.ext:
        if isinstance(node, c_ast.FuncDef):
            ret.append(node)
    return ret

def visit_subexprs(top_node, callback):
    def rec(node, toplevel=False):
        if isinstance(node, c_ast.Assignment):
            node.rvalue = rec(node.rvalue)
        elif isinstance(node, c_ast.StructRef):
            node.name = rec(node.name)
        elif isinstance(node, (c_ast.Return, c_ast.Cast)):
            node.expr = rec(node.expr)
        elif isinstance(node, (c_ast.Constant, c_ast.ID)):
            if not toplevel:
                x = callback(node)
                if x: return x
        elif isinstance(node, c_ast.UnaryOp):
            if not toplevel:
                x = callback(node)
                if x: return x
            if node.op not in ['p++', 'p--', '++', '--', '&']:
                node.expr = rec(node.expr)
        elif isinstance(node, c_ast.BinaryOp):
            if not toplevel:
                x = callback(node)
                if x: return x
            node.left = rec(node.left)
            node.right = rec(node.right)
        elif isinstance(node, c_ast.Compound):
            for sub in node.block_items or []:
                rec(sub, True)
        elif isinstance(node, (c_ast.Case, c_ast.Default)):
            for sub in node.stmts or []:
                rec(sub, True)
        elif isinstance(node, c_ast.FuncCall):
            if not toplevel:
                x = callback(node)
                if x: return x
            if node.args:
                for i in range(len(node.args.exprs)):
                    node.args.exprs[i] = rec(node.args.exprs[i])
        elif isinstance(node, c_ast.ArrayRef):
            if not toplevel:
                x = callback(node)
                if x: return x
            node.name = rec(node.name)
            node.subscript = rec(node.subscript)
        elif isinstance(node, c_ast.Decl):
            if node.init:
                node.init = rec(node.init)
        elif isinstance(node, c_ast.For):
            if node.init:
                node.init = rec(node.init)
            node.stmt = rec(node.stmt, True)
        elif isinstance(node, c_ast.TernaryOp):
            if not toplevel:
                x = callback(node)
                if x: return x
            node.cond = rec(node.cond)
            node.iftrue = rec(node.iftrue)
            node.iffalse = rec(node.iffalse)
        elif isinstance(node, (c_ast.While, c_ast.DoWhile)):
            node.stmt = rec(node.stmt, True)
        elif isinstance(node, c_ast.Switch):
            node.cond = rec(node.cond)
            node.stmt = rec(node.stmt, True)
        elif isinstance(node, c_ast.If):
            node.cond = rec(node.cond)
            if node.iftrue:
                node.iftrue = rec(node.iftrue, True)
            if node.iffalse:
                node.iffalse = rec(node.iffalse, True)
        elif isinstance(node, (c_ast.TypeDecl, c_ast.PtrDecl, c_ast.ArrayDecl,
                c_ast.Typename, c_ast.EmptyStatement, c_ast.Pragma)):
            pass
        else:
            print("Node with unknown type!", file=sys.stderr)
            print(node, file=sys.stderr)
            exit(1)
        return node

    rec(top_node, True)

def get_block_stmts(block, force):
    if isinstance(block, c_ast.Compound):
        ret = block.block_items or []
        if force and not block.block_items:
            block.block_items = ret
    else:
        assert isinstance(block, (c_ast.Case, c_ast.Default))
        ret = block.stmts or []
        if force and not block.stmts:
            block.stmts = ret
    return ret

def insert_decl(fn, decl):
    for index, stmt in enumerate(fn.body.block_items):
        if not isinstance(stmt, c_ast.Decl):
            break
    else:
        index = len(fn.body.block_items)
    fn.body.block_items[index:index] = [decl]

def insert_statement(block, index, stmt):
    stmts = get_block_stmts(block, True)
    stmts[index:index] = [stmt]

def for_nested_blocks(stmt, callback):
    if isinstance(stmt, c_ast.Compound):
        callback(stmt)
    elif isinstance(stmt, (c_ast.For, c_ast.While, c_ast.DoWhile)):
        callback(stmt.stmt)
    elif isinstance(stmt, c_ast.If):
        if stmt.iftrue:
            callback(stmt.iftrue)
        if stmt.iffalse:
            callback(stmt.iffalse)
    elif isinstance(stmt, c_ast.Switch):
        if stmt.stmt:
            callback(stmt.stmt)
    elif isinstance(stmt, (c_ast.Case, c_ast.Default)):
        callback(stmt)

def perm_temp_for_expr(fn):
    phase = 0
    einds = {}
    sumprob = 0
    targetprob = None
    found = None
    def rec(block, reuse_cands):
        stmts = get_block_stmts(block, False)
        reuse_cands = reuse_cands[:]
        assignment_cands = []
        past_decls = False
        for index, stmt in enumerate(stmts):
            if isinstance(stmt, c_ast.Decl):
                if not isinstance(stmt.type, c_ast.ArrayDecl):
                    reuse_cands.append(stmt.name)
                    if not isinstance(stmt.type, c_ast.PtrDecl):
                        # Make non-pointers more common
                        reuse_cands.append(stmt.name)
            else:
                past_decls = True
            if past_decls:
                assignment_cands.append((block, index))

            for_nested_blocks(stmt, lambda b: rec(b, reuse_cands))

            def visitor(expr):
                nonlocal sumprob
                nonlocal found
                eind = einds.get(id(expr), 0)
                for place in assignment_cands[::-1]:
                    prob = 1 / (1 + eind)
                    if isinstance(expr, (c_ast.ID, c_ast.Constant)):
                        prob *= 0.5
                    sumprob += prob
                    if phase == 1 and found is None and sumprob > targetprob:
                        if random.randint(0,1) or not reuse_cands:
                            var = c_ast.ID('new_var')
                            reused = False
                        else:
                            var = c_ast.ID(random.choice(reuse_cands))
                            reused = True
                        found = (place, expr, var, reused)
                        return var
                    eind += 1
                einds[id(expr)] = eind
                return None
            visit_subexprs(stmt, visitor)
        assignment_cands.append((block, len(stmts)))

    rec(fn.body, [])
    phase = 1
    targetprob = random.uniform(0, sumprob)
    sumprob = 0
    einds = {}
    rec(fn.body, [])

    assert found is not None
    location, expr, var, reused = found
    # print("replacing:", to_c(expr))
    block, index = location
    assignment = c_ast.Assignment('=', var, expr)
    insert_statement(block, index, assignment)
    if not reused:
        typ = c_ast.TypeDecl(declname=var.name, quals=[],
                type=c_ast.IdentifierType(names=['int']))
        decl = c_ast.Decl(name=var.name, quals=[], storage=[], funcspec=[],
                type=typ, init=None, bitsize=None)
        insert_decl(fn, decl)

def perm_sameline(fn):
    cands = []
    def rec(block):
        stmts = get_block_stmts(block, False)
        for index, stmt in enumerate(stmts):
            cands.append((block, index))
            for_nested_blocks(stmt, rec)
        cands.append((block, len(stmts)))
    rec(fn.body)
    n = len(cands)
    assert n >= 3
    # Generate a small random interval
    le = n - 2
    for i in range(4):
        le *= random.uniform(0, 1)
    le = int(le) + 2
    i = random.randrange(n - le)
    j = i + le
    # Insert the second statement first, since inserting a statement may cause
    # later indices to move.
    insert_statement(cands[j][0], cands[j][1], c_ast.Pragma("sameline end"))
    insert_statement(cands[i][0], cands[i][1], c_ast.Pragma("sameline start"))

def permute_ast(ast):
    ast = copy.deepcopy(ast)
    fns = find_fns(ast)
    assert len(fns) == 1
    fn = fns[0]
    methods = [
        (perm_temp_for_expr, 90),
        (perm_sameline, 10),
    ]
    method = random.choice([x for (elem, prob) in methods for x in [elem]*prob])
    method(fn)
    return ast

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
        fn_name = fns[0].decl.name
        sys.stdout.write(f" {base_c}")
        sys.stdout.flush()
        start_o = compiler.compile(to_c(start_ast))
        if start_o is None:
            print(f"Unable to compile {base_c}", file=sys.stderr)
            exit(1)
        base_score, base_hash = scorer.score(start_o)

        permuters.append(Permuter(d, fn_name, compiler, scorer, start_ast, base_score, base_hash))
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
            ast = permute_ast(perm.ast)
            new_score, new_hash = perm.score(ast)
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

            source = to_c(ast)
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

main()
