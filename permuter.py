import sys
import os
import tempfile
import subprocess
import random
import copy
import hashlib

from pycparser import parse_file, c_ast, c_parser, c_generator

filename = sys.argv[1]
target_o = sys.argv[2]
compile_cmd = sys.argv[3]

DISPLAY_ERRORS = False

assert target_o.endswith('.o')

def to_c(ast):
    return c_generator.CGenerator().visit(ast)

def compile_ast(ast):
    source = to_c(ast)

    with tempfile.NamedTemporaryFile(prefix='permuter', suffix='.c', mode='w', delete=False) as f:
        c_name = f.name
        f.write(source)

    with tempfile.NamedTemporaryFile(prefix='permuter', suffix='.o', delete=False) as f:
        o_name = f.name

    try:
        stderr = None if DISPLAY_ERRORS else subprocess.DEVNULL
        subprocess.check_call(compile_cmd + " " + c_name + " -o " + o_name, shell=True, stderr=stderr)
    except subprocess.CalledProcessError:
        if not DISPLAY_ERRORS:
            os.remove(c_name)
        return None

    os.remove(c_name)
    return o_name

PENALTY_INF = 10**9

PENALTY_REGALLOC = 10
PENALTY_SPLIT_DIFF = 20
PENALTY_REORDERING = 60
PENALTY_INSERTION = 100
PENALTY_DELETION = 100

def score(ast):
    cand_o = compile_ast(ast)
    if cand_o is None:
        return PENALTY_INF, None
    try:
        diff = subprocess.check_output(['./diff.sh', target_o, cand_o]).decode()
    finally:
        os.remove(cand_o)
    diffs = 0
    deletions = []
    insertions = []
    for line in diff.split('\n'):
        deletion = '[-' in line
        insertion = '{+' in line
        if not deletion and not insertion:
            continue
        # print(line)
        if deletion and insertion:
            # probably regalloc difference, or signed vs unsigned
            diffs += PENALTY_REGALLOC
        elif (line.startswith('[-') and line.endswith('-]')) or (line.startswith('{+') and line.endswith('+}')):
            # reordering or totally different codegen
            # defer this until later when we can tell
            line = line[2:-2]
            if deletion:
                deletions.append(line)
            else:
                insertions.append(line)
        else:
            # insertion/deletion split across lines, ugh
            diffs += PENALTY_SPLIT_DIFF
    common = set(deletions) & set(insertions)
    diffs += len(common) * PENALTY_REORDERING
    for change in deletions:
        if change not in common:
            diffs += PENALTY_DELETION
    for change in insertions:
        if change not in common:
            diffs += PENALTY_INSERTION
    return (diffs, hashlib.sha256(diff.encode()).hexdigest())

def find_fn(ast):
    for node in ast.ext:
        if isinstance(node, c_ast.FuncDef):
            return node
    assert False, "missing function"

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
                c_ast.Typename, c_ast.EmptyStatement)):
            pass
        else:
            print("Node with unknown type!", file=sys.stderr)
            print(node, file=sys.stderr)
            exit(1)
        return node

    rec(top_node, True)

def insert_decl(fn, decl):
    for index, item in enumerate(fn.body.block_items):
        if not isinstance(item, c_ast.Decl):
            break
    else:
        index = len(fn.body.block_items)
    fn.body.block_items[index:index] = [decl]

def get_block_items(block, force):
    if isinstance(block, c_ast.Compound):
        ret = block.block_items or []
        if force and not block.block_items:
            block.block_items = ret
    else:
        ret = block.stmts or []
        if force and not block.stmts:
            block.stmts = ret
    return ret

def permute_ast(ast):
    ast = copy.deepcopy(ast)
    fn = find_fn(ast)
    phase = 0
    einds = {}
    sumprob = 0
    targetprob = None
    found = None
    def rec(block):
        assert isinstance(block, (c_ast.Compound, c_ast.Case, c_ast.Default))
        after = []
        past_decls = False
        items = get_block_items(block, False)
        for index, item in enumerate(items):
            if not isinstance(item, c_ast.Decl):
                past_decls = True
            if past_decls:
                after.append((block, index))
            if isinstance(item, c_ast.Compound):
                rec(item)
            elif isinstance(item, (c_ast.For, c_ast.While, c_ast.DoWhile)):
                rec(item.stmt)
            elif isinstance(item, c_ast.If):
                if item.iftrue:
                    rec(item.iftrue)
                if item.iffalse:
                    rec(item.iffalse)
            elif isinstance(item, c_ast.Switch):
                if item.stmt:
                    rec(item.stmt)
            elif isinstance(item, (c_ast.Case, c_ast.Default)):
                rec(item)
            def visitor(expr):
                nonlocal sumprob
                nonlocal found
                eind = einds.get(id(expr), 0)
                for place in after[::-1]:
                    prob = 1 / (1 + eind)
                    if isinstance(expr, (c_ast.ID, c_ast.Constant)):
                        prob *= 0.5
                    sumprob += prob
                    if phase == 1 and found is None and sumprob > targetprob:
                        var = c_ast.ID('new_var')
                        found = (place, expr, var)
                        return var
                    eind += 1
                einds[id(expr)] = eind
                return None
            visit_subexprs(item, visitor)
        after.append((block, len(items)))

    rec(fn.body)
    phase = 1
    targetprob = random.uniform(0, sumprob)
    sumprob = 0
    einds = {}
    rec(fn.body)

    assert found is not None
    location, expr, var = found
    block, index = location
    assignment = c_ast.Assignment('=', var, expr)
    items = get_block_items(block, True)
    items[index:index] = [assignment]
    typ = c_ast.TypeDecl(declname=var.name, quals=[],
            type=c_ast.IdentifierType(names=['int']))
    decl = c_ast.Decl(name=var.name, quals=[], storage=[], funcspec=[],
            type=typ, init=None, bitsize=None)
    insert_decl(fn, decl)
    # print("replacing:", to_c(expr))
    return ast

def main():
    start_ast = parse_file(filename, use_cpp=False)

    base_score, base_hash = score(start_ast)
    hashes = {base_hash}
    if base_score == PENALTY_INF:
        print("unable to compile original .c file")
        exit(1)
    print(f"base score = {base_score}")

    ctr = 0
    iteration = 0
    errors = 0
    while True:
        ast = permute_ast(start_ast)
        new_score, new_hash = score(ast)
        iteration += 1
        if new_hash is None:
            errors += 1
        disp_score = 'inf' if new_score == PENALTY_INF else new_score
        sys.stdout.write("\b"*10 + " "*10 + f"\riteration {iteration}, {errors} errors, score = {disp_score}")
        sys.stdout.flush()
        if new_score < base_score or (new_score == base_score and new_hash not in hashes):
            hashes.add(new_hash)
            print()
            if new_score < base_score:
                print("found a better score!!")
            else:
                print("found different asm with same score", new_hash)

            source = to_c(ast)
            while True:
                ctr += 1
                try:
                    fname = f'output-{ctr}.c'
                    with open(fname, 'x') as f:
                        f.write(source)
                    break
                except FileExistsError:
                    pass
            print(f"wrote to {fname}")

main()
