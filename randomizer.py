import sys
import random
import copy
import bisect

from pycparser import c_ast, c_parser, c_generator

from ast_types import (SimpleType, build_typemap, decayed_expr_type, same_type,
        set_decl_name)

# Set to true to perform expression type detection eagerly. This can help when
# debugging crashes in the ast_types code.
DEBUG_EAGER_TYPES = False

class PatchedCGenerator(c_generator.CGenerator):
    """Like a CGenerator, except it keeps else if's prettier despite
    the terrible things we've done to them in normalize_ast."""
    def visit_If(self, n):
        n2 = n
        if (n.iffalse and isinstance(n.iffalse, c_ast.Compound) and
                len(n.iffalse.block_items or []) == 1 and
                isinstance(n.iffalse.block_items[0], c_ast.If)):
            n2 = c_ast.If(cond=n.cond, iftrue=n.iftrue,
                    iffalse=n.iffalse.block_items[0])
        return super().visit_If(n2)

def to_c(ast):
    source = PatchedCGenerator().visit(ast)
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

def find_fns(ast):
    ret = []
    for node in ast.ext:
        if isinstance(node, c_ast.FuncDef):
            ret.append(node)
    return ret

def compute_node_indices(top_node):
    indices = {}
    cur_index = 0
    class Visitor(c_ast.NodeVisitor):
        def generic_visit(self, node):
            nonlocal cur_index
            indices[node] = cur_index
            cur_index += 1
            super().generic_visit(node)
    Visitor().visit(top_node)
    return indices

def compute_write_locations(top_node, indices):
    writes = {}
    def add_write(var_name, loc):
        if var_name not in writes:
            writes[var_name] = []
        else:
            assert loc > writes[var_name][-1], \
                    "consistent traversal order should guarantee monotonicity here"
        writes[var_name].append(loc)
    class Visitor(c_ast.NodeVisitor):
        def visit_Decl(self, node):
            add_write(node.name, indices[node])
            self.generic_visit(node)
        def visit_UnaryOp(self, node):
            if node.op in ['p++', 'p--', '++', '--'] and isinstance(node.expr, c_ast.ID):
                add_write(node.expr.name, indices[node])
            self.generic_visit(node)
        def visit_Assignment(self, node):
            if isinstance(node.lvalue, c_ast.ID):
                add_write(node.lvalue.name, indices[node])
            self.generic_visit(node)
    Visitor().visit(top_node)
    return writes

def compute_read_locations(top_node, indices):
    reads = {}
    for node in find_var_reads(top_node):
        var_name = node.name
        loc = indices[node]
        if var_name not in reads:
            reads[var_name] = []
        else:
            assert loc > reads[var_name][-1], \
                    "consistent traversal order should guarantee monotonicity here"
        reads[var_name].append(loc)
    return reads

def find_var_reads(top_node):
    ret = []
    class Visitor(c_ast.NodeVisitor):
        def visit_Decl(self, node):
            if node.init:
                self.visit(node.init)
        def visit_ID(self, node):
            ret.append(node)
        def visit_StructRef(self, node):
            self.visit(node.name)
        def visit_Assignment(self, node):
            if isinstance(node.lvalue, c_ast.ID):
                return
            self.generic_visit(node)
    Visitor().visit(top_node)
    return ret

def replace_subexprs(top_node, callback):
    def rec(node, toplevel=False):
        assert node is not None
        if isinstance(node, c_ast.Assignment):
            node.rvalue = rec(node.rvalue)
        elif isinstance(node, c_ast.StructRef):
            node.name = rec(node.name)
        elif isinstance(node, (c_ast.Return, c_ast.Cast)):
            if node.expr:
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
                rec(node.args, True)
        elif isinstance(node, c_ast.ExprList):
            if not toplevel:
                x = callback(node)
                if x: return x
            for i in range(len(node.exprs)):
                node.exprs[i] = rec(node.exprs[i])
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
            if node.cond:
                node.cond = rec(node.cond)
            if node.next:
                node.next = rec(node.next, True)
            node.stmt = rec(node.stmt, True)
        elif isinstance(node, c_ast.TernaryOp):
            if not toplevel:
                x = callback(node)
                if x: return x
            node.cond = rec(node.cond)
            node.iftrue = rec(node.iftrue)
            node.iffalse = rec(node.iffalse)
        elif isinstance(node, c_ast.While):
            node.cond = rec(node.cond)
            node.stmt = rec(node.stmt, True)
        elif isinstance(node, c_ast.DoWhile):
            node.stmt = rec(node.stmt, True)
            node.cond = rec(node.cond)
        elif isinstance(node, c_ast.Switch):
            node.cond = rec(node.cond)
            node.stmt = rec(node.stmt, True)
        elif isinstance(node, c_ast.Label):
            node.stmt = rec(node.stmt, True)
        elif isinstance(node, c_ast.If):
            node.cond = rec(node.cond)
            node.iftrue = rec(node.iftrue, True)
            if node.iffalse:
                node.iffalse = rec(node.iffalse, True)
        elif isinstance(node, (c_ast.TypeDecl, c_ast.PtrDecl, c_ast.ArrayDecl,
                c_ast.Typename, c_ast.EmptyStatement, c_ast.Pragma, c_ast.Break,
                c_ast.Continue, c_ast.Goto)):
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

def brace_nested_blocks(stmt):
    def brace(stmt):
        if isinstance(stmt, (c_ast.Compound, c_ast.Case, c_ast.Default)):
            return stmt
        return c_ast.Compound([stmt])
    if isinstance(stmt, (c_ast.For, c_ast.While, c_ast.DoWhile)):
        stmt.stmt = brace(stmt.stmt)
    elif isinstance(stmt, c_ast.If):
        stmt.iftrue = brace(stmt.iftrue)
        if stmt.iffalse:
            stmt.iffalse = brace(stmt.iffalse)
    elif isinstance(stmt, c_ast.Switch):
        stmt.stmt = brace(stmt.stmt)
    elif isinstance(stmt, c_ast.Label):
        brace_nested_blocks(stmt.stmt)

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
        callback(stmt.stmt)
    elif isinstance(stmt, (c_ast.Case, c_ast.Default)):
        callback(stmt)
    elif isinstance(stmt, c_ast.Label):
        for_nested_blocks(stmt.stmt, callback)

def perm_temp_for_expr(fn, ast):
    phase = 0
    einds = {}
    sumprob = 0
    targetprob = None
    found = None
    indices = compute_node_indices(fn)
    writes = compute_write_locations(fn, indices)
    reads = compute_read_locations(fn, indices)
    typemap = build_typemap(ast)

    def rec(block, reuse_cands):
        stmts = get_block_stmts(block, False)
        reuse_cands = reuse_cands[:]
        assignment_cands = [] # places to insert before
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
                assignment_cands.append((block, index, stmt))

            for_nested_blocks(stmt, lambda b: rec(b, reuse_cands))

            def replacer(expr):
                nonlocal sumprob
                nonlocal found
                if found is not None:
                    return None

                if DEBUG_EAGER_TYPES:
                    decayed_expr_type(expr, typemap)

                eind = einds.get(id(expr), 0)
                sub_reads = find_var_reads(expr)
                latest_write = -1
                for sub_read in sub_reads:
                    var_name = sub_read.name
                    if var_name not in writes:
                        continue
                    # Find the first write that is strictly before indices[expr]
                    ind = bisect.bisect_left(writes[var_name], indices[expr])
                    if ind == 0:
                        continue
                    latest_write = max(latest_write, writes[var_name][ind - 1])

                for place in assignment_cands[::-1]:
                    # If expr contains an ID which is written to within
                    # [place, expr), bail out; we're trying to move the
                    # assignment too high up.
                    # TODO: also fail on moving past function calls, or
                    # possibly-aliasing writes.
                    if indices[place[2]] <= latest_write:
                        break

                    prob = 1 / (1 + eind)
                    if isinstance(expr, (c_ast.ID, c_ast.Constant)):
                        prob *= 0.5
                    sumprob += prob
                    if phase == 1 and sumprob > targetprob:
                        type: SimpleType = decayed_expr_type(expr, typemap)
                        reused = False
                        if random.randint(0,1) and reuse_cands:
                            var = c_ast.ID(random.choice(reuse_cands))
                            var_type: SimpleType = decayed_expr_type(var, typemap)
                            if same_type(var_type, type, typemap, allow_similar=True):
                                reused = True
                        if not reused:
                            var = c_ast.ID('new_var')
                        found = (place, expr, var, type, reused)
                        return var
                    eind += 1
                einds[id(expr)] = eind
                return None
            replace_subexprs(stmt, replacer)

    rec(fn.body, [])
    phase = 1
    targetprob = random.uniform(0, sumprob)
    sumprob = 0
    einds = {}
    rec(fn.body, [])

    assert found is not None
    location, expr, var, type, reused = found
    # print("replacing:", to_c(expr))
    block, index, _ = location
    assignment = c_ast.Assignment('=', var, expr)
    insert_statement(block, index, assignment)
    if not reused:
        decl = c_ast.Decl(name=var.name, quals=[], storage=[], funcspec=[],
                type=copy.deepcopy(type), init=None, bitsize=None)
        set_decl_name(decl)
        insert_decl(fn, decl)

def perm_sameline(fn, ast):
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

def normalize_ast(ast):
    # Add braces to all ifs/fors/etc., to make it easier to insert statements.
    fn = find_fns(ast)[0]
    def rec(block):
        stmts = get_block_stmts(block, False)
        for stmt in stmts:
            brace_nested_blocks(stmt)
            for_nested_blocks(stmt, rec)
    rec(fn.body)

class Randomizer():
    def __init__(self, start_ast):
        self.start_ast = start_ast
        normalize_ast(self.start_ast)
        self.ast = self.start_ast

    def get_current_source(self):
        return to_c(self.ast)

    def randomize(self):
        ast = copy.deepcopy(self.start_ast)
        fn = find_fns(ast)[0]
        methods = [
            (perm_temp_for_expr, 90),
            #(perm_sameline, 10),
        ]
        method = random.choice([x for (elem, prob) in methods for x in [elem]*prob])
        method(fn, ast)
        self.ast = ast
