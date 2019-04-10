from typing import Dict, Union, List, Tuple, Callable, Optional, Any, Set
import attr
import bisect
import copy
from random import Random
import sys
import time
import typing

from pycparser import c_ast as ca, c_parser, c_generator

from ast_types import (SimpleType, TypeMap, build_typemap, decayed_expr_type,
        resolve_typedefs, same_type, set_decl_name)

# Set to true to perform expression type detection eagerly. This can help when
# debugging crashes in the ast_types code.
DEBUG_EAGER_TYPES = False

# Randomize the type of introduced temporary variable with this probability
RANDOMIZE_TYPE_PROB = 0.3

# Reuse an existing var instead of introducing a new temporary one with this probability
REUSE_VAR_PROB = 0.5

# When wrapping statements in a new block, use a same-line `do { ... } while(0);`
# (as opposed to non-same-line `if (1) { ... }`) with this probability.
# This matches what macros often do.
INS_BLOCK_DOWHILE_PROB = 0.5

# Make a pointer to a temporary expression, rather than copy it by value, with
# this probability. (This always happens for expressions of struct type,
# regardless of this probability.)
TEMP_PTR_PROB = 0.05

# When substituting a variable by its value, substitute all instances with this
# probability, rather than just a subrange or the complement of one.
PROB_REPLACE_ALL = 0.3

# When substituting a variable by its value, keep the variable assignment with
# this probability.
PROB_KEEP_REPLACED_VAR = 0.2

# Number larger than any node index. (If you're trying to compile a 1 GB large
# C file to matching asm, you have bigger problems than this limit.)
MAX_INDEX = 10**9

Indices = Dict[ca.Node, int]
Block = Union[ca.Compound, ca.Case, ca.Default]

@attr.s
class Region:
    start: int = attr.ib()
    end: int = attr.ib()
    indices: Optional[Indices] = attr.ib(cmp=False)

    @staticmethod
    def unbounded() -> 'Region':
        return Region(-1, MAX_INDEX, None)

    def is_unbounded(self) -> bool:
        return self.indices is None

    def contains_node(self, node: ca.Node) -> bool:
        """Check whether the region contains an entire node."""
        if self.indices is None:
            return True
        # We assume valid nesting of regions, so it's fine to check just the
        # node's starting index. (Though for clarify we should probably check
        # the end index as well, if we refactor the code so it's available.)
        return self.start < self.indices[node] < self.end

    def contains_pre(self, node: ca.Node) -> bool:
        """Check whether the region contains a point just before a given node."""
        if self.indices is None:
            return True
        return self.start < self.indices[node] <= self.end

    def contains_pre_index(self, index: int) -> bool:
        """Check whether the region contains a point just before a given node,
        as specified by its index."""
        if self.indices is None:
            return True
        return self.start < index <= self.end

if typing.TYPE_CHECKING:
    # ca.Expression and ca.Statement don't actually exist, they live only in
    # the stubs file.
    Expression = ca.Expression
    Statement = ca.Statement
else:
    Expression = Statement = None

class PatchedCGenerator(c_generator.CGenerator):
    """Like a CGenerator, except it keeps else if's prettier despite
    the terrible things we've done to them in normalize_ast."""
    def visit_If(self, n: ca.If) -> str:
        n2 = n
        if (n.iffalse and isinstance(n.iffalse, ca.Compound) and
                n.iffalse.block_items and
                len(n.iffalse.block_items) == 1 and
                isinstance(n.iffalse.block_items[0], ca.If)):
            n2 = ca.If(cond=n.cond, iftrue=n.iftrue,
                    iffalse=n.iffalse.block_items[0])
        return super().visit_If(n2) # type: ignore

def to_c(node: ca.Node) -> str:
    source = PatchedCGenerator().visit(node)
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
            elif stripped == '#pragma sameline end':
                same_line -= 1
                if same_line == 0:
                    out.append('\n')
            # Never output pragmas
            continue
        if not same_line:
            line += '\n'
        elif out and not out[-1].endswith('\n'):
            line = ' ' + line.lstrip()
        out.append(line)
    assert same_line == 0
    return ''.join(out).rstrip() + '\n'

def find_fn(ast: ca.FileAST) -> Tuple[ca.FuncDef, int]:
    ret = []
    for i, node in enumerate(ast.ext):
        if isinstance(node, ca.FuncDef):
            ret.append((node, i))
    assert len(ret) == 1
    return ret[0]

def compute_node_indices(top_node: ca.Node) -> Indices:
    indices = {}
    cur_index = 0
    class Visitor(ca.NodeVisitor):
        def generic_visit(self, node: ca.Node) -> None:
            nonlocal cur_index
            indices[node] = cur_index
            cur_index += 1
            super().generic_visit(node)
    Visitor().visit(top_node)
    return indices

def reverse_indices(indices: Indices) -> Dict[int, ca.Node]:
    ret = {}
    for k, v in indices.items():
        ret[v] = k
    return ret

def get_randomization_region(top_node: ca.Node, indices: Indices, random: Random) -> Region:
    ret: List[Region] = []
    cur_start: Optional[int] = None
    class Visitor(ca.NodeVisitor):
        def visit_Pragma(self, node: ca.Pragma) -> None:
            nonlocal cur_start
            if node.string == 'randomizer start':
                if cur_start is not None:
                    raise Exception("nested PERM_RANDOMIZE not supported")
                cur_start = indices[node]
            if node.string == 'randomizer end':
                assert cur_start is not None, "randomizer end without start"
                ret.append(Region(cur_start, indices[node], indices))
                cur_start = None
    Visitor().visit(top_node)
    assert cur_start is None, "randomizer start without end"
    if not ret:
        return Region.unbounded()
    return random.choice(ret)

def compute_write_locations(
    top_node: ca.Node, indices: Indices
) -> Dict[str, List[int]]:
    writes : Dict[str, List[int]] = {}
    def add_write(var_name: str, loc: int) -> None:
        if var_name not in writes:
            writes[var_name] = []
        else:
            assert loc > writes[var_name][-1], \
                    "consistent traversal order should guarantee monotonicity here"
        writes[var_name].append(loc)
    class Visitor(ca.NodeVisitor):
        def visit_Decl(self, node: ca.Decl) -> None:
            if node.name:
                add_write(node.name, indices[node])
            self.generic_visit(node)
        def visit_UnaryOp(self, node: ca.UnaryOp) -> None:
            if node.op in ['p++', 'p--', '++', '--'] and isinstance(node.expr, ca.ID):
                add_write(node.expr.name, indices[node])
            self.generic_visit(node)
        def visit_Assignment(self, node: ca.Assignment) -> None:
            if isinstance(node.lvalue, ca.ID):
                add_write(node.lvalue.name, indices[node])
            self.generic_visit(node)
    Visitor().visit(top_node)
    return writes

def compute_read_locations(
    top_node: ca.Node, indices: Indices
) -> Dict[str, List[int]]:
    reads: Dict[str, List[int]] = {}
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

def find_var_reads(top_node: ca.Node) -> List[ca.ID]:
    ret = []
    class Visitor(ca.NodeVisitor):
        def visit_Decl(self, node: ca.Decl) -> None:
            if node.init:
                self.visit(node.init)
        def visit_ID(self, node: ca.ID) -> None:
            ret.append(node)
        def visit_UnaryOp(self, node: ca.UnaryOp) -> None:
            if node.op == '&' and isinstance(node.expr, ca.ID):
                return
            self.generic_visit(node)
        def visit_StructRef(self, node: ca.StructRef) -> None:
            self.visit(node.name)
        def visit_Assignment(self, node: ca.Assignment) -> None:
            if isinstance(node.lvalue, ca.ID):
                return
            self.generic_visit(node)
    Visitor().visit(top_node)
    return ret

def visit_replace(
    top_node: ca.Node,
    callback: Callable[[ca.Node, bool], Any]
) -> None:
    def rec(orig_node: ca.Node, toplevel: bool=False) -> Any:
        node: 'ca.AnyNode' = typing.cast('ca.AnyNode', orig_node)
        repl = callback(node, not toplevel)
        if repl:
            return repl
        if isinstance(node, ca.Assignment):
            node.rvalue = rec(node.rvalue)
        elif isinstance(node, ca.StructRef):
            node.name = rec(node.name)
        elif isinstance(node, ca.Cast):
            if node.expr:
                node.expr = rec(node.expr)
        elif isinstance(node, (ca.Constant, ca.ID)):
            pass
        elif isinstance(node, ca.UnaryOp):
            if node.op not in ['p++', 'p--', '++', '--', '&', 'sizeof']:
                node.expr = rec(node.expr)
        elif isinstance(node, ca.BinaryOp):
            node.left = rec(node.left)
            node.right = rec(node.right)
        elif isinstance(node, ca.FuncCall):
            if node.args:
                rec(node.args, True)
        elif isinstance(node, ca.ExprList):
            for i in range(len(node.exprs)):
                if not isinstance(node.exprs[i], ca.Typename):
                    node.exprs[i] = rec(node.exprs[i])
        elif isinstance(node, ca.ArrayRef):
            node.name = rec(node.name)
            node.subscript = rec(node.subscript)
        elif isinstance(node, ca.TernaryOp):
            node.cond = rec(node.cond)
            node.iftrue = rec(node.iftrue, True)
            node.iffalse = rec(node.iffalse, True)
        elif isinstance(node, ca.Return):
            if node.expr:
                node.expr = rec(node.expr)
        elif isinstance(node, ca.Decl):
            if node.init:
                node.init = rec(node.init)
        elif isinstance(node, ca.For):
            if node.init:
                node.init = rec(node.init)
            if node.cond:
                node.cond = rec(node.cond)
            if node.next:
                node.next = rec(node.next, True)
            node.stmt = rec(node.stmt, True)
        elif isinstance(node, ca.Compound):
            for sub in node.block_items or []:
                rec(sub, True)
        elif isinstance(node, (ca.Case, ca.Default)):
            for sub in node.stmts or []:
                rec(sub, True)
        elif isinstance(node, ca.While):
            node.cond = rec(node.cond)
            node.stmt = rec(node.stmt, True)
        elif isinstance(node, ca.DoWhile):
            node.stmt = rec(node.stmt, True)
            node.cond = rec(node.cond)
        elif isinstance(node, ca.Switch):
            node.cond = rec(node.cond)
            node.stmt = rec(node.stmt, True)
        elif isinstance(node, ca.Label):
            node.stmt = rec(node.stmt, True)
        elif isinstance(node, ca.If):
            node.cond = rec(node.cond)
            node.iftrue = rec(node.iftrue, True)
            if node.iffalse:
                node.iffalse = rec(node.iffalse, True)
        elif isinstance(node, (ca.TypeDecl, ca.PtrDecl, ca.ArrayDecl,
                ca.Typename, ca.IdentifierType, ca.Struct,
                ca.Union, ca.Enum, ca.EmptyStatement, ca.Pragma,
                ca.Break, ca.Continue, ca.Goto, ca.CompoundLiteral,
                ca.Typedef, ca.FuncDecl, ca.FuncDef,
                ca.EllipsisParam, ca.Enumerator, ca.EnumeratorList,
                ca.FileAST, ca.InitList, ca.NamedInitializer,
                ca.ParamList)):
            pass
        else:
            _: None = node
            assert False, f"Node with unknown type: {node}"
        return node

    rec(top_node, True)

def replace_subexprs(
    top_node: ca.Node,
    callback: Callable[[Expression], Any]
) -> None:
    def expr_filter(node: ca.Node, is_expr: bool) -> Any:
        if not is_expr:
            return None
        return callback(typing.cast(Expression, node))
    visit_replace(top_node, expr_filter)

def equal_ast(a: ca.Node, b: ca.Node) -> bool:
    def equal(a: Any, b: Any) -> bool:
        if type(a) != type(b):
            return False
        if a is None:
            return b is None
        if isinstance(a, list):
            assert isinstance(b, list)
            if len(a) != len(b):
                return False
            for i in range(len(a)):
                if not equal(a[i], b[i]):
                    return False
            return True
        if isinstance(a, (int, str)):
            return bool(a == b)
        assert isinstance(a, ca.Node)
        for name in a.__slots__[:-2]: # type: ignore
            if not equal(getattr(a, name), getattr(b, name)):
                return False
        return True
    return equal(a, b)

def is_lvalue(expr: Expression) -> bool:
    if isinstance(expr, (ca.ID, ca.StructRef, ca.ArrayRef)):
        return True
    if isinstance(expr, ca.UnaryOp):
        return expr.op == '*'
    return False

def is_effectful(expr: Expression) -> bool:
    found = False
    class Visitor(ca.NodeVisitor):
        def visit_UnaryOp(self, node: ca.UnaryOp) -> None:
            nonlocal found
            if node.op in ['p++', 'p--', '++', '--']:
                found = True
            else:
                self.generic_visit(node.expr)
        def visit_FuncCall(self, _: ca.Node) -> None:
            nonlocal found
            found = True
        def visit_Assignment(self, _: ca.Node) -> None:
            nonlocal found
            found = True
    Visitor().visit(expr)
    return found

def get_block_stmts(block: Block, force: bool) -> List[Statement]:
    if isinstance(block, ca.Compound):
        ret = block.block_items or []
        if force and not block.block_items:
            block.block_items = ret
    else:
        ret = block.stmts or []
        if force and not block.stmts:
            block.stmts = ret
    return ret

def insert_decl(fn: ca.FuncDef, var: str, type: SimpleType) -> None:
    type=copy.deepcopy(type)
    decl = ca.Decl(name=var, quals=[], storage=[], funcspec=[],
            type=type, init=None, bitsize=None)
    set_decl_name(decl)
    assert fn.body.block_items, "Non-empty function"
    for index, stmt in enumerate(fn.body.block_items):
        if not isinstance(stmt, ca.Decl):
            break
    else:
        index = len(fn.body.block_items)
    fn.body.block_items[index:index] = [decl]

def insert_statement(block: Block, index: int, stmt: Statement) -> None:
    stmts = get_block_stmts(block, True)
    stmts[index:index] = [stmt]

def brace_nested_blocks(stmt: Statement) -> None:
    def brace(stmt: Statement) -> Block:
        if isinstance(stmt, (ca.Compound, ca.Case, ca.Default)):
            return stmt
        return ca.Compound([stmt])
    if isinstance(stmt, (ca.For, ca.While, ca.DoWhile)):
        stmt.stmt = brace(stmt.stmt)
    elif isinstance(stmt, ca.If):
        stmt.iftrue = brace(stmt.iftrue)
        if stmt.iffalse:
            stmt.iffalse = brace(stmt.iffalse)
    elif isinstance(stmt, ca.Switch):
        stmt.stmt = brace(stmt.stmt)
    elif isinstance(stmt, ca.Label):
        brace_nested_blocks(stmt.stmt)

def has_nested_block(node: ca.Node) -> bool:
    return isinstance(node, (ca.Compound, ca.For, ca.While, ca.DoWhile, ca.If,
        ca.Switch, ca.Case, ca.Default))

def for_nested_blocks(
    stmt: Statement,
    callback: Callable[[Block], None]
) -> None:
    def invoke(stmt: Statement) -> None:
        assert isinstance(stmt, (ca.Compound, ca.Case, ca.Default)), \
                "brace_nested_blocks should have turned nested statements into blocks"
        callback(stmt)
    if isinstance(stmt, ca.Compound):
        invoke(stmt)
    elif isinstance(stmt, (ca.For, ca.While, ca.DoWhile)):
        invoke(stmt.stmt)
    elif isinstance(stmt, ca.If):
        if stmt.iftrue:
            invoke(stmt.iftrue)
        if stmt.iffalse:
            invoke(stmt.iffalse)
    elif isinstance(stmt, ca.Switch):
        invoke(stmt.stmt)
    elif isinstance(stmt, (ca.Case, ca.Default)):
        invoke(stmt)
    elif isinstance(stmt, ca.Label):
        for_nested_blocks(stmt.stmt, callback)

def randomize_type(type: SimpleType, typemap: TypeMap, random: Random) -> SimpleType:
    type2 = resolve_typedefs(type, typemap)
    if not isinstance(type2, ca.TypeDecl):
        return type
    if not isinstance(type2.type, ca.IdentifierType):
        return type
    if all(x not in type2.type.names for x in ['int', 'char', 'long', 'short', 'unsigned']):
        return type
    new_names: List[str] = []
    if random.choice([True, False]):
        new_names.append('unsigned')
    new_names.append(random.choice(['char', 'short', 'int', 'int']))
    idtype = ca.IdentifierType(names=new_names)
    return ca.TypeDecl(declname=None, quals=[], type=idtype)

def get_insertion_points(
    fn: ca.FuncDef, region: Region
) -> List[Tuple[Block, int, Optional[ca.Node]]]:
    cands: List[Tuple[Block, int, Optional[ca.Node]]] = []
    def rec(block: Block) -> None:
        stmts = get_block_stmts(block, False)
        last_node: ca.Node = block
        for i, stmt in enumerate(stmts):
            if region.contains_pre(stmt):
                cands.append((block, i, stmt))
            for_nested_blocks(stmt, rec)
            last_node = stmt
        if region.contains_node(last_node):
            cands.append((block, len(stmts), None))
    rec(fn.body)
    return cands

def maybe_reuse_var(
    var: Optional[str],
    assign_before: ca.Node,
    orig_expr: Expression,
    type: SimpleType,
    reads: Dict[str, List[int]],
    writes: Dict[str, List[int]],
    indices: Indices,
    typemap: TypeMap,
    random: Random,
) -> Optional[str]:
    if random.uniform(0, 1) > REUSE_VAR_PROB or var is None:
        return None
    var_type: SimpleType = decayed_expr_type(ca.ID(var), typemap)
    if not same_type(var_type, type, typemap, allow_similar=True):
        return None
    def find_next(list: List[int], value: int) -> Optional[int]:
        ind = bisect.bisect_left(list, value)
        if ind < len(list):
            return list[ind]
        return None
    assignment_ind = indices[assign_before]
    expr_ind = indices[orig_expr]
    write = find_next(writes.get(var, []), assignment_ind)
    read = find_next(reads.get(var, []), assignment_ind)
    # TODO: if write/read is within expr, search again from after it (since
    # we move expr, uses within it aren't relevant).
    if read is not None and (write is None or write >= read):
        # We don't want to overwrite a variable which we later read,
        # unless we write to it before that read
        return None
    if write is not None and write < expr_ind:
        # Our write will be overwritten before we manage to read from it.
        return None
    return var

def perm_temp_for_expr(
    fn: ca.FuncDef, ast: ca.FileAST, indices: Indices, region: Region, random: Random
) -> bool:
    """Create a temporary variable for a random expression. The variable will
    be assigned at another random point (nearer the expression being more
    likely), possibly reuse an existing variable, possibly be of a different
    size/signedness, and possibly be used for other identical expressions as
    well. Only expressions within the given region may be chosen for
    replacement, but the assignment and the affected identical expressions may
    be outside of it."""
    Place = Tuple[Block, int, Statement]
    einds: Dict[ca.Node, int] = {}
    writes: Dict[str, List[int]] = compute_write_locations(fn, indices)
    reads: Dict[str, List[int]] = compute_read_locations(fn, indices)
    typemap = build_typemap(ast)
    candidates: List[Tuple[float, Tuple[Place, Expression, Optional[str]]]] = []

    # Step 0: decide whether to make a pointer to the chosen expression, or to
    # copy it by value.
    should_make_ptr = (random.uniform(0, 1) < TEMP_PTR_PROB)

    def surrounding_writes(expr: Expression, base: Expression) -> Tuple[int, int]:
        """Compute the previous and next write to a variable included in expr,
        starting from base. If none, default to -1 or MAX_INDEX respectively.
        If base itself writes to an included variable (e.g. if it is an
        increment expression), the \"next\" write will be defined as the node
        itself, while the \"previous\" will continue searching to the left."""
        sub_reads = find_var_reads(expr)
        prev_write = -1
        next_write = MAX_INDEX
        base_index = indices[base]
        for sub_read in sub_reads:
            var_name = sub_read.name
            if var_name not in writes:
                continue
            # Find the first write that is strictly before indices[expr],
            # and the first write that is on or after.
            wr = writes[var_name]
            ind = bisect.bisect_left(wr, base_index)
            if ind > 0:
                prev_write = max(prev_write, wr[ind - 1])
            if ind < len(wr):
                next_write = min(next_write, wr[ind])
        return prev_write, next_write

    # Step 1: assign probabilities to each place/expression
    def rec(block: Block, reuse_cands: List[str]) -> None:
        stmts = get_block_stmts(block, False)
        reuse_cands = reuse_cands[:]
        assignment_cands: List[Place] = [] # places to insert before
        past_decls = False
        for index, stmt in enumerate(stmts):
            if isinstance(stmt, ca.Decl):
                assert stmt.name, "Anonymous declarations cannot happen in functions"
                if not isinstance(stmt.type, ca.ArrayDecl):
                    reuse_cands.append(stmt.name)
                    if not isinstance(stmt.type, ca.PtrDecl):
                        # Make non-pointers more common
                        reuse_cands.append(stmt.name)
            elif not isinstance(stmt, ca.Pragma):
                past_decls = True
            if past_decls:
                assignment_cands.append((block, index, stmt))

            for_nested_blocks(stmt, lambda b: rec(b, reuse_cands))

            def visitor(expr: Expression) -> None:
                if DEBUG_EAGER_TYPES:
                    decayed_expr_type(expr, typemap)

                if not region.contains_node(expr):
                    return

                orig_expr = expr
                if should_make_ptr:
                    if not is_lvalue(expr):
                        return
                    expr = ca.UnaryOp('&', expr)

                eind = einds.get(expr, 0)
                prev_write, _ = surrounding_writes(expr, orig_expr)

                for place in assignment_cands[::-1]:
                    # If expr contains an ID which is written to within
                    # [place, expr), bail out; we're trying to move the
                    # assignment too high up.
                    # TODO: also fail on moving past function calls, or
                    # possibly-aliasing writes.
                    if indices[place[2]] <= prev_write:
                        break

                    # Make far-away places less likely, and similarly for
                    # trivial expressions.
                    eind += 1
                    prob = 1 / eind
                    if isinstance(orig_expr, (ca.ID, ca.Constant)):
                        prob *= 0.15 if should_make_ptr else 0.5
                    reuse_cand = random.choice(reuse_cands) if reuse_cands else None
                    candidates.append((prob, (place, expr, reuse_cand)))

                einds[expr] = eind
            replace_subexprs(stmt, visitor)

    rec(fn.body, [])

    if not candidates:
        return False

    # Step 2: decide on a place/expression
    sumprob = 0.0
    for (prob, cand) in candidates:
        sumprob += prob
    targetprob = random.uniform(0, sumprob)
    sumprob = 0.0
    chosen_cand = None
    for (prob, cand) in candidates:
        sumprob += prob
        if sumprob > targetprob:
            chosen_cand = cand
            break

    assert chosen_cand is not None, "math"
    place, expr, reuse_cand = chosen_cand
    type: SimpleType = decayed_expr_type(expr, typemap)

    if is_effectful(expr):
        # Don't replace effectful expressions. This is a bit expensive to
        # check, so do it here instead of within the visitor.
        return False

    # Always use pointers when replacing structs
    if (not should_make_ptr and isinstance(type, ca.TypeDecl) and
            isinstance(type.type, ca.Struct) and is_lvalue(expr)):
        should_make_ptr = True
        expr = ca.UnaryOp('&', expr)
        type = decayed_expr_type(expr, typemap)

    if should_make_ptr:
        assert isinstance(expr, ca.UnaryOp)
        assert not isinstance(expr.expr, ca.Typename)
        orig_expr = expr.expr
    else:
        orig_expr = expr
    # print("replacing:", to_c(expr))

    # Step 3: decide on a variable to hold the expression
    assign_before = place[2]
    reused_var = maybe_reuse_var(reuse_cand, assign_before, orig_expr, type,
            reads, writes, indices, typemap, random)
    if reused_var is not None:
        reused = True
        var = reused_var
    else:
        reused = False
        var = 'new_var'
        counter = 1
        while var in writes:
            counter += 1
            var = f'new_var{counter}'

    # Step 4: possibly expand the replacement to include duplicate expressions.
    prev_write, next_write = surrounding_writes(expr, orig_expr)
    prev_write = max(prev_write, indices[assign_before] - 1)
    replace_cands: List[Expression] = []
    def find_duplicates(e: Expression) -> None:
        if prev_write < indices[e] <= next_write and equal_ast(e, orig_expr):
            replace_cands.append(e)
    replace_subexprs(fn.body, find_duplicates)
    assert orig_expr in replace_cands
    index = replace_cands.index(orig_expr)
    lo_index = random.randint(0, index)
    hi_index = random.randint(index + 1, len(replace_cands))
    replace_cand_set = set(replace_cands[lo_index:hi_index])

    # Step 5: replace the chosen expression
    def replacer(e: Expression) -> Optional[Expression]:
        if e in replace_cand_set:
            if should_make_ptr:
                return ca.UnaryOp('*', ca.ID(var))
            else:
                return ca.ID(var)
        return None
    replace_subexprs(fn.body, replacer)

    # Step 6: insert the assignment and any new variable declaration
    block, index, _ = place
    assignment = ca.Assignment('=', ca.ID(var), expr)
    insert_statement(block, index, assignment)
    if not reused:
        if random.uniform(0, 1) < RANDOMIZE_TYPE_PROB:
            type = randomize_type(type, typemap, random)
        insert_decl(fn, var, type)

    return True

def perm_expand_expr(
    fn: ca.FuncDef, ast: ca.FileAST, indices: Indices, region: Region, random: Random
) -> bool:
    """Replace a random variable by its contents."""
    all_writes: Dict[str, List[int]] = compute_write_locations(fn, indices)
    all_reads: Dict[str, List[int]] = compute_read_locations(fn, indices)

    # Step 1: pick out a variable to replace
    rev: Dict[int, str] = {}
    for var, locs in all_reads.items():
        for index in locs:
            if region.contains_pre_index(index):
                rev[index] = var
    if not rev:
        return False
    index = random.choice(list(rev.keys()))
    var = rev[index]

    # Step 2: find the assignment it uses
    reads = all_reads[var]
    writes = all_writes.get(var, [])
    read = random.choice(reads)
    i = bisect.bisect_left(writes, index)
    if i == 0:
        # No write to replace the read by.
        return False
    before = writes[i-1]
    after = MAX_INDEX if i == len(writes) else writes[i]
    rev_indices = reverse_indices(indices)
    write = rev_indices[before]
    if isinstance(write, ca.Decl) and write.init:
        repl_expr = write.init
    elif isinstance(write, ca.Assignment):
        repl_expr = write.rvalue
    else:
        return False
    if is_effectful(repl_expr):
        return False

    # Step 3: pick of the range of variables to replace
    repl_cands = [i for i in reads if before < i < after and
                                      region.contains_pre_index(i)]
    assert repl_cands, "index is always in repl_cands"
    myi = repl_cands.index(index)
    if random.uniform(0, 1) >= PROB_REPLACE_ALL and len(repl_cands) > 1:
        # Keep using the variable for a bit in the middle
        side = random.randrange(3)
        H = len(repl_cands)
        loi = 0 if side == 0 else random.randint(0, myi)
        hii = H if side == 1 else random.randint(myi+1, H)
        if loi == 0 and hii == H:
            loi, hii = myi, myi + 1
        repl_cands[loi:hii] = []
        keep_var = True
    else:
        keep_var = (random.uniform(0, 1) < PROB_KEEP_REPLACED_VAR)
    repl_cands_set = set(repl_cands)

    # Step 4: do the replacement
    def callback(expr: ca.Node, is_expr: bool) -> Optional[ca.Node]:
        if indices[expr] in repl_cands_set:
            return copy.deepcopy(repl_expr)
        if expr == write and isinstance(write, ca.Assignment) and not keep_var:
            if is_expr:
                return write.lvalue
            else:
                return ca.EmptyStatement()
        return None
    visit_replace(fn.body, callback)
    if not keep_var and isinstance(write, ca.Decl):
        write.init = None
    return True

def perm_randomize_type(
    fn: ca.FuncDef, ast: ca.FileAST, indices: Indices, region: Region, random: Random
) -> bool:
    """Randomize types of pre-existing local variables. Function parameter
    types are not permuted (that would require removing forward declarations,
    and most likely parameters types are already correct). Only variables
    mentioned within the given region are affected."""
    ids: Set[Optional[str]] = set()
    class IdVisitor(ca.NodeVisitor):
        def visit_ID(self, node: ca.ID) -> None:
            if region.contains_node(node):
                ids.add(node.name)
    IdVisitor().visit(fn)

    typemap = build_typemap(ast)
    decls: List[ca.Decl] = []
    class Visitor(ca.NodeVisitor):
        def visit_Decl(self, decl: ca.Decl) -> None:
            if isinstance(decl.type, ca.TypeDecl) and decl.name in ids:
                decls.append(decl)
    Visitor().visit(fn)

    if len(decls) == 0:
        return False

    decl = random.choice(decls)
    assert isinstance(decl.type, ca.TypeDecl), "checked above"
    decl.type = randomize_type(decl.type, typemap, random)
    set_decl_name(decl)

    return True

def perm_ins_block(
    fn: ca.FuncDef, ast: ca.FileAST, indices: Indices, region: Region, random: Random
) -> bool:
    """Wrap a random range of statements within `if (1) { ... }` or
    `do { ... } while(0)`. Control flow can have remote effects, so this
    mostly ignores the region restriction."""
    cands: List[Block] = []
    def rec(block: Block) -> None:
        cands.append(block)
        for stmt in get_block_stmts(block, False):
            for_nested_blocks(stmt, rec)
    rec(fn.body)
    block = random.choice(cands)
    stmts = get_block_stmts(block, True)
    decl_count = 0
    for stmt in stmts:
        if isinstance(stmt, (ca.Decl, ca.Pragma)):
            decl_count += 1
        else:
            break
    lo = random.randrange(decl_count, len(stmts) + 1)
    hi = random.randrange(decl_count, len(stmts) + 1)
    if hi < lo:
        lo, hi = hi, lo
    new_block = ca.Compound(block_items=stmts[lo:hi])
    if (random.uniform(0, 1) < INS_BLOCK_DOWHILE_PROB and
            all(region.contains_node(n) for n in stmts[lo:hi])):
        cond = ca.Constant(type='int', value='0')
        stmts[lo:hi] = [
            ca.Pragma("sameline start"),
            ca.DoWhile(cond=cond, stmt=new_block),
            ca.Pragma("sameline end"),
        ]
    else:
        cond = ca.Constant(type='int', value='1')
        stmts[lo:hi] = [ca.If(cond=cond, iftrue=new_block, iffalse=None)]
    return True

def perm_sameline(
    fn: ca.FuncDef, ast: ca.FileAST, indices: Indices, region: Region, random: Random
) -> bool:
    """Put all statements within a random interval on the same line."""
    cands = get_insertion_points(fn, region)
    n = len(cands)
    if n < 3:
        return False
    # Generate a small random interval
    lef: float = n - 2
    for i in range(4):
        lef *= random.uniform(0, 1)
    le = int(lef) + 2
    i = random.randrange(n - le)
    j = i + le
    # Insert the second statement first, since inserting a statement may cause
    # later indices to move.
    insert_statement(cands[j][0], cands[j][1], ca.Pragma("sameline end"))
    insert_statement(cands[i][0], cands[i][1], ca.Pragma("sameline start"))
    return True

def perm_associative(
    fn: ca.FuncDef, ast: ca.FileAST, indices: Indices, region: Region, random: Random
) -> bool:
    """Change a+b into b+a, or similar for other commutative operations."""
    cands: List[ca.BinaryOp] = []
    commutative_ops = list("+*|&^<>") + ['<=', '>=', '==', '!=']
    class Visitor(ca.NodeVisitor):
        def visit_BinaryOp(self, node: ca.BinaryOp) -> None:
            if node.op in commutative_ops and region.contains_node(node):
                cands.append(node)
    if not cands:
        return False
    node = random.choice(cands)
    node.left, node.right = node.right, node.left
    if node.op[0] == '<':
        node.op = '>' + node.op[1:]
    elif node.op[0] == '>':
        node.op = '<' + node.op[1:]
    return True

def perm_add_self_assignment(
    fn: ca.FuncDef, ast: ca.FileAST, indices: Indices, region: Region, random: Random
) -> bool:
    """Introduce a "x = x;" somewhere."""
    cands = get_insertion_points(fn, region)
    vars: List[str] = []
    class Visitor(ca.NodeVisitor):
        def visit_Decl(self, decl: ca.Decl) -> None:
            if decl.name:
                vars.append(decl.name)
    if not vars or not cands:
        return False
    var = random.choice(vars)
    where = random.choice(cands)
    assignment = ca.Assignment('=', ca.ID(var), ca.ID(var))
    insert_statement(where[0], where[1], assignment)
    return True

def perm_reorder_stmts(
    fn: ca.FuncDef, ast: ca.FileAST, indices: Indices, region: Region, random: Random
) -> bool:
    """Move a statement to another random place."""
    cands = get_insertion_points(fn, region)

    # Don't reorder declarations, or put statements before them.
    cands = [c for c in cands if not isinstance(c[2], ca.Decl)]

    # Figure out candidate statements to be moved. Don't move pragmas; it can
    # cause assertion failures. Don't move blocks; statements are generally not
    # reordered across basic blocks, and we don't want to risk moving a block
    # to inside itself.
    source_inds = []
    for i, c in enumerate(cands):
        stmt = c[2]
        if (stmt is not None and not isinstance(stmt, ca.Pragma)
                and not has_nested_block(stmt)):
            source_inds.append(i)

    if not source_inds:
        return False
    fromi = random.choice(source_inds)
    toi = round(random.triangular(0, len(cands) - 1, fromi))

    fromb, fromi, _ = cands[fromi]
    tob, toi, _ = cands[toi]
    if fromb == tob and fromi < toi:
        toi -= 1
    if fromb == tob and fromi == toi:
        return False

    stmt = get_block_stmts(fromb, True).pop(fromi)
    insert_statement(tob, toi, stmt)
    return True

def normalize_ast(fn: ca.FuncDef, ast: ca.FileAST) -> None:
    """Add braces to all ifs/fors/etc., to make it easier to insert statements."""
    def rec(block: Block) -> None:
        stmts = get_block_stmts(block, False)
        for stmt in stmts:
            brace_nested_blocks(stmt)
            for_nested_blocks(stmt, rec)
    rec(fn.body)

class Randomizer:
    def __init__(self, start_ast: ca.FileAST, random: Random) -> None:
        self.orig_fn, self.fn_index = find_fn(start_ast)
        normalize_ast(self.orig_fn, start_ast)
        self.orig_fn = copy.deepcopy(self.orig_fn)
        self.cur_ast = start_ast
        self.random = random

    def get_current_source(self) -> str:
        return to_c(self.cur_ast)

    def reset(self) -> None:
        self.cur_ast.ext[self.fn_index] = copy.deepcopy(self.orig_fn)

    def randomize(self) -> None:
        ast = self.cur_ast
        fn = ast.ext[self.fn_index]
        assert isinstance(fn, ca.FuncDef)
        indices = compute_node_indices(fn)
        region = get_randomization_region(fn, indices, self.random)
        methods = [
            (perm_temp_for_expr, 100),
            (perm_expand_expr, 20),
            (perm_randomize_type, 10),
            (perm_sameline, 10),
            (perm_ins_block, 10),
            (perm_add_self_assignment, 5),
            (perm_reorder_stmts, 5),
            (perm_associative, 5),
        ]
        while True:
            method = self.random.choice([x for (elem, prob) in methods for x in [elem]*prob])
            ret = method(fn, ast, indices, region, self.random)
            if ret:
                break
