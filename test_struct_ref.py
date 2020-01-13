#!/usr/bin/env python

from pycparser import c_ast as ca, c_parser, c_generator
from pathlib import Path
from collections import defaultdict
from random import Random
from itertools import product
import copy

source = Path('test_struct_ref.c').read_text()

ast = c_parser.CParser().parse(source, filename='test_struct_ref.c')

cg = c_generator.CGenerator()
random = Random()

def write_output_header(f):
    f.write("#include <stdio.h>\n" +
            "struct test{\n" +
            "    int c;\n" +
            "};\n" +
            "\n" +
            "int main() {\n" +
            "    int b;\n" +
            "    struct test t = {69};\n" +
            "    struct test *a, **p2, ***p3;\n" +
            "    a = &t;\n" +
            "    p2 = &a;\n" +
            "    p3 = &p2;\n")

def write_output(f, cg, node):
    f.write(f'    printf("%-30s: %d\\n", "{cg.visit(node)}", {cg.visit(node)});\n')

def write_output_footer(f):
    f.write('    puts("nice");\n}\n');

cands = []
class Visitor(ca.NodeVisitor):
    def visit_StructRef(self, node: ca.StructRef):
        cands.append(node)
Visitor().visit(ast.ext)


# TODO: This might need to handle nested BinaryOps
def randomize_associative_binop(left: ca.Node, right: ca.BinaryOp) -> ca.BinaryOp:
    """Try moving parentheses to the left side sometimes (sadly, it seems to matter)"""
    if random.choice([True, False]) and right.op in ['+', '-']:
        # ((a + b) - c)
        return ca.BinaryOp(right.op, ca.BinaryOp('+', left, right.left), right.right)
    else:
        # (a + (b - c))
        return ca.BinaryOp('+', left, right)

# Conversions
def to_array(node: ca.BinaryOp) -> ca.ArrayRef:
    """a[b].c"""
    # Handle different expressions like (a - 1)->c
    if (node.op == '-'):
        node.right = ca.UnaryOp('-', node.right)
    return ca.ArrayRef(node.left, node.right)

def to_binop(node: ca.ArrayRef) -> ca.BinaryOp:
    """(a + b)->c"""
    if isinstance(node.subscript, ca.BinaryOp):
        return randomize_associative_binop(node.name, node.subscript)
    return ca.BinaryOp('+', node.name, node.subscript)

# Add / subtract a level of indirection
def deref(node: ca.Node) -> ca.UnaryOp:
    # This should be possible but it would mess up my crappy tree handling code :|
    #
    #if isinstance(node, ca.UnaryOp) and node.op == '&':
    #    return node.expr
    return ca.UnaryOp('*', node)

def addr(node: ca.Node) -> ca.UnaryOp:
    # This should be possible but it would mess up my crappy tree handling code :|
    #
    #if isinstance(node, ca.UnaryOp) and node.op == '*':
    #    return node.expr
    return ca.UnaryOp('&', node)


cg = c_generator.CGenerator()

# Step 1: Simplify by converting lhs to BinaryOp 
nodes = []
def rec(node: ca.Node) -> bool:
    global nodes
    if isinstance(node, ca.UnaryOp) and node.op in ['&', '*']:
        if rec(node.expr):
            nodes.append(node)
            return True
    else:
        nodes.append(node)
        return isinstance(node, (ca.ArrayRef, ca.BinaryOp))

    return False

# (Oh god why) 

def apply_child(parent: ca.Node, func):
    if isinstance(parent, ca.StructRef):
        parent.name = func(parent.name)
    elif isinstance(parent, ca.UnaryOp):
        parent.expr = func(parent.expr)

def set_child(parent: ca.Node, child):
    if isinstance(parent, ca.StructRef):
        parent.name = child
    elif isinstance(parent, ca.UnaryOp):
        parent.expr = child

def get_child(parent: ca.Node):
    if isinstance(parent, ca.StructRef):
        return parent.name
    elif isinstance(parent, ca.UnaryOp):
        return parent.expr

def perm_struct_ref(sref, f):
    global nodes
    print('\033[94m')
    print(cg.visit(sref),end='')
    print('\033[m')
    sref.show()
    for choices in product([True, False], [True, False]):
        print(choices)
        cur_sref = copy.deepcopy(sref)
        nodes = []

        binop_or_aref = rec(cur_sref.name)
        if cur_sref.type == '->':
            cur_sref.type = '.'
            cur_sref.name = deref(cur_sref.name)
            nodes.append(cur_sref.name)
            print('-> changed: \033[33m',cg.visit(cur_sref),'\033[m')
        nodes.append(cur_sref)

        if not binop_or_aref:
            if not choices[0]:
                # Only two possibilities for ID StructRefs
                print('\033[33mID StructRef\033[m: Stop early')
                return
            if choices[1]: #random.choice([True, False]):
                apply_child(cur_sref, addr)
                cur_sref.type = '->'
                print('After changing back to ->: \033[33m',cg.visit(cur_sref),'\033[m')
        else:
            # nodes now contains at least 3 elements: [the arrayref or binop, at least one * or &, the structref]
            # For binops, a lhs like  &(a+b)->c is impossible, because a + b is an rvalue

            if isinstance(nodes[0], ca.ArrayRef):
                apply_child(nodes[1], deref)
                nodes.insert(1, get_child(nodes[1]))
                apply_child(nodes[1], to_binop)
                nodes[0] = get_child(nodes[1])
                print('Simplified: \033[33m',cg.visit(cur_sref),'\033[m')


            # Step 3: Convert lhs back to array ref
            if choices[0]: #random.choice([True, False]):
                if isinstance(nodes[1], ca.UnaryOp) and nodes[1].op == '*':
                    apply_child(nodes[1], to_array)
                    nodes[0] = get_child(nodes[1])
                    set_child(nodes[2], nodes[0])
                    print('Converted to array: \033[33m',cg.visit(cur_sref),'\033[m')

            # Step 4: Convert the StructRef type back
            if choices[1]: #random.choice([True, False]):
                apply_child(cur_sref, addr)
                cur_sref.type = '->'
                print('Converted back to ->: \033[33m',cg.visit(cur_sref),'\033[m')
        print('final: \033[92m',cg.visit(cur_sref),'\033[m\n')
        write_output(f, cg, cur_sref)

out = Path('struct_ref_out.c')
with out.open('w') as f:
    write_output_header(f)
    for sref in cands:
        perm_struct_ref(sref, f)
    write_output_footer(f)

# sref                # type of a         # possible conversion
################################################################
# (a + b).c;          # impossible        # 
# (a + b)->c;         # s*                # a[b].c
# (*(a + b)).c;       # s*                # a[b].c
# (*(a + b))->c;      # s**               # (*(a[b]).c
# &(a + b).c;         # impossible        # 
# &(a + b)->c;        # impossible        # 
# (*(&(a + b))).c;    # impossible        # 
# (*(&(a + b)))->c;   # imp: a+b=rvalue   # (*(&(a[b]))).c
# (&(*(a + b))).c;    # impossible        # 
# (&(*(a + b)))->c;   # s*                # a[b].c (-&* req.)
################################################################
# (a[b]).c;           # s*                # (a + b)->c
# (a[b])->c;          # s**               # (*(a + b))->c
# (*(a[b])).c;        # s**               # (*(a + b))->c
# (*(a[b]))->c;       # s***              # (*(*(a + b)))->c
# (&(a[b])).c;        # impossible        # 
# (&(a[b]))->c;       # s*                # (&(*(a + b)))->c
# (*(&(a[b]))).c;     # s*                # (*(&(a + b)))->c
# (*(&(a[b])))->c;    # s**               # (*(&(*(a + b))))->c
# (&(*(a[b]))).c;     # impossible        # 
# (&(*(a[b])))->c;    # s**               # (&(*(*(a + b))))->c
################################################################
# a.c                 # s                 # (&a)->c
# a->c                # s*                # (*a).c
# (*a).c              # s*                # a->c
# (*a)->c             # s**               # (*(*a)).c
# (&a).c              # impossible        #
# (&a)->c             # s                 # (*(&a)).c
