"""Functions and classes for dealing with types in a C AST.

They make a number of simplifying assumptions:
 - const and volatile doesn't matter.
 - function pointers don't exist.
 - arithmetic promotes all int-like types to 'int'.
 - no two variables can have the same name, even across functions.

For the purposes of the randomizer these restrictions are acceptable."""

from typing import Union, Dict, Set
import sys

import attr
from pycparser import c_ast
from pycparser.c_ast import ArrayDecl, TypeDecl, PtrDecl, IdentifierType

# (For simplicity we ignore FuncDecl)
Type = Union[PtrDecl, ArrayDecl, TypeDecl]
SimpleType = Union[PtrDecl, TypeDecl]

StructUnion = Union[c_ast.Struct, c_ast.Union]

@attr.s
class TypeMap:
    typedefs: Dict[str, Type] = attr.ib(factory=dict)
    fn_ret_types: Dict[str, Type] = attr.ib(factory=dict)
    var_types: Dict[str, Type] = attr.ib(factory=dict)
    struct_defs: Dict[str, StructUnion] = attr.ib(factory=dict)

def basic_type(name: str) -> TypeDecl:
    idtype = IdentifierType(names=[name])
    return TypeDecl(declname=None, quals=[], type=idtype)

def pointer(type: Type) -> Type:
    return PtrDecl(quals=[], type=type)

def resolve_typedefs(type: Type, typemap: TypeMap) -> Type:
    while (isinstance(type, TypeDecl) and
            isinstance(type.type, IdentifierType) and
            len(type.type.names) == 1 and
            type.type.names[0] in typemap.typedefs):
        type = typemap.typedefs[type.type.names[0]]
    return type

def pointer_decay(type: Type, typemap: TypeMap) -> SimpleType:
    real_type = resolve_typedefs(type, typemap)
    if isinstance(real_type, ArrayDecl):
        return PtrDecl(quals=[], type=real_type.type)
    return type

def deref_type(type: Type, typemap: TypeMap) -> Type:
    type = resolve_typedefs(type, typemap)
    assert isinstance(type, (ArrayDecl, PtrDecl)), "dereferencing non-pointer"
    return type.type

def struct_member_type(struct: StructUnion, field_name: str, typemap: TypeMap) -> Type:
    if not struct.decls:
        assert struct.name in typemap.struct_defs, \
                f"Accessing field {field_name} of undefined struct {struct.name}"
        struct = typemap.struct_defs[struct.name]
    for decl in struct.decls:
        if decl.name == field_name:
            return decl.type
    assert False, f"No field {field_name} in struct {struct.name}"

def expr_type(node: c_ast.Node, typemap: TypeMap) -> Type:
    def rec(sub_expr: c_ast.Node) -> Type:
        return expr_type(sub_expr, typemap)

    if isinstance(node, c_ast.Assignment):
        return rec(node.lvalue)
    if isinstance(node, c_ast.StructRef):
        lhs_type = rec(node.name)
        if node.type == '->':
            lhs_type = deref_type(lhs_type, typemap)
        struct_type = resolve_typedefs(lhs_type, typemap)
        assert isinstance(struct_type, TypeDecl)
        assert isinstance(struct_type.type, (c_ast.Struct, c_ast.Union)), \
                f"struct deref of non-struct {struct_type.declname}"
        return struct_member_type(struct_type.type, node.field.name, typemap)
    if isinstance(node, c_ast.Cast):
        return node.to_type.type
    if isinstance(node, c_ast.Constant):
        if node.type == 'string':
            return pointer(basic_type('char'))
        if node.type == 'int':
            return basic_type('int')
        if node.type == 'float':
            return basic_type('float')
        if node.type == 'double':
            return basic_type('double')
        assert False, f"unknown constant type {node.type}"
    if isinstance(node, c_ast.ID):
        return typemap.var_types[node.name]
    if isinstance(node, c_ast.UnaryOp):
        if node.op in ['p++', 'p--', '++', '--']:
            return rec(node.expr)
        if node.op == '&':
            return pointer(rec(node.expr))
        if node.op == '*':
            subtype = rec(node.expr)
            return deref_type(subtype, typemap)
        if node.op in ['sizeof', '-', '+', '~', '!']:
            return basic_type('int')
        assert False, f"unknown unary op {node.op}"
    if isinstance(node, c_ast.BinaryOp):
        lhs_type = pointer_decay(rec(node.left), typemap)
        rhs_type = pointer_decay(rec(node.right), typemap)
        if node.op in ['>>', '<<']:
            return lhs_type
        if node.op in ['<', '<=', '>', '>=', '==', '!=', '&&', '||']:
            return basic_type('int')
        if node.op in "&|^%":
            return basic_type('int')
        if node.op in "+-":
            real_lhs = resolve_typedefs(lhs_type, typemap)
            real_rhs = resolve_typedefs(rhs_type, typemap)
            lptr = isinstance(real_lhs, PtrDecl)
            rptr = isinstance(real_rhs, PtrDecl)
            if lptr or rptr:
                if lptr and rptr:
                    assert node.op != '+', "pointer + pointer"
                    return basic_type('int')
                if lptr:
                    return lhs_type
                assert node.op == '+', "int - pointer"
                return rhs_type
        if node.op in "*/+-":
            lhs_type = resolve_typedefs(lhs_type, typemap)
            rhs_type = resolve_typedefs(rhs_type, typemap)
            assert isinstance(lhs_type, TypeDecl)
            assert isinstance(rhs_type, TypeDecl)
            assert isinstance(lhs_type.type, IdentifierType)
            assert isinstance(rhs_type.type, IdentifierType)
            if 'double' in lhs_type.type.names + rhs_type.type.names:
                return basic_type('double')
            if 'float' in lhs_type.type.names + rhs_type.type.names:
                return basic_type('float')
            return basic_type('int')
    if isinstance(node, c_ast.FuncCall):
        return typemap.fn_ret_types[node.name.name]
    if isinstance(node, c_ast.ExprList):
        return rec(node.exprs[-1])
    if isinstance(node, c_ast.ArrayRef):
        subtype = rec(node.name)
        return deref_type(subtype, typemap)
    if isinstance(node, c_ast.TernaryOp):
        return rec(node.iftrue)
    assert False, f"Unknown expression node type: {node}"

def decayed_expr_type(expr: c_ast.Node, typemap: TypeMap) -> Type:
    return pointer_decay(expr_type(expr, typemap), typemap)

def same_type(type1: Type, type2: Type, typemap: TypeMap, allow_similar: bool=False):
    while True:
        type1 = resolve_typedefs(type1, typemap)
        type2 = resolve_typedefs(type2, typemap)
        if isinstance(type1, ArrayDecl) and isinstance(type2, ArrayDecl):
            type1 = type1.type
            type2 = type2.type
            continue
        if isinstance(type1, PtrDecl) and isinstance(type2, PtrDecl):
            type1 = type1.type
            type2 = type2.type
            continue
        if isinstance(type1, TypeDecl) and isinstance(type2, TypeDecl):
            sub1 = type1.type
            sub2 = type2.type
            if isinstance(sub1, c_ast.Struct) and isinstance(sub2, c_ast.Struct):
                return sub1.name == sub2.name
            if isinstance(sub1, c_ast.Union) and isinstance(sub2, c_ast.Union):
                return sub1.name == sub2.name
            if isinstance(sub1, IdentifierType) and isinstance(sub2, IdentifierType):
                if allow_similar:
                    # Int-ish types are similar
                    return True
                return sorted(sub1.names) == sorted(sub2.names)
        return False

def build_typemap(ast: c_ast.FileAST) -> TypeMap:
    ret = TypeMap()
    for item in ast.ext:
        if isinstance(item, c_ast.Typedef):
            ret.typedefs[item.name] = item.type
        if isinstance(item, c_ast.FuncDef):
            ret.fn_ret_types[item.decl.name] = item.decl.type.type
        if isinstance(item, c_ast.Decl) and isinstance(item.type, c_ast.FuncDecl):
            ret.fn_ret_types[item.name] = item.type.type
    defined_function_decls: Set[c_ast.Decl] = set()
    class Visitor(c_ast.NodeVisitor):
        def visit_Struct(self, struct: c_ast.Struct) -> None:
            if struct.decls:
                ret.struct_defs[struct.name] = struct
            # Do not visit decls of this struct
        def visit_Union(self, union: c_ast.Union) -> None:
            if union.decls:
                ret.struct_defs[union.name] = union
            # Do not visit decls of this union
        def visit_Decl(self, decl: c_ast.Decl) -> None:
            if not isinstance(decl.type, c_ast.FuncDecl):
                ret.var_types[decl.name] = decl.type
                self.visit(decl.type)
            elif decl in defined_function_decls:
                # Do not visit declarations in parameter lists of functions
                # other than our own.
                self.visit(decl.type)
        def visit_FuncDef(self, fn: c_ast.FuncDef) -> None:
            defined_function_decls.add(fn.decl)
            self.generic_visit(fn)
    Visitor().visit(ast)
    return ret

def set_decl_name(decl: c_ast.Decl) -> None:
    name = decl.name
    type = decl.type
    while not isinstance(type, TypeDecl):
        assert isinstance(type, (ArrayDecl, PtrDecl))
        type = type.type
    type.declname = name

