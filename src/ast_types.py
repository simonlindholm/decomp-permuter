"""Functions and classes for dealing with types in a C AST.

They make a number of simplifying assumptions:
 - const and volatile doesn't matter.
 - arithmetic promotes all int-like types to 'int'.
 - no two variables can have the same name, even across functions.

For the purposes of the randomizer these restrictions are acceptable."""

from dataclasses import dataclass, field
from typing import Union, Dict, Set, List

from pycparser import c_ast as ca

Type = Union[ca.PtrDecl, ca.ArrayDecl, ca.TypeDecl, ca.FuncDecl]
SimpleType = Union[ca.PtrDecl, ca.TypeDecl]

StructUnion = Union[ca.Struct, ca.Union]


@dataclass
class TypeMap:
    typedefs: Dict[str, Type] = field(default_factory=dict)
    var_types: Dict[str, Type] = field(default_factory=dict)
    local_vars: Set[str] = field(default_factory=set)
    struct_defs: Dict[str, StructUnion] = field(default_factory=dict)


def is_local_var(name: str, typemap: TypeMap) -> bool:
    return name in typemap.local_vars


def basic_type(name: Union[str, List[str]]) -> ca.TypeDecl:
    names = [name] if isinstance(name, str) else name
    idtype = ca.IdentifierType(names=names)
    return ca.TypeDecl(declname=None, quals=[], align=[], type=idtype)


def pointer(type: Type) -> ca.PtrDecl:
    return ca.PtrDecl(quals=[], type=type)


def resolve_typedefs(type: Type, typemap: TypeMap) -> Type:
    while (
        isinstance(type, ca.TypeDecl)
        and isinstance(type.type, ca.IdentifierType)
        and len(type.type.names) == 1
        and type.type.names[0] in typemap.typedefs
    ):
        type = typemap.typedefs[type.type.names[0]]
    return type


def pointer_decay(type: Type, typemap: TypeMap) -> SimpleType:
    real_type = resolve_typedefs(type, typemap)
    if isinstance(real_type, ca.ArrayDecl):
        return pointer(real_type.type)
    if isinstance(real_type, ca.FuncDecl):
        return pointer(type)
    if isinstance(real_type, ca.TypeDecl) and isinstance(real_type.type, ca.Enum):
        return basic_type("int")
    assert not isinstance(
        type, (ca.ArrayDecl, ca.FuncDecl)
    ), "resolve_typedefs can't hide arrays/functions"
    return type


def get_decl_type(decl: ca.Decl) -> Type:
    """For a Decl that declares a variable (and not just a struct/union/enum),
    return its type."""
    assert decl.name is not None
    assert isinstance(decl.type, (ca.PtrDecl, ca.ArrayDecl, ca.FuncDecl, ca.TypeDecl))
    return decl.type


def deref_type(type: Type, typemap: TypeMap) -> Type:
    type = resolve_typedefs(type, typemap)
    assert isinstance(type, (ca.ArrayDecl, ca.PtrDecl)), "dereferencing non-pointer"
    return type.type


def struct_member_type(struct: StructUnion, field_name: str, typemap: TypeMap) -> Type:
    if not struct.decls:
        assert (
            struct.name in typemap.struct_defs
        ), f"Accessing field {field_name} of undefined struct {struct.name}"
        struct = typemap.struct_defs[struct.name]
    assert struct.decls, "struct_defs never points to an incomplete type"
    for decl in struct.decls:
        if isinstance(decl, ca.Decl):
            if decl.name == field_name:
                return get_decl_type(decl)
            if decl.name == None and isinstance(decl.type, (ca.Struct, ca.Union)):
                try:
                    return struct_member_type(decl.type, field_name, typemap)
                except AssertionError:
                    pass

    assert False, f"No field {field_name} in struct {struct.name}"


def expr_type(node: ca.Node, typemap: TypeMap) -> Type:
    def rec(sub_expr: ca.Node) -> Type:
        return expr_type(sub_expr, typemap)

    if isinstance(node, ca.Assignment):
        return rec(node.lvalue)
    if isinstance(node, ca.StructRef):
        lhs_type = rec(node.name)
        if node.type == "->":
            lhs_type = deref_type(lhs_type, typemap)
        struct_type = resolve_typedefs(lhs_type, typemap)
        assert isinstance(struct_type, ca.TypeDecl)
        assert isinstance(
            struct_type.type, (ca.Struct, ca.Union)
        ), f"struct deref of non-struct {struct_type.declname}"
        return struct_member_type(struct_type.type, node.field.name, typemap)
    if isinstance(node, ca.Cast):
        return node.to_type.type
    if isinstance(node, ca.Constant):
        if node.type == "string":
            return pointer(basic_type("char"))
        if node.type == "char":
            return basic_type("int")
        return basic_type(node.type.split(" "))
    if isinstance(node, ca.ID):
        return typemap.var_types[node.name]
    if isinstance(node, ca.UnaryOp):
        if node.op in ["p++", "p--", "++", "--"]:
            return rec(node.expr)
        if node.op == "&":
            return pointer(rec(node.expr))
        if node.op == "*":
            subtype = rec(node.expr)
            return deref_type(subtype, typemap)
        if node.op in ["-", "+"]:
            subtype = pointer_decay(rec(node.expr), typemap)
            if allowed_basic_type(subtype, typemap, ["double"]):
                return basic_type("double")
            if allowed_basic_type(subtype, typemap, ["float"]):
                return basic_type("float")
        if node.op in ["sizeof", "-", "+", "~", "!"]:
            return basic_type("int")
        assert False, f"unknown unary op {node.op}"
    if isinstance(node, ca.BinaryOp):
        lhs_type = pointer_decay(rec(node.left), typemap)
        rhs_type = pointer_decay(rec(node.right), typemap)
        if node.op in [">>", "<<"]:
            return lhs_type
        if node.op in ["<", "<=", ">", ">=", "==", "!=", "&&", "||"]:
            return basic_type("int")
        if node.op in "&|^%":
            return basic_type("int")
        real_lhs = resolve_typedefs(lhs_type, typemap)
        real_rhs = resolve_typedefs(rhs_type, typemap)
        if node.op in "+-":
            lptr = isinstance(real_lhs, ca.PtrDecl)
            rptr = isinstance(real_rhs, ca.PtrDecl)
            if lptr or rptr:
                if lptr and rptr:
                    assert node.op != "+", "pointer + pointer"
                    return basic_type("int")
                if lptr:
                    return lhs_type
                assert node.op == "+", "int - pointer"
                return rhs_type
        if node.op in "*/+-":
            assert isinstance(real_lhs, ca.TypeDecl)
            assert isinstance(real_rhs, ca.TypeDecl)
            assert isinstance(real_lhs.type, ca.IdentifierType)
            assert isinstance(real_rhs.type, ca.IdentifierType)
            if "double" in real_lhs.type.names + real_rhs.type.names:
                return basic_type("double")
            if "float" in real_lhs.type.names + real_rhs.type.names:
                return basic_type("float")
            return basic_type("int")
    if isinstance(node, ca.FuncCall):
        expr = node.name
        fptr_type = resolve_typedefs(rec(expr), typemap)
        if isinstance(fptr_type, ca.PtrDecl):
            fptr_type = fptr_type.type
        fptr_type = resolve_typedefs(fptr_type, typemap)
        assert isinstance(fptr_type, ca.FuncDecl), "call to non-function"
        return fptr_type.type
    if isinstance(node, ca.ExprList):
        return rec(node.exprs[-1])
    if isinstance(node, ca.ArrayRef):
        subtype = rec(node.name)
        return deref_type(subtype, typemap)
    if isinstance(node, ca.TernaryOp):
        return rec(node.iftrue)
    assert False, f"Unknown expression node type: {node}"


def decayed_expr_type(expr: ca.Node, typemap: TypeMap) -> SimpleType:
    return pointer_decay(expr_type(expr, typemap), typemap)


def _same_param_type(
    p1: Union[ca.Decl, ca.ID, ca.Typename, ca.EllipsisParam],
    p2: Union[ca.Decl, ca.ID, ca.Typename, ca.EllipsisParam],
    typemap: TypeMap,
) -> bool:
    if isinstance(p1, ca.EllipsisParam) and isinstance(p2, ca.EllipsisParam):
        return True
    if isinstance(p1, ca.ID) and isinstance(p2, ca.ID):
        return p1.name == p2.name
    if (
        isinstance(p1, (ca.Typename, ca.Decl))
        and isinstance(p2, (ca.Typename, ca.Decl))
        and isinstance(p1.type, (ca.PtrDecl, ca.ArrayDecl, ca.TypeDecl, ca.FuncDecl))
        and isinstance(p2.type, (ca.PtrDecl, ca.ArrayDecl, ca.TypeDecl, ca.FuncDecl))
        and same_type(p1.type, p2.type, typemap)
    ):
        return True
    return False


def same_type(
    type1: Type, type2: Type, typemap: TypeMap, allow_similar: bool = False
) -> bool:
    while True:
        type1 = resolve_typedefs(type1, typemap)
        type2 = resolve_typedefs(type2, typemap)
        if isinstance(type1, ca.ArrayDecl) and isinstance(type2, ca.ArrayDecl):
            type1 = type1.type
            type2 = type2.type
            continue
        if isinstance(type1, ca.PtrDecl) and isinstance(type2, ca.PtrDecl):
            type1 = type1.type
            type2 = type2.type
            continue
        if isinstance(type1, ca.TypeDecl) and isinstance(type2, ca.TypeDecl):
            sub1 = type1.type
            sub2 = type2.type
            if isinstance(sub1, ca.Struct) and isinstance(sub2, ca.Struct):
                return sub1.name == sub2.name
            if isinstance(sub1, ca.Union) and isinstance(sub2, ca.Union):
                return sub1.name == sub2.name
            if (
                allow_similar
                and isinstance(sub1, (ca.IdentifierType, ca.Enum))
                and isinstance(sub2, (ca.IdentifierType, ca.Enum))
            ):
                # All int-ish types are similar (except void, but whatever)
                return True
            if isinstance(sub1, ca.Enum) and isinstance(sub2, ca.Enum):
                return sub1.name == sub2.name
            if isinstance(sub1, ca.IdentifierType) and isinstance(
                sub2, ca.IdentifierType
            ):
                return sorted(sub1.names) == sorted(sub2.names)
        if isinstance(type1, ca.FuncDecl) and isinstance(type2, ca.FuncDecl):
            params1 = type1.args.params if type1.args else []
            params2 = type2.args.params if type2.args else []
            if len(params1) != len(params2):
                return False
            for param1, param2 in zip(params1, params2):
                if not _same_param_type(param1, param2, typemap):
                    return False
            type1 = type1.type
            type2 = type2.type
            allow_similar = False
            continue
        return False


def allowed_basic_type(
    type: SimpleType, typemap: TypeMap, allowed_types: List[str]
) -> bool:
    """Check if a type resolves to a basic type with one of the allowed_types
    keywords in it."""
    base_type = resolve_typedefs(type, typemap)
    if not isinstance(base_type, ca.TypeDecl):
        return False
    if not isinstance(base_type.type, ca.IdentifierType):
        return False
    if all(x not in base_type.type.names for x in allowed_types):
        return False
    return True


def build_typemap(ast: ca.FileAST, target_fn: ca.FuncDef) -> TypeMap:
    ret = TypeMap()
    for item in ast.ext:
        if isinstance(item, ca.Typedef):
            ret.typedefs[item.name] = item.type
    within_fn: bool = False

    class Visitor(ca.NodeVisitor):
        def visit_Struct(self, struct: ca.Struct) -> None:
            if struct.decls and struct.name is not None:
                ret.struct_defs[struct.name] = struct
            # Do not visit decls of this struct

        def visit_Union(self, union: ca.Union) -> None:
            if union.decls and union.name is not None:
                ret.struct_defs[union.name] = union
            # Do not visit decls of this union

        def visit_FuncDecl(self, fn_decl: ca.FuncDecl) -> None:
            self.visit(fn_decl.type)
            # Do not visit params of this function declaration

        def visit_Decl(self, decl: ca.Decl) -> None:
            if decl.name is not None:
                ret.var_types[decl.name] = get_decl_type(decl)
                if within_fn:
                    ret.local_vars.add(decl.name)
            self.visit(decl.type)

        def visit_Enumerator(self, enumerator: ca.Enumerator) -> None:
            ret.var_types[enumerator.name] = basic_type("int")

        def visit_FuncDef(self, fn: ca.FuncDef) -> None:
            assert isinstance(fn.decl.type, ca.FuncDecl)
            if fn.decl.name is None:
                return
            ret.var_types[fn.decl.name] = get_decl_type(fn.decl)
            if fn is target_fn:
                nonlocal within_fn
                within_fn = True
                if fn.decl.type.args:
                    self.visit(fn.decl.type.args)
                self.visit(fn.body)
                within_fn = False

    Visitor().visit(ast)
    return ret


def set_decl_name(decl: ca.Decl) -> None:
    name = decl.name
    assert name is not None
    type = get_decl_type(decl)
    while not isinstance(type, ca.TypeDecl):
        type = type.type
    type.declname = name
