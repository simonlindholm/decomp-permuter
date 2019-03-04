#-----------------------------------------------------------------
# pycparser: c_ast.py
#
# AST Node classes.
#
# Eli Bendersky [https://eli.thegreenplace.net/]
# License: BSD
#-----------------------------------------------------------------


from typing import TextIO, Iterable, List, Any, Optional, Union as Union_
from .plyparser import Coord
import sys

class Node(object):
    coord: Optional[Coord]

    def __repr__(self) -> str: ...
    def __iter__(self) -> Iterable[Node]: ...
    def children(self) -> Iterable[Node]: ...
    def show(self, buf: TextIO=sys.stdout, offset: int=0, attrnames: bool=False, nodenames: bool=False, showcoord: bool=False) -> None: ...

Expression = Union_['ArrayRef', 'Assignment', 'BinaryOp', 'Cast',
        'CompoundLiteral', 'Constant', 'FuncCall', 'ID', 'TernaryOp']
Statement = Union_[Expression, 'Decl', 'Break', 'Case', 'Compound', 'Continue',
        'Decl', 'Default', 'DoWhile', 'EmptyStatement', 'For', 'Goto', 'If',
        'Label', 'Return', 'Switch', 'Typedef', 'Union', 'While', 'Pragma']
Type = Union_['PtrDecl', 'ArrayDecl', 'FuncDecl', 'TypeDecl']
InnerType = Union_['IdentifierType', 'Struct', 'Union']
ExternalDeclaration = Union_['FuncDef', 'Decl', 'Typedef', 'Pragma']

class NodeVisitor(object):
    # TODO: add other methods
    def visit(self, node: Node) -> Any: ...
    def generic_visit(self, node: Node) -> Any: ...

class ArrayDecl(Node):
    type: Type
    dim: Optional[Expression]
    dim_quals: List[str]
    def __init__(self, type: Type, dim: Optional[Node], dim_quals: List[str], coord: Coord=None): ...

class ArrayRef(Node):
    name: Expression
    subscript: Expression
    def __init__(self, name: Node, subscript: Node, coord: Coord=None): ...

class Assignment(Node):
    op: str
    lvalue: Expression
    rvalue: Expression
    def __init__(self, op: str, lvalue: Expression, rvalue: Expression, coord: Coord=None): ...

class BinaryOp(Node):
    op: str
    left: Expression
    right: Expression
    def __init__(self, op: str, left: Node, right: Node, coord: Coord=None): ...

class Break(Node):
    def __init__(self, coord: Coord=None): ...

class Case(Node):
    expr: Expression
    stmts: List[Statement]
    def __init__(self, expr: Expression, stmts: List[Statement], coord: Coord=None): ...

class Cast(Node):
    to_type: 'Typename'
    expr: Expression
    def __init__(self, to_type: 'Typename', expr: Expression, coord: Coord=None): ...

class Compound(Node):
    block_items: Optional[List[Statement]]
    def __init__(self, block_items: Optional[List[Statement]], coord: Coord=None): ...

class CompoundLiteral(Node):
    type: 'Typename'
    init: 'InitList'
    def __init__(self, type: 'Typename', init: 'InitList', coord: Coord=None): ...

class Constant(Node):
    type: str
    value: str
    def __init__(self, type: str, value: str, coord: Coord=None): ...

class Continue(Node):
    def __init__(self, coord: Coord=None): ...

class Decl(Node):
    name: Optional[str]
    quals: List[str] # e.g. const
    storage: List[str] # e.g. register
    funcspec: List[str] # e.g. inline
    type: Type
    init: Optional[Expression]
    bitsize: Optional[Expression]

    def __init__(self, name: Optional[str], quals: List[str], storage: List[str], funcspec: List[str], type: Type, init: Optional[Expression], bitsize: Optional[Expression], coord: Coord=None): ...

class DeclList(Node):
    decls: List[Decl]
    def __init__(self, decls: List[Decl], coord: Coord=None): ...

class Default(Node):
    stmts: List[Statement]
    def __init__(self, stmts: List[Statement], coord: Coord=None): ...

class DoWhile(Node):
    cond: Expression
    stmt: Statement
    def __init__(self, cond: Expression, stmt: Statement, coord: Coord=None): ...

class EllipsisParam(Node):
    def __init__(self, coord: Coord=None): ...

class EmptyStatement(Node):
    def __init__(self, coord: Coord=None): ...

class Enum(Node):
    name: Optional[str]
    values: 'EnumeratorList'
    def __init__(self, name: Optional[str], values: 'EnumeratorList', coord: Coord=None): ...

class Enumerator(Node):
    name: str
    value: Optional[Expression]
    def __init__(self, name: str, value: Optional[Expression], coord: Coord=None): ...

class EnumeratorList(Node):
    enumerators: List[Enumerator]
    def __init__(self, enumerators: List[Enumerator], coord: Coord=None): ...

class ExprList(Node):
    exprs: List[Union_[Expression, Typename]] # typename only for offsetof
    def __init__(self, exprs: List[Union_[Expression, Typename]], coord: Coord=None): ...

class FileAST(Node):
    ext: List[ExternalDeclaration]
    def __init__(self, ext: List[ExternalDeclaration], coord: Coord=None): ...

class For(Node):
    init: Union_[None, Expression, DeclList]
    cond: Optional[Expression]
    next: Optional[Expression]
    stmt: Statement
    def __init__(self, init: Union_[None, Expression, DeclList], cond: Optional[Expression], next: Optional[Expression], stmt: Statement, coord: Coord=None): ...

class FuncCall(Node):
    name: Expression
    args: Optional[ExprList]
    def __init__(self, name: Expression, args: Optional[ExprList], coord: Coord=None): ...

class FuncDecl(Node):
    args: Optional[ParamList]
    type: Type # return type
    def __init__(self, args: Optional[ParamList], type: Type, coord: Coord=None): ...

class FuncDef(Node):
    decl: Decl
    param_decls: Optional[List[Decl]]
    body: Compound
    def __init__(self, decl: Decl, param_decls: Optional[List[Decl]], body: Compound, coord: Coord=None): ...

class Goto(Node):
    name: str
    def __init__(self, name: str, coord: Coord=None): ...

class ID(Node):
    name: str
    def __init__(self, name: str, coord: Coord=None): ...

class IdentifierType(Node):
    names: List[str] # e.g. ['long', 'int']
    def __init__(self, names: List[str], coord: Coord=None): ...

class If(Node):
    cond: Expression
    iftrue: Statement
    iffalse: Optional[Statement]
    def __init__(self, cond: Expression, iftrue: Statement, iffalse: Optional[Statement], coord: Coord=None): ...

class InitList(Node):
    exprs: List[Union_[Expression, 'NamedInitializer']]
    def __init__(self, exprs: List[Union_[Expression, 'NamedInitializer']], coord: Coord=None): ...

class Label(Node):
    name: str
    stmt: Statement
    def __init__(self, name: str, stmt: Statement, coord: Coord=None): ...

class NamedInitializer(Node):
    name: List[Expression] # [ID(x), Constant(4)] for {.x[4] = ...}
    expr: Expression
    def __init__(self, name: List[Expression], expr: Expression, coord: Coord=None): ...

class ParamList(Node):
    params: List[Union_[Decl, ID, Typename, EllipsisParam]]
    def __init__(self, params: List[Union_[Decl, ID, Typename, EllipsisParam]], coord: Coord=None): ...

class PtrDecl(Node):
    quals: List[str]
    type: Type
    def __init__(self, quals: List[str], type: Type, coord: Coord=None): ...

class Return(Node):
    expr: Optional[Expression]
    def __init__(self, expr: Optional[Expression], coord: Coord=None): ...

class Struct(Node):
    name: Optional[str]
    decls: Optional[List[Decl]]
    def __init__(self, name: Optional[str], decls: Optional[List[Decl]], coord: Coord=None): ...

class StructRef(Node):
    name: Expression
    type: str
    field: ID
    def __init__(self, name: Expression, type: str, field: ID, coord: Coord=None): ...

class Switch(Node):
    cond: Expression
    stmt: Statement
    def __init__(self, cond: Expression, stmt: Statement, coord: Coord=None): ...

class TernaryOp(Node):
    cond: Expression
    iftrue: Expression
    iffalse: Expression
    def __init__(self, cond: Expression, iftrue: Expression, iffalse: Expression, coord: Coord=None): ...

class TypeDecl(Node):
    declname: Optional[str]
    quals: List[str]
    type: InnerType
    def __init__(self, declname: Optional[str], quals: List[str], type: InnerType, coord: Coord=None): ...

class Typedef(Node):
    name: str
    quals: List[str]
    storage: List[str]
    type: Type
    def __init__(self, name: str, quals: List[str], storage: List[str], type: Type, coord: Coord=None): ...

class Typename(Node):
    name: None
    quals: List[str]
    type: Type
    def __init__(self, name: None, quals: List[str], type: Type, coord: Coord=None): ...

class UnaryOp(Node):
    op: str
    expr: Union_[Expression, Typename]
    def __init__(self, op: str, expr: Union_[Expression, Typename], coord: Coord=None): ...

class Union(Node):
    name: Optional[str]
    decls: Optional[List[Decl]]
    def __init__(self, name: Optional[str], decls: Optional[List[Decl]], coord: Coord=None): ...

class While(Node):
    cond: Expression
    stmt: Statement
    def __init__(self, cond: Expression, stmt: Statement, coord: Coord=None): ...

class Pragma(Node):
    string: str
    def __init__(self, string: str, coord: Coord=None): ...

