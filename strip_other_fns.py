import sys

from pycparser import parse_file, c_ast, c_parser, c_generator

filename = sys.argv[1]
fn_name = sys.argv[2]

ast = parse_file(filename, use_cpp=False)

new_nodes = []
for node in ast.ext:
    if isinstance(node, c_ast.FuncDef) and node.decl.name != fn_name:
        node = node.decl
    new_nodes.append(node)
ast.ext = new_nodes

generator = c_generator.CGenerator()

ret = generator.visit(ast)
with open(filename, 'w') as f:
    f.write(ret)
