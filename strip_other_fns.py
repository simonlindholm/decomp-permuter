import sys

from pycparser import parse_file, c_ast, c_parser, c_generator

def strip_other_fns(filename, fn_name, out_name = None, use_cpp=False, cpp_args = ''):
    if out_name == None:
        out_name = filename

    ast = parse_file(filename, use_cpp=use_cpp, cpp_args=cpp_args)

    new_nodes = []
    for node in ast.ext:
        if isinstance(node, c_ast.FuncDef) and node.decl.name != fn_name:
            node = node.decl
        new_nodes.append(node)
    ast.ext = new_nodes

    generator = c_generator.CGenerator()

    ret = generator.visit(ast)
    with open(out_name, 'w') as f:
        f.write(ret)

if __name__ == "__main__":
    filename = sys.argv[1]
    fn_name = sys.argv[2]
    strip_other_fns(filename, fn_name)
    pass
