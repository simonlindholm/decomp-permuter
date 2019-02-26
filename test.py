import sys

from pycparser import parse_file

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} filename.c")
    exit()

ast = parse_file(sys.argv[1], use_cpp=True)
ast.show()
# ast = c_parser.CParser().parse(src)
# print(ast)
