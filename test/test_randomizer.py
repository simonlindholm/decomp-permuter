import unittest

from perm_pycparser import c_parser

from src.randomizer import RANDOMIZATION_PASSES, Randomizer


class TestUnknownIdentifiers(unittest.TestCase):
    def test_inline_pass_survives_undeclared_functions(self) -> None:
        # Decompiled code calls functions the file never declares. The inline pass asks for the type of every
        # identifier in the expression it picks, which used to end the whole candidate with a KeyError.
        src = """
        int test(int a) {
            int b;
            b = undeclared_fn(a) + 1;
            return undeclared_fn(b) + a;
        }
        """
        weights = {method.__name__: 0.0 for method in RANDOMIZATION_PASSES}
        weights["perm_inline"] = 1.0
        for seed in range(300):
            ast = c_parser.CParser().parse(src)
            Randomizer(weights, seed).randomize(ast, "test")


if __name__ == "__main__":
    unittest.main()
