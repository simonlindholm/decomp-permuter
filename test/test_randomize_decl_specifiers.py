from random import Random
import unittest
from typing import Set

from src import ast_util
from src.randomizer import (
    RANDOMIZATION_PASSES,
    Region,
    perm_randomize_decl_specifiers,
)


class TestRandomizeDeclSpecifiers(unittest.TestCase):
    def randomizations(self, declaration: str) -> Set[str]:
        source = f"int target(void) {{ {declaration} value; value = 1; return value; }}"
        outputs: Set[str] = set()

        for seed in range(100):
            ast = ast_util.parse_c(source)
            fn, _ = ast_util.extract_fn(ast, "target")
            indices = ast_util.compute_node_indices(fn)
            perm_randomize_decl_specifiers(
                fn, ast, indices, Region.unbounded(), Random(seed)
            )
            outputs.add(ast_util.to_c(ast))

        return outputs

    def test_adds_storage_and_const_specifiers(self) -> None:
        outputs = self.randomizations("int")

        self.assertTrue(any("static int value" in output for output in outputs))
        self.assertTrue(any("extern int value" in output for output in outputs))
        self.assertTrue(any("const int value" in output for output in outputs))

    def test_removes_existing_specifiers(self) -> None:
        static_outputs = self.randomizations("static int")
        extern_outputs = self.randomizations("extern int")
        const_outputs = self.randomizations("const int")

        self.assertTrue(
            any("static int value" not in output for output in static_outputs)
        )
        self.assertTrue(
            any("extern int value" not in output for output in extern_outputs)
        )
        self.assertTrue(
            any("const int value" not in output for output in const_outputs)
        )

    def test_pass_is_enabled_by_default(self) -> None:
        self.assertIn(perm_randomize_decl_specifiers, RANDOMIZATION_PASSES)


if __name__ == "__main__":
    unittest.main()
