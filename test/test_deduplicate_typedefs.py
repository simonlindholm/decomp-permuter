import unittest

from perm_pycparser import c_ast as ca, c_generator
from perm_pycparser.c_parser import CParser

from src.ast_util import deduplicate_typedefs


def parse_and_dedup(source: str) -> str:
    """Parse C source, run deduplicate_typedefs, and return the resulting C."""
    parser = CParser()
    ast = parser.parse(source, "<source>")
    deduplicate_typedefs(ast)
    return c_generator.CGenerator().visit(ast)


class TestDeduplicateTypedefs(unittest.TestCase):
    """Tests for deduplicate_typedefs handling of shared struct/union/enum
    nodes produced by multi-name declarations."""

    # ------------------------------------------------------------------
    # Top-level typedefs
    # ------------------------------------------------------------------

    def test_top_level_anonymous_struct_typedef(self):
        """Anonymous struct with two typedef names gets a generated tag;
        only the first typedef keeps the body."""
        source = "typedef struct { int x; } Foo, Bar;\n"
        result = parse_and_dedup(source)
        self.assertIn("_PermuterAnon1", result)
        self.assertIn("} Foo", result)
        self.assertIn("_PermuterAnon1 Bar", result)
        self.assertEqual(result.count("int x;"), 1)

    def test_top_level_named_struct_typedef(self):
        """Named struct keeps its tag; second typedef becomes a forward ref."""
        source = "typedef struct S { int x; } A, B;\n"
        result = parse_and_dedup(source)
        self.assertIn("struct S", result)
        self.assertIn("} A", result)
        self.assertIn("struct S B", result)
        self.assertEqual(result.count("int x;"), 1)
        self.assertNotIn("_PermuterAnon", result)

    def test_top_level_single_typedef_unchanged(self):
        """A single typedef name should not be altered."""
        source = "typedef struct { int x; } Foo;\n"
        result = parse_and_dedup(source)
        self.assertIn("int x;", result)
        self.assertNotIn("_PermuterAnon", result)

    def test_top_level_enum_typedef(self):
        """Enum typedef with two names."""
        source = "typedef enum { VAL_A, VAL_B } E1, E2;\n"
        result = parse_and_dedup(source)
        self.assertIn("} E1", result)
        self.assertIn("_PermuterAnon1 E2", result)
        self.assertEqual(result.count("VAL_A"), 1)

    # ------------------------------------------------------------------
    # Nested struct/union members with multi-name declarations
    # ------------------------------------------------------------------

    def test_nested_named_struct_two_members(self):
        """Named struct declared inline with two member names inside an
        outer struct.  The body should appear once."""
        source = """\
struct Outer {
    struct Inner { int val; } m1, m2;
};
"""
        result = parse_and_dedup(source)
        self.assertIn("} m1", result)
        self.assertIn("struct Inner m2", result)
        self.assertEqual(result.count("int val;"), 1)
        self.assertNotIn("_PermuterAnon", result)

    def test_nested_anonymous_struct_members(self):
        """Anonymous struct with two member names gets a generated tag."""
        source = """\
struct Outer {
    struct { int val; } m1, m2;
};
"""
        result = parse_and_dedup(source)
        self.assertIn("} m1", result)
        self.assertIn("_PermuterAnon1 m2", result)
        self.assertEqual(result.count("int val;"), 1)

    # ------------------------------------------------------------------
    # Deeply nested / multi-level
    # ------------------------------------------------------------------

    def test_two_levels_of_multi_decl(self):
        """Both inner and outer structs use multi-name declarations.
        Each body should appear exactly once."""
        source = """\
struct L0 {
    struct L1 {
        struct L2 { int val; } x, y;
    } p, q;
};
"""
        result = parse_and_dedup(source)
        # L2 body once, under x
        self.assertEqual(result.count("int val;"), 1)
        self.assertIn("} x", result)
        self.assertIn("struct L2 y", result)
        # L1 body once, under p
        self.assertIn("} p", result)
        self.assertIn("struct L1 q", result)

    # ------------------------------------------------------------------
    # Mixed top-level and nested
    # ------------------------------------------------------------------

    def test_top_level_and_nested_in_same_tu(self):
        """A top-level typedef multi-decl and a nested member multi-decl
        coexist without interfering."""
        source = """\
typedef struct { int t; } T1, T2;
struct Outer {
    struct Inner { int n; } m1, m2;
};
"""
        result = parse_and_dedup(source)
        # top-level
        self.assertIn("} T1", result)
        self.assertIn("_PermuterAnon1 T2", result)
        self.assertEqual(result.count("int t;"), 1)
        # nested
        self.assertIn("} m1", result)
        self.assertIn("struct Inner m2", result)
        self.assertEqual(result.count("int n;"), 1)

    # ------------------------------------------------------------------
    # Pointer / array member wrappers
    # ------------------------------------------------------------------

    def test_pointer_member_multi_decl(self):
        """Multi-name declaration where members are pointers to a nested
        struct — the PtrDecl wrapper must be traversed."""
        source = """\
struct Outer {
    struct Inner { int val; } *p1, *p2;
};
"""
        result = parse_and_dedup(source)
        self.assertEqual(result.count("int val;"), 1)

if __name__ == "__main__":
    unittest.main()
