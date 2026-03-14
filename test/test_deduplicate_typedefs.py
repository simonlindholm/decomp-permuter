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

    def test_top_level_three_typedef_names(self):
        """Three typedef names — body appears once, two forward refs."""
        source = "typedef struct { int x; } A, B, C;\n"
        result = parse_and_dedup(source)
        self.assertIn("} A", result)
        self.assertIn("_PermuterAnon1 B", result)
        self.assertIn("_PermuterAnon1 C", result)
        self.assertEqual(result.count("int x;"), 1)

    def test_top_level_single_typedef_unchanged(self):
        """A single typedef name should not be altered."""
        source = "typedef struct { int x; } Foo;\n"
        result = parse_and_dedup(source)
        self.assertIn("int x;", result)
        self.assertNotIn("_PermuterAnon", result)

    def test_top_level_union_typedef(self):
        """Union typedef with two names."""
        source = "typedef union { int a; float b; } U1, U2;\n"
        result = parse_and_dedup(source)
        self.assertIn("} U1", result)
        self.assertIn("_PermuterAnon1 U2", result)
        self.assertEqual(result.count("int a;"), 1)

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

    def test_nested_named_struct_three_members(self):
        """Three member names sharing a named nested struct."""
        source = """\
struct Outer {
    struct Inner { int val; } a, b, c;
};
"""
        result = parse_and_dedup(source)
        self.assertIn("} a", result)
        self.assertIn("struct Inner b", result)
        self.assertIn("struct Inner c", result)
        self.assertEqual(result.count("int val;"), 1)

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

    def test_nested_union_members(self):
        """Union declared inline with two member names inside a struct."""
        source = """\
struct Outer {
    union { int a; float b; } u1, u2;
};
"""
        result = parse_and_dedup(source)
        self.assertIn("} u1", result)
        self.assertIn("_PermuterAnon1 u2", result)
        self.assertEqual(result.count("int a;"), 1)

    def test_struct_inside_union_members(self):
        """Struct with multi-name declaration inside a union container."""
        source = """\
union Outer {
    struct Inner { int val; } f1, f2;
    int raw;
};
"""
        result = parse_and_dedup(source)
        self.assertIn("} f1", result)
        self.assertIn("struct Inner f2", result)
        self.assertEqual(result.count("int val;"), 1)

    def test_nested_single_member_unchanged(self):
        """A single member name — no deduplication needed."""
        source = """\
struct Outer {
    struct Inner { int val; } only;
};
"""
        result = parse_and_dedup(source)
        self.assertIn("int val;", result)
        self.assertIn("} only", result)
        self.assertNotIn("_PermuterAnon", result)

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

    def test_sibling_nested_structs(self):
        """Two independent nested structs with multi-name declarations
        inside the same outer struct."""
        source = """\
struct Outer {
    struct A { int a; } a1, a2;
    struct B { int b; } b1, b2;
};
"""
        result = parse_and_dedup(source)
        self.assertEqual(result.count("int a;"), 1)
        self.assertIn("} a1", result)
        self.assertIn("struct A a2", result)
        self.assertEqual(result.count("int b;"), 1)
        self.assertIn("} b1", result)
        self.assertIn("struct B b2", result)

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

    def test_array_member_multi_decl(self):
        """Multi-name declaration where members are arrays of a nested
        struct — the ArrayDecl wrapper must be traversed."""
        source = """\
struct Outer {
    struct Inner { int val; } arr1[2], arr2[3];
};
"""
        result = parse_and_dedup(source)
        self.assertEqual(result.count("int val;"), 1)

    # ------------------------------------------------------------------
    # Edge cases / no-ops
    # ------------------------------------------------------------------

    def test_no_multi_decl_at_all(self):
        """No shared nodes anywhere — output should be structurally identical."""
        source = """\
struct A { int a; };
struct B { struct A m; };
"""
        result = parse_and_dedup(source)
        self.assertIn("int a;", result)
        self.assertNotIn("_PermuterAnon", result)

    def test_forward_ref_passthrough(self):
        """Forward-declared struct used only as a pointer should survive."""
        source = "struct Fwd; struct S { struct Fwd *p; };\n"
        result = parse_and_dedup(source)
        self.assertIn("struct Fwd", result)

    def test_empty_file(self):
        """An empty translation unit should not crash."""
        result = parse_and_dedup("")
        self.assertEqual(result.strip(), "")

    def test_only_functions(self):
        """A file with only function definitions — nothing to deduplicate."""
        source = "int foo(void) { return 0; }\n"
        result = parse_and_dedup(source)
        self.assertIn("foo", result)


if __name__ == "__main__":
    unittest.main()
