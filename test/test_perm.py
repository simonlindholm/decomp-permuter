# type: ignore
import unittest
import os
import tempfile
import shutil
from pathlib import Path
import re

from strip_other_fns import strip_other_fns_and_write
from src.compiler import Compiler
from src.preprocess import preprocess
from src import main


class TestPermMacros(unittest.TestCase):
    def go(self, intro, outro, base, target, fn_name=None, **kwargs) -> int:
        base = intro + "\n" + base + "\n" + outro
        target = intro + "\n" + target + "\n" + outro
        compiler = Compiler("test/compile.sh")

        # For debugging, to avoid the auto-deleted directory:
        # target_dir = tempfile.mkdtemp()
        with tempfile.TemporaryDirectory() as target_dir:
            with open(os.path.join(target_dir, "base.c"), "w") as f:
                f.write(base)

            target_o = compiler.compile(target, show_errors=True)
            assert target_o is not None
            shutil.move(target_o, os.path.join(target_dir, "target.o"))

            shutil.copy2("test/compile.sh", os.path.join(target_dir, "compile.sh"))

            if fn_name:
                with open(os.path.join(target_dir, "function.txt"), "w") as f:
                    f.write(fn_name)

            opts = main.Options(directories=[target_dir], stop_on_zero=True, **kwargs)
            return main.run(opts)[0]

    def test_general(self):
        score = self.go(
            "int test() {",
            "}",
            "return PERM_GENERAL(32,64);",
            "return 64;",
        )
        self.assertEqual(score, 0)

    def test_not_found(self):
        score = self.go(
            "int test() {",
            "}",
            "return PERM_GENERAL(32,64);",
            "return 92;",
        )
        self.assertNotEqual(score, 0)

    def test_multiple_functions(self):
        score = self.go(
            "",
            "",
            """
            int ignoreme() {}
            int foo() { return PERM_GENERAL(32,64); }
            int ignoreme2() {}
            """,
            "int foo() { return 64; }",
            fn_name="foo",
        )
        self.assertEqual(score, 0)

    def test_general_multiple(self):
        score = self.go(
            "int test() {",
            "}",
            "return PERM_GENERAL(1,2,3) + PERM_GENERAL(3,6,9);",
            "return 9;",
        )
        self.assertEqual(score, 0)

    def test_general_nested(self):
        score = self.go(
            "int test() {",
            "}",
            "return PERM_GENERAL(1,PERM_GENERAL(100,101),3) + PERM_GENERAL(3,6,9);",
            "return 110;",
        )
        self.assertEqual(score, 0)

    def test_ternary1(self):
        score = self.go(
            "int test(int cond) {",
            "}",
            "int test; PERM_TERNARY(test = ,cond,1,2) return test;",
            "int test; if (cond) test = 1; else test = 2; return test;",
        )
        self.assertEqual(score, 0)

    def test_ternary2(self):
        score = self.go(
            "int test(int cond) {",
            "}",
            "int test; PERM_TERNARY(test = ,cond,1,2) return test;",
            "int test; test = cond ? 1 : 2; return test;",
        )
        self.assertEqual(score, 0)

    def test_type1(self):
        score = self.go(
            "int test(int a, int b) {",
            "}",
            "return a / PERM_TYPECAST(,unsigned int,float) b;",
            "return a / b;",
        )
        self.assertEqual(score, 0)

    def test_type2(self):
        score = self.go(
            "int test(int a, int b) {",
            "}",
            "return a / PERM_TYPECAST(,unsigned int,float) b;",
            "return a / (unsigned int) b;",
        )
        self.assertEqual(score, 0)

    def test_type3(self):
        score = self.go(
            "int test(int a, int b) {",
            "}",
            "return a / PERM_TYPECAST(,unsigned int,float) b;",
            "return a / (float) b;",
        )
        self.assertEqual(score, 0)

    def test_type3_threaded(self):
        score = self.go(
            "int test(int a, int b) {",
            "}",
            "return a / PERM_TYPECAST(,unsigned int,float) b;",
            "return a / (float) b;",
            threads=2,
        )
        self.assertEqual(score, 0)

    def test_ignore(self):
        score = self.go(
            "int test(int a, int b) {",
            "}",
            "PERM_IGNORE( return a / PERM_GENERAL(a, b); )",
            "return a / b;",
        )
        self.assertEqual(score, 0)

    def test_once1(self):
        score = self.go(
            "volatile int A, B, C; void test() {",
            "}",
            """
                PERM_ONCE(B = 2;)
                A = 1;
                PERM_ONCE(B = 2;)
                C = 3;
                PERM_ONCE(B = 2;)
            """,
            "A = 1; B = 2; C = 3;",
        )
        self.assertEqual(score, 0)

    def test_once2(self):
        score = self.go(
            "volatile int A, B, C; void test() {",
            "}",
            """
                PERM_VAR(emit,)
                PERM_VAR(bademit,)
                PERM_ONCE(1, PERM_VAR(bademit, A = 7;) A = 2;)
                PERM_ONCE(1, PERM_VAR(emit, A = 1;))
                PERM_VAR(emit)
                PERM_VAR(bademit)
                PERM_ONCE(2, B = 2;)
                PERM_ONCE(2, B = 1;)
                PERM_ONCE(2,)
                PERM_ONCE(3, PERM_VAR(bademit, A = 9))
                PERM_ONCE(3, PERM_VAR(bademit, A = 9))
                C = 3;
            """,
            "A = 1; B = 2; C = 3;",
        )
        self.assertEqual(score, 0)

    def test_randomizer(self):
        score = self.go(
            "void foo(); void bar(); void test(void) {",
            "}",
            "PERM_RANDOMIZE(bar(); foo();)",
            "foo(); bar();",
        )
        self.assertEqual(score, 0)

    def test_auto_randomizer(self):
        score = self.go(
            "void foo(); void bar(); void test(void) {",
            "}",
            "bar(); foo();",
            "foo(); bar();",
        )
        self.assertEqual(score, 0)

    def test_randomizer_threaded(self):
        score = self.go(
            "void foo(); void bar(); void test(void) {",
            "}",
            "PERM_RANDOMIZE(bar(); foo();)",
            "foo(); bar();",
            threads=2,
        )
        self.assertEqual(score, 0)


if __name__ == "__main__":
    unittest.main()
