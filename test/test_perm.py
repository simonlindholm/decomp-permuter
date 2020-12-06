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


class TestStringMethods(unittest.TestCase):
    def go(self, filename, fn_name, **kwargs) -> int:
        compiler = Compiler("test/compile.sh")

        with tempfile.TemporaryDirectory() as target_dir:
            file_test = os.path.join("test", filename)
            file_actual = os.path.join(target_dir, "actual.c")
            file_base = os.path.join(target_dir, "base.c")
            file_target = os.path.join(target_dir, "target.o")

            actual_preprocessed = preprocess(file_test, cpp_args=["-DACTUAL"])
            base_preprocessed = preprocess(file_test, cpp_args=["-UACTUAL"])

            # Strip away other functions to be able to get an .o file with
            # only the target function to compare again.
            strip_other_fns_and_write(actual_preprocessed, fn_name, file_actual)

            # For symmetry, do the same for the base file. This isn't technically
            # necessary.
            strip_other_fns_and_write(base_preprocessed, fn_name, file_base)

            actual_source = Path(file_actual).read_text()
            target_o = compiler.compile(actual_source, show_errors=True)
            assert target_o is not None
            shutil.copy2(target_o, file_target)
            os.remove(target_o)

            shutil.copy2("test/compile.sh", target_dir)

            opts = main.Options(directories=[target_dir], stop_on_zero=True, **kwargs)
            return main.run(opts)[0]

    def test_general(self):
        score = self.go("test_general.c", "test_general")
        self.assertEqual(score, 0)

    def test_general_3(self):
        score = self.go("test_general.c", "test_general_3")
        self.assertEqual(score, 0)

    def test_general_multiple(self):
        score = self.go("test_general.c", "test_general_multiple")
        self.assertEqual(score, 0)

    def test_ternary1(self):
        score = self.go("test_ternary.c", "test_ternary1")
        self.assertEqual(score, 0)

    def test_ternary2(self):
        score = self.go("test_ternary.c", "test_ternary2")
        self.assertEqual(score, 0)

    def test_type1(self):
        score = self.go("test_type.c", "test_type1")
        self.assertEqual(score, 0)

    def test_type2(self):
        score = self.go("test_type.c", "test_type2")
        self.assertEqual(score, 0)

    def test_type3(self):
        score = self.go("test_type.c", "test_type3")
        self.assertEqual(score, 0)

    def test_type3_threaded(self):
        score = self.go("test_type.c", "test_type3", threads=2)
        self.assertEqual(score, 0)

    def test_ignore(self):
        score = self.go("test_ignore.c", "test_ignore")
        self.assertEqual(score, 0)

    def test_once1(self):
        score = self.go("test_once.c", "test_once1")
        self.assertEqual(score, 0)

    def test_once2(self):
        score = self.go("test_once.c", "test_once2")
        self.assertEqual(score, 0)

    def test_randomizer(self):
        score = self.go("test_randomizer.c", "test_randomizer")
        self.assertEqual(score, 0)

    def test_auto_randomizer(self):
        score = self.go("test_randomizer.c", "test_randomizer2")
        self.assertEqual(score, 0)

    def test_randomizer_threaded(self):
        score = self.go("test_randomizer.c", "test_randomizer", threads=2)
        self.assertEqual(score, 0)


if __name__ == "__main__":
    unittest.main()
