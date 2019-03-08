import unittest
import main
import os.path as path
import os
import tempfile
from strip_other_fns import strip_other_fns_and_write
import shutil
from compiler import Compiler
from pathlib import Path
from preprocess import preprocess
import re

c_files_list = [
    ['test_general.c', 'test_general'],
    ['test_general.c', 'test_general_3'],
    ['test_general.c', 'test_general_multiple'],
    ['test_ternary.c', 'test_ternary1'],
    ['test_ternary.c', 'test_ternary2'],
    ['test_type.c', 'test_type1'],
    ['test_type.c', 'test_type2'],
    ['test_type.c', 'test_type3'],
]

class TestStringMethods(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = Compiler('test/compile.sh')
        cls.tmp_dirs = {}
        for test_c, test_fn in c_files_list:
            d = tempfile.TemporaryDirectory()
            file_test = path.join('test', test_c)
            file_actual = path.join(d.name, "actual.c")
            file_base = path.join(d.name, "base.c")
            file_target = path.join(d.name, "target.o")

            actual_preprocessed = preprocess(file_test, cpp_args=['-DACTUAL'])
            base_preprocessed = preprocess(file_test, cpp_args=['-UACTUAL'])

            strip_other_fns_and_write(actual_preprocessed, test_fn, file_actual)
            strip_other_fns_and_write(base_preprocessed, test_fn, file_base)

            actual_source = Path(file_actual).read_text()
            target_o = compiler.compile(actual_source)
            shutil.copy2(target_o, file_target)
            os.remove(target_o)

            shutil.copy2("test/compile.sh", d.name)
            cls.tmp_dirs[(test_c, test_fn)] = d
            
    @classmethod
    def tearDownClass(cls):
        for _, d in cls.tmp_dirs:
            del d

    def test_general(self):
        d = self.tmp_dirs[('test_general.c', 'test_general')].name
        score = main.main(main.Options(directories=[d]))
        self.assertEqual(score, 0)

    def test_general_3(self):
        d = self.tmp_dirs[('test_general.c', 'test_general_3')].name
        score = main.main(main.Options(directories=[d]))
        self.assertEqual(score, 0)

    def test_general_multiple(self):
        d = self.tmp_dirs[('test_general.c', 'test_general_multiple')].name
        score = main.main(main.Options(directories=[d]))
        self.assertEqual(score, 0)

    def test_ternary1(self):
        d = self.tmp_dirs[('test_ternary.c', 'test_ternary1')].name
        score = main.main(main.Options(directories=[d]))
        self.assertEqual(score, 0)

    def test_ternary2(self):
        d = self.tmp_dirs[('test_ternary.c', 'test_ternary2')].name
        score = main.main(main.Options(directories=[d]))
        self.assertEqual(score, 0)

    def test_type1(self):
        d = self.tmp_dirs[('test_type.c', 'test_type1')].name
        score = main.main(main.Options(directories=[d]))
        self.assertEqual(score, 0)

    def test_type2(self):
        d = self.tmp_dirs[('test_type.c', 'test_type2')].name
        score = main.main(main.Options(directories=[d]))
        self.assertEqual(score, 0)

    def test_type3(self):
        d = self.tmp_dirs[('test_type.c', 'test_type3')].name
        score = main.main(main.Options(directories=[d]))
        self.assertEqual(score, 0)

if __name__ == '__main__':
    unittest.main()
