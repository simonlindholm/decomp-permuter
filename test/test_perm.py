import unittest
import main
import os.path as path
import os
import tempfile
from strip_other_fns import strip_other_fns
import shutil
from compiler import Compiler
from pathlib import Path

c_files_list = [
    ['test1.c', 'test_general'],
    ['test1.c', 'test_general_3'],
    ['test1.c', 'test_general_multiple'],
]

class TestStringMethods(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = Compiler('test/compile.sh')
        cls.tmp_dirs = {}
        for test_c, test_fn in c_files_list:
            d = tempfile.TemporaryDirectory()
            file_actual = path.join(d.name, "actual.c")
            strip_other_fns(path.join('test', test_c), test_fn, file_actual, True, '-DACTUAL')
            strip_other_fns(path.join('test', test_c), test_fn, path.join(d.name, "base.c"), True, '-UACTUAL')

            actual_source = Path(file_actual).read_text()
            target_o = compiler.compile(actual_source)
            shutil.copy2(target_o, path.join(d.name, "target.o"))
            os.remove(target_o)

            shutil.copy2("test/compile.sh", d.name)
            cls.tmp_dirs[(test_c, test_fn)] = d
            
    @classmethod
    def tearDownClass(cls):
        for _, d in cls.tmp_dirs:
            del d

    def test_general(self):
        d = self.tmp_dirs[('test1.c', 'test_general')].name
        scores = main.main([d], False)
        self.assertEqual(scores[0], 0)


    def test_general_3(self):
        d = self.tmp_dirs[('test1.c', 'test_general_3')].name
        scores = main.main([d], False)
        self.assertEqual(scores[0], 0)

    def test_general_multiple(self):
        d = self.tmp_dirs[('test1.c', 'test_general_multiple')].name
        scores = main.main([d], False)
        self.assertEqual(scores[0], 0)

if __name__ == '__main__':
    unittest.main()