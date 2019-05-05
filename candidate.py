from typing import List, Dict, Optional, Callable, Optional, Tuple, Iterable
import functools

import attr
import pycparser
import copy

from compiler import Compiler
from randomizer import Randomizer
from scorer import Scorer
from perm.perm import EvalState, Perm
import perm
import ast_util
from pycparser import CParser
from pycparser import c_ast as ca

@attr.s
class Candidate(object):
    '''
    Represents a AST candidate created from a source which can be randomized, 
    reset to its base, compiled, and scored.
    '''
    ast: ca.FileAST = attr.ib()
    seed: Optional[int] = attr.ib(default=None)

    orig_fn: ca.FuncDef = attr.ib(init=False, default=None)
    fn_index: int = attr.ib(init=False, default=0)
    o_file: Optional[str] = attr.ib(init=False, default=None)
    cur_ast: ca.FileAST = attr.ib(init=False, default=None)
    score_value: Optional[int] = attr.ib(init=False, default=None)
    score_hash: Optional[str] = attr.ib(init=False, default=None)
    _cache_source: Optional[str] = attr.ib(init=False, default=None)

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def _cache_start_source(source: str):
        parser = CParser()
        ast = parser.parse(source)
        orig_fn, fn_index = ast_util.find_fn(ast)
        ast_util.normalize_ast(orig_fn, ast)
        return orig_fn, fn_index, ast

    @staticmethod
    def from_source(source: str, cparser: CParser, seed: Optional[int] = None) -> 'Candidate':
        orig_fn, fn_index, ast = Candidate._cache_start_source(source)
        p: Candidate = Candidate(ast=ast, seed=seed)
        p.orig_fn = orig_fn
        p.fn_index = fn_index
        ast_util.normalize_ast(p.orig_fn, ast)
        p.reset_ast()
        return p

    def reset_ast(self) -> None:
        self.ast.ext[self.fn_index] = copy.deepcopy(self.orig_fn)
        self._cache_source = None

    def randomize_ast(self, randomizer: Randomizer) -> None:
        randomizer.random.seed(self.seed)
        randomizer.randomize(self.ast, self.fn_index)
        self._cache_source = None


    def get_source(self) -> str:
        if self._cache_source is None:
            self._cache_source = ast_util.to_c(self.ast)
        return self._cache_source

    def compile(self, compiler: Compiler) -> bool:
        self._remove_o_file()
        source = self.get_source()
        self.o_file = compiler.compile(source)
        return self.o_file is not None

    def score(self, scorer: Scorer) -> None:
        self.score_value, self.score_hash = scorer.score(self.o_file)

    def _remove_o_file(self) -> None:
        if self.o_file is not None:
            try:
                os.remove(self.o_file)
            except:
                pass
                
    def __enter__(self) -> 'Candidate':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._remove_o_file()