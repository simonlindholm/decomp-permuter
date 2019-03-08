from typing import List, Optional
import math

class Perm:
    """A Perm subclass generates different variations of a part of the source
    code. Its _evaluate_self method will be called with a seed between 0 and
    perm_count-1, and it should return a unique string for each.

    A Perm is allowed to return different strings for the same seed, but if so,
    if should override is_random to return True. This will cause permutation
    to happen in an infinite loop, rather than stop after the last permutation
    has been tested."""

    def __init__(self) -> None:
        self.perm_count = 1
        self.next_perm = None

    def evaluate(self, seeds: List[int]) -> str:
        ret = self._evaluate_self(seeds[0])
        if self.next_perm:
            ret += self.next_perm.evaluate(seeds[1:])
        return ret

    def _evaluate_self(self, seed: int) -> str:
        return ''

    def get_counts(self) -> List[int]:
        ret = [self.perm_count]
        if self.next_perm:
            ret += self.next_perm.get_counts()
        return ret

    def is_random(self) -> bool:
        return self.next_perm is not None and self.next_perm.is_random()

class TextPerm(Perm):
    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text

    def _evaluate_self(self, seed: int) -> str:
        return self.text

class RandomizerPerm(Perm):
    def _pragmate_text(self, text: str) -> str:
        return ("\n"
        + "#pragma randomizer_start\n"
        + text + "\n"
        + "#pragma randomizer_end\n")

    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = self._pragmate_text(text)

    def _evaluate_self(self, seed: int) -> str:
        return self.text

    def is_random(self) -> bool:
        return True

class GeneralPerm(Perm):
    def __init__(self, candidates: List[str]) -> None:
        super().__init__()
        self.perm_count = len(candidates)
        self.candidates = candidates

    def _evaluate_self(self, seed: int) -> str:
        return self.candidates[seed]
        
class TernaryPerm(Perm):
    def __init__(self, pre: str, cond: str, iftrue: str, iffalse: str) -> None:
        super().__init__()
        self.perm_count = 2 
        self.pre = pre
        self.cond = cond
        self.iftrue = iftrue
        self.iffalse = iffalse

    def _evaluate_self(self, seed: int) -> str:
        if seed > 0:
            return f'{self.pre}({self.cond} ? {self.iftrue} : {self.iffalse});'
        else:
            return f'if ({self.cond})\n {self.pre}{self.iftrue};\n else\n {self.pre}{self.iffalse};'

class TypecastPerm(Perm):
    def __init__(self, types: List[str]) -> None:
        super().__init__()
        self.perm_count = len(types) 
        self.types = types

    def _evaluate_self(self, seed: int) -> str:
        t = self.types[seed]
        if t == '' or t.isspace():
            return ''
        else:
            return f'({t})'
