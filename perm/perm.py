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

    def evaluate(self, seed: int) -> str:
        next_seed, my_seed = divmod(seed, self.perm_count)
        ret = self._evaluate_self(my_seed)
        if self.next_perm:
            ret += self.next_perm.evaluate(next_seed)
        else:
            assert next_seed == 0, "seed must be in [0, prod(counts))"
        return ret

    def _evaluate_self(self, seed: int) -> str:
        return ''

    def get_counts(self) -> int:
        ret = self.perm_count
        if self.next_perm:
            ret *= self.next_perm.get_counts()
        return ret

    def is_random(self) -> bool:
        return self.next_perm is not None and self.next_perm.is_random()

def eval_all(seed: int, perms: List[Perm]) -> List[str]:
    ret = []
    for p in perms:
        seed, sub_seed = divmod(seed, p.perm_count)
        ret.append(p.evaluate(sub_seed))
    assert seed == 0, "seed must be in [0, prod(counts))"
    return ret

def count_all(perms: List[Perm]) -> int:
    res = 1
    for p in perms:
        res *= p.perm_count
    return res

def eval_either(seed: int, perms: List[Perm]) -> str:
    for p in perms:
        if seed < p.perm_count:
            return p.evaluate(seed)
        seed -= p.perm_count
    assert False, "seed must be in [0, sum(counts))"

def count_either(perms: List[Perm]) -> int:
    return sum(p.perm_count for p in perms)

class TextPerm(Perm):
    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text

    def _evaluate_self(self, seed: int) -> str:
        return self.text

class RandomizerPerm(Perm):
    def __init__(self, inner: Perm) -> None:
        super().__init__()
        self.inner = inner

    def _evaluate_self(self, seed: int) -> str:
        text = self.inner.evaluate(seed)
        return "\n".join(["",
            "#pragma randomizer_start",
            text,
            "#pragma randomizer_end",
            ""])

    def is_random(self) -> bool:
        return True

class GeneralPerm(Perm):
    def __init__(self, candidates: List[Perm]) -> None:
        super().__init__()
        self.perm_count = count_either(candidates)
        self.candidates = candidates

    def _evaluate_self(self, seed: int) -> str:
        return eval_either(seed, self.candidates)

class TernaryPerm(Perm):
    def __init__(self, pre: Perm, cond: Perm, iftrue: Perm, iffalse: Perm) -> None:
        super().__init__()
        self.sub_parts = [pre, cond, iftrue, iffalse]
        self.perm_count = 2 * count_all(self.sub_parts)

    def _evaluate_self(self, seed: int) -> str:
        sub_seed, variation = divmod(seed, 2)
        pre, cond, iftrue, iffalse = eval_all(sub_seed, self.sub_parts)
        if variation > 0:
            return f'{pre}({cond} ? {iftrue} : {iffalse});'
        else:
            return f'if ({cond})\n {pre}{iftrue};\n else\n {pre}{iffalse};'

class TypecastPerm(Perm):
    def __init__(self, types: List[Perm]) -> None:
        super().__init__()
        self.perm_count = count_either(types)
        self.types = types

    def _evaluate_self(self, seed: int) -> str:
        t = eval_either(seed, self.types)
        if not t.strip():
            return ''
        else:
            return f'({t})'
