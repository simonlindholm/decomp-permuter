from typing import List
import math

class Perm:
    """A Perm subclass generates different variations of a part of the source
    code. Its evaluate method will be called with a seed between 0 and
    perm_count-1, and it should return a unique string for each.

    A Perm is allowed to return different strings for the same seed, but if so,
    if should override is_random to return True. This will cause permutation
    to happen in an infinite loop, rather than stop after the last permutation
    has been tested."""

    def __init__(self) -> None:
        self.perm_count = 1
        self.children: List[Perm] = []

    def evaluate(self, seed: int) -> str:
        return ''

    def is_random(self) -> bool:
        return any(p.is_random() for p in self.children)

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

    def evaluate(self, seed: int) -> str:
        return self.text

class CombinePerm(Perm):
    def __init__(self, parts: List[Perm]) -> None:
        super().__init__()
        self.children = parts
        self.perm_count = count_all(parts)

    def evaluate(self, seed: int) -> str:
        texts = eval_all(seed, self.children)
        return ''.join(texts)

class RandomizerPerm(Perm):
    def __init__(self, inner: Perm) -> None:
        super().__init__()
        self.inner = inner

    def evaluate(self, seed: int) -> str:
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
        self.children = candidates

    def evaluate(self, seed: int) -> str:
        return eval_either(seed, self.children)

class TernaryPerm(Perm):
    def __init__(self, pre: Perm, cond: Perm, iftrue: Perm, iffalse: Perm) -> None:
        super().__init__()
        self.children = [pre, cond, iftrue, iffalse]
        self.perm_count = 2 * count_all(self.children)

    def evaluate(self, seed: int) -> str:
        sub_seed, variation = divmod(seed, 2)
        pre, cond, iftrue, iffalse = eval_all(sub_seed, self.children)
        if variation > 0:
            return f'{pre}({cond} ? {iftrue} : {iffalse});'
        else:
            return f'if ({cond})\n {pre}{iftrue};\n else\n {pre}{iffalse};'

class TypecastPerm(Perm):
    def __init__(self, types: List[Perm]) -> None:
        super().__init__()
        self.perm_count = count_either(types)
        self.children = types

    def evaluate(self, seed: int) -> str:
        t = eval_either(seed, self.children)
        if not t.strip():
            return ''
        else:
            return f'({t})'
