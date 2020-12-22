from base64 import b64encode
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import math
import itertools


@dataclass
class PreprocessState:
    once_options: Dict[str, List["Perm"]] = field(
        default_factory=lambda: defaultdict(list)
    )


@dataclass
class EvalState:
    vars: Dict[str, str] = field(default_factory=dict)
    once_choices: Dict[str, "Perm"] = field(default_factory=dict)


class Perm:
    """A Perm subclass generates different variations of a part of the source
    code. Its evaluate method will be called with a seed between 0 and
    perm_count-1, and it should return a unique string for each.

    A Perm is allowed to return different strings for the same seed, but if so,
    if should override is_random to return True. This will cause permutation
    to happen in an infinite loop, rather than stop after the last permutation
    has been tested."""

    perm_count: int
    children: List["Perm"]

    def evaluate(self, seed: int, state: EvalState) -> str:
        return ""

    def preprocess(self, state: PreprocessState) -> None:
        for p in self.children:
            p.preprocess(state)

    def is_random(self) -> bool:
        return any(p.is_random() for p in self.children)


def _eval_all(seed: int, perms: List[Perm], state: EvalState) -> List[str]:
    ret = []
    for p in perms:
        seed, sub_seed = divmod(seed, p.perm_count)
        ret.append(p.evaluate(sub_seed, state))
    assert seed == 0, "seed must be in [0, prod(counts))"
    return ret


def _count_all(perms: List[Perm]) -> int:
    res = 1
    for p in perms:
        res *= p.perm_count
    return res


def _eval_either(seed: int, perms: List[Perm], state: EvalState) -> str:
    for p in perms:
        if seed < p.perm_count:
            return p.evaluate(seed, state)
        seed -= p.perm_count
    assert False, "seed must be in [0, sum(counts))"


def _count_either(perms: List[Perm]) -> int:
    return sum(p.perm_count for p in perms)


class RootPerm(Perm):
    def __init__(self, inner: Perm) -> None:
        self.children = [inner]
        self.perm_count = inner.perm_count
        self.preprocess_state = PreprocessState()
        self.preprocess(self.preprocess_state)
        for key, options in self.preprocess_state.once_options.items():
            if len(options) == 1:
                raise Exception(f"PERM_ONCE({key}) occurs only once, possible error?")
            self.perm_count *= len(options)

    def evaluate(self, seed: int, state: EvalState) -> str:
        for key, options in self.preprocess_state.once_options.items():
            seed, choice = divmod(seed, len(options))
            state.once_choices[key] = options[choice]
        return self.children[0].evaluate(seed, state)


class TextPerm(Perm):
    def __init__(self, text: str) -> None:
        # Comma escape sequence
        text = text.replace("(,)", ",")
        self.text = text
        self.children = []
        self.perm_count = 1

    def evaluate(self, seed: int, state: EvalState) -> str:
        return self.text


class IgnorePerm(Perm):
    def __init__(self, inner: Perm) -> None:
        self.children = [inner]
        self.perm_count = inner.perm_count

    def evaluate(self, seed: int, state: EvalState) -> str:
        text = self.children[0].evaluate(seed, state)
        if not text:
            return ""
        encoded = b64encode(text.encode("utf-8")).decode("ascii")
        return "#pragma _permuter b64literal " + encoded


class PretendPerm(Perm):
    def __init__(self, inner: Perm) -> None:
        self.children = [inner]
        self.perm_count = inner.perm_count

    def evaluate(self, seed: int, state: EvalState) -> str:
        text = self.children[0].evaluate(seed, state)
        return "\n".join(
            [
                "",
                "#pragma _permuter latedefine start",
                text,
                "#pragma _permuter latedefine end",
                "",
            ]
        )


class CombinePerm(Perm):
    def __init__(self, parts: List[Perm]) -> None:
        self.children = parts
        self.perm_count = _count_all(parts)

    def evaluate(self, seed: int, state: EvalState) -> str:
        texts = _eval_all(seed, self.children, state)
        return "".join(texts)


class RandomizerPerm(Perm):
    def __init__(self, inner: Perm) -> None:
        self.children = [inner]
        self.perm_count = inner.perm_count

    def evaluate(self, seed: int, state: EvalState) -> str:
        text = self.children[0].evaluate(seed, state)
        return "\n".join(
            [
                "",
                "#pragma _permuter randomizer start",
                text,
                "#pragma _permuter randomizer end",
                "",
            ]
        )

    def is_random(self) -> bool:
        return True


class GeneralPerm(Perm):
    def __init__(self, candidates: List[Perm]) -> None:
        self.perm_count = _count_either(candidates)
        self.children = candidates

    def evaluate(self, seed: int, state: EvalState) -> str:
        return _eval_either(seed, self.children, state)


class OncePerm(Perm):
    def __init__(self, key: str, inner: Perm) -> None:
        self.key = key
        self.children = [inner]
        self.perm_count = inner.perm_count

    def preprocess(self, state: PreprocessState) -> None:
        state.once_options[self.key].append(self)
        super().preprocess(state)

    def evaluate(self, seed: int, state: EvalState) -> str:
        if state.once_choices[self.key] is self:
            return self.children[0].evaluate(seed, state)
        return ""


class TernaryPerm(Perm):
    def __init__(self, pre: Perm, cond: Perm, iftrue: Perm, iffalse: Perm) -> None:
        self.children = [pre, cond, iftrue, iffalse]
        self.perm_count = 2 * _count_all(self.children)

    def evaluate(self, seed: int, state: EvalState) -> str:
        sub_seed, variation = divmod(seed, 2)
        pre, cond, iftrue, iffalse = _eval_all(sub_seed, self.children, state)
        if variation > 0:
            return f"{pre}({cond} ? {iftrue} : {iffalse});"
        else:
            return f"if ({cond})\n {pre}{iftrue};\n else\n {pre}{iffalse};"


class TypecastPerm(Perm):
    def __init__(self, types: List[Perm]) -> None:
        self.children = types
        self.perm_count = _count_either(types)

    def evaluate(self, seed: int, state: EvalState) -> str:
        t = _eval_either(seed, self.children, state)
        if not t.strip():
            return ""
        else:
            return f"({t})"


class VarPerm(Perm):
    def __init__(self, var_name: Perm, expansion: Optional[Perm]) -> None:
        if expansion:
            self.children = [var_name, expansion]
        else:
            self.children = [var_name]
        self.perm_count = _count_all(self.children)

    def evaluate(self, seed: int, state: EvalState) -> str:
        var_name_perm = self.children[0]
        seed, sub_seed = divmod(seed, var_name_perm.perm_count)
        var_name = var_name_perm.evaluate(sub_seed, state).strip()
        if len(self.children) > 1:
            ret = self.children[1].evaluate(seed, state)
            state.vars[var_name] = ret
            return ""
        else:
            if var_name not in state.vars:
                raise Exception(f"Tried to read undefined PERM_VAR {var_name}")
            return state.vars[var_name]


class CondNezPerm(Perm):
    def __init__(self, perm: Perm) -> None:
        self.children = [perm]
        self.perm_count = 2 * _count_all(self.children)

    def evaluate(self, seed: int, state: EvalState) -> str:
        sub_seed, variation = divmod(seed, 2)
        cond = self.children[0].evaluate(sub_seed, state)
        if variation == 0:
            return f"{cond}"
        else:
            return f"({cond}) != 0"


class LineSwapPerm(Perm):
    def __init__(self, lines: List[Perm]) -> None:
        self.children = lines
        self.own_count = math.factorial(len(lines))
        self.perm_count = self.own_count * _count_all(self.children)

    def evaluate(self, seed: int, state: EvalState) -> str:
        sub_seed, variation = divmod(seed, self.own_count)
        texts = _eval_all(sub_seed, self.children, state)
        output = []
        while texts:
            ind = variation % len(texts)
            variation //= len(texts)
            output.append(texts[ind])
            del texts[ind]
        return "\n".join(output)


class IntPerm(Perm):
    def __init__(self, low: int, high: int) -> None:
        assert low <= high
        self.low = low
        self.children = []
        self.perm_count = high - low + 1

    def evaluate(self, seed: int, state: EvalState) -> str:
        return str(self.low + seed)
