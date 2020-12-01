from typing import Callable, Dict, List, Tuple
import re

from .perm import (
    CombinePerm,
    CondNezPerm,
    GeneralPerm,
    IgnorePerm,
    IntPerm,
    LineSwapPerm,
    OncePerm,
    Perm,
    RandomizerPerm,
    RootPerm,
    TextPerm,
    TernaryPerm,
    TypecastPerm,
    VarPerm,
)


def split_by_comma(text: str) -> List[str]:
    level = 0
    current = ""
    args: List[str] = []
    for c in text:
        if c == "," and level == 0:
            args.append(current)
            current = ""
        else:
            if c == "(":
                level += 1
            elif c == ")":
                level -= 1
                assert level >= 0, "Bad nesting"
            current += c
    assert level == 0, "Mismatched parentheses"
    args.append(current)
    return args


def split_args(text: str) -> List[Perm]:
    perm_args = [rec_perm_gen(arg) for arg in split_by_comma(text)]
    return perm_args


def split_args_newline(text: str) -> List[Perm]:
    return [rec_perm_gen(line) for line in text.split("\n") if line.strip()]


def split_args_text(text: str) -> List[str]:
    perm_list = split_args(text)
    res: List[str] = []
    for perm in perm_list:
        assert isinstance(perm, TextPerm)
        res.append(perm.text)
    return res


def make_once_perm(text: str) -> OncePerm:
    args = split_by_comma(text)
    if len(args) not in [1, 2]:
        raise Exception("PERM_ONCE takes 1 or 2 arguments")
    key = args[0]
    value = rec_perm_gen(args[-1])
    return OncePerm(key, value)


def make_var_perm(text: str) -> VarPerm:
    args = split_by_comma(text)
    if len(args) not in [1, 2]:
        raise Exception("PERM_VAR takes 1 or 2 arguments")
    var_name = args[0]
    value = rec_perm_gen(args[1]) if len(args) == 2 else None
    return VarPerm(var_name, value)


PERM_FACTORIES: Dict[str, Callable[[str], Perm]] = {
    "PERM_GENERAL": lambda text: GeneralPerm(split_args(text)),
    "PERM_ONCE": lambda text: make_once_perm(text),
    "PERM_RANDOMIZE": lambda text: RandomizerPerm(rec_perm_gen(text)),
    "PERM_TERNARY": lambda text: TernaryPerm(*split_args(text)),
    "PERM_TYPECAST": lambda text: TypecastPerm(split_args(text)),
    "PERM_VAR": lambda text: make_var_perm(text),
    "PERM_CONDNEZ": lambda text: CondNezPerm(rec_perm_gen(text)),
    "PERM_LINESWAP": lambda text: LineSwapPerm(split_args_newline(text)),
    "PERM_INT": lambda text: IntPerm(*map(int, split_args_text(text))),
    "PERM_IGNORE": lambda text: IgnorePerm(rec_perm_gen(text)),
}


def consume_arg_parens(text: str) -> Tuple[str, str]:
    level = 0
    for i, c in enumerate(text):
        if c == "(":
            level += 1
        elif c == ")":
            level -= 1
            if level == -1:
                return text[:i], text[i + 1 :]
    raise Exception("Failed to find closing parenthesis when parsing PERM macro")


def rec_perm_gen(text: str) -> Perm:
    remain = text
    macro_search = r"(PERM_.+?)\("

    perms: List[Perm] = []
    while len(remain) > 0:
        match = re.search(macro_search, remain)

        # No match found; return remaining
        if match is None:
            text_perm = TextPerm(remain)
            perms.append(text_perm)
            break

        # Get perm type and args
        perm_type = match.group(1)
        if perm_type not in PERM_FACTORIES:
            raise Exception("Unrecognized PERM macro: " + perm_type)
        between = remain[: match.start()]
        args, remain = consume_arg_parens(remain[match.end() :])

        # Create text perm
        perms.append(TextPerm(between))

        # Create new perm
        perms.append(PERM_FACTORIES[perm_type](args))

    if len(perms) == 1:
        return perms[0]
    return CombinePerm(perms)


def perm_gen(text: str) -> Perm:
    ret = rec_perm_gen(text)
    if isinstance(ret, TextPerm):
        ret = RandomizerPerm(ret)
        print("No perm macros found. Defaulting to randomization")
    return RootPerm(ret)
