from typing import Callable, Dict, List, Tuple
import re

from perm.perm import (Perm, CombinePerm, GeneralPerm, RandomizerPerm,
        TextPerm, TernaryPerm, TypecastPerm, VarPerm)

perm_create: Dict[str, Callable[[List[Perm]], Perm]] = {
    'PERM_GENERAL':   lambda args: GeneralPerm(args),
    'PERM_RANDOMIZE': lambda args: RandomizerPerm(args[0]),
    'PERM_TERNARY':   lambda args: TernaryPerm(*args),
    'PERM_TYPECAST':  lambda args: TypecastPerm(args),
    'PERM_VAR':       lambda args: VarPerm(args),
}

def get_parenthesis_args(s: str) -> Tuple[List[str], str]:
    level = 0
    current = ''
    remain = ''
    args = []
    for i, c in enumerate(s):
        # Find individual args
        if c == ',' and level == 1:
            args.append(current)
            current = ''
        # Track parenthesis level
        else:
            if c == '(':
                level += 1
                if level == 1: # Ignore first parenthesis
                    continue
            elif c == ')':
                level -= 1
                if level == 0: # Last closing parenthesis; get remaining and finish
                    args.append(current)
                    if i + 1 < len(s):
                        remain = s[i+1:]
                    break
            current += c
    assert level == 0, "Error, no closing parenthesis found"
    return args, remain

def rec_perm_gen(input: str) -> Perm:
    remain = input
    macro_search = r'(PERM_.+?)\('

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
        if not perm_type in perm_create:
            raise Exception('Could not evaluate expression:' + perm_type)
        between = remain[:match.start()]
        args, remain = get_parenthesis_args(remain[match.end() - 1:])

        # Create text perm
        perms.append(TextPerm(between))

        # Create new perm
        perm_args = [rec_perm_gen(arg) for arg in args]
        perms.append(perm_create[perm_type](perm_args))

    if len(perms) == 1:
        return perms[0]
    return CombinePerm(perms)

def perm_gen(input: str) -> Perm:
    ret = rec_perm_gen(input)
    if isinstance(ret, TextPerm):
        ret = RandomizerPerm(ret)
        print("No perm macros found. Defaulting to randomization")
    return ret
