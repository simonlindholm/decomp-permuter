import os
from typing import NoReturn


def plural(n: int, noun: str) -> str:
    s = "s" if n != 1 else ""
    return f"{n} {noun}{s}"


def exception_to_string(e: object) -> str:
    return str(e) or e.__class__.__name__


def static_assert_unreachable(x: NoReturn) -> NoReturn:
    raise Exception("Unreachable! " + repr(x))


def try_remove(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def trim_source(source: str, fn_name: str) -> str:
    fn_index = source.find(fn_name)
    if fn_index != -1:
        new_index = source.rfind("\n", 0, fn_index)
        if new_index != -1:
            return source[new_index:]
    return source
