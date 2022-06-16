import os
import toml
from typing import NoReturn, Mapping, Any, Optional


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


def load_weights_from_file() -> Mapping[str, Any]:
    with open("default_weights.toml") as f:
        return toml.load(f)


def load_settings_from_file(dir: str) -> Optional[Mapping[str, Any]]:
    if os.path.exists(os.path.join(dir, "settings.toml")):
        with open(os.path.join(dir, "settings.toml")) as f:
            return toml.load(f)
    else:
        return None
