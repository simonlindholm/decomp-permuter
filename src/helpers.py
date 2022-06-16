import os
import toml
from typing import NoReturn, Mapping, Any, Optional, Dict


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


def load_weights_from_file(compiler_type: str) -> Mapping[str, float]:
    weights: Dict[str, float] = {}
    with open("default_weights.toml") as f:
        all_weights = toml.load(f)
        base_weights = all_weights["base"]
        compiler_weights = all_weights[compiler_type]
        for randomization_type, weight in base_weights.items():
            if randomization_type in compiler_weights:
                weight = compiler_weights[randomization_type]
            weights[randomization_type] = weight
        return weights


def load_settings_from_file(dir: str) -> Mapping[str, object]:
    try:
        with open(os.path.join(dir, "settings.toml")) as f:
            return toml.load(f)
    except FileNotFoundError:
        return {}
