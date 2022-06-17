import os
import toml
from typing import NoReturn, Mapping, Optional, Dict


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


def get_default_randomization_weights(compiler_type: str) -> Mapping[str, float]:
    weights: Dict[str, float] = {}
    with open("default_weights.toml") as f:
        all_weights: Mapping[str, object] = toml.load(f)

        base_weights = all_weights.get("base", {})
        assert isinstance(base_weights, Mapping)
        compiler_weights = all_weights.get(compiler_type, {})
        assert isinstance(compiler_weights, Mapping)

        for key, weight in base_weights.items():
            if key in compiler_weights:
                weight = compiler_weights[key]
            assert isinstance(weight, (int, float))
            weights[key] = float(weight)

        return weights


def get_settings(dir: str) -> Mapping[str, object]:
    try:
        with open(os.path.join(dir, "settings.toml")) as f:
            return toml.load(f)
    except FileNotFoundError:
        return {}
