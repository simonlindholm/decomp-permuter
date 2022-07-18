import os
import toml
from pathlib import Path
import typing
from typing import List, Mapping, NoReturn, Optional, Type, TypeVar
from .error import CandidateConstructionFailure

T = TypeVar("T")


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


def merge_randomization_weights(
    base: Mapping[str, float], overrides: Mapping[str, float]
) -> Mapping[str, float]:
    return {key: overrides.get(key, weight) for key, weight in base.items()}


def get_default_randomization_weights(compiler_type: str) -> Mapping[str, float]:
    default_weights_file = Path(__file__).parent.parent / "default_weights.toml"
    with open(default_weights_file) as f:
        obj: Mapping[str, object] = toml.load(f)

        base_weights = json_dict(json_prop(obj, "base", dict, {}), float)

        if compiler_type not in obj:
            raise CandidateConstructionFailure(
                f"Unable to find compiler type {compiler_type} in default_weights.toml"
            )
        compiler_weights = json_dict(json_prop(obj, compiler_type, dict), float)

        return merge_randomization_weights(base_weights, compiler_weights)


def get_settings(dir: str) -> Mapping[str, object]:
    try:
        with open(os.path.join(dir, "settings.toml")) as f:
            return toml.load(f)
    except FileNotFoundError:
        return {}


def _json_as_type(what: str, value: object, t: Type[T]) -> T:
    if isinstance(value, t):
        return value
    if t is float and isinstance(value, int):
        return typing.cast(T, float(value))
    raise ValueError(f"{what} must have type {t.__name__}; got {type(value).__name__}")


def json_prop(
    obj: Mapping[str, object], prop: str, t: Type[T], default: Optional[T] = None
) -> T:
    value = obj.get(prop)
    if isinstance(value, t):
        # Fast path
        return value
    if value is None and prop not in obj:
        if default is not None:
            return default
        raise ValueError(f"Member {prop} does not exist")
    return _json_as_type("Member " + prop, value, t)


def json_array(obj: list, t: Type[T]) -> List[T]:
    ret = []
    for elem in obj:
        ret.append(_json_as_type("Array elements", elem, t))
    return ret


def json_dict(obj: dict, t: Type[T]) -> Mapping[str, T]:
    ret = {}
    for key, value in obj.items():
        assert isinstance(key, str), "JSON/TOML can only have string keys"
        ret[key] = _json_as_type("Dict entries", value, t)
    return ret
