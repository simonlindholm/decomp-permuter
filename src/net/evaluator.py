"""This file runs as a free-standing program within a sandbox, and processes
permutation requests. It communicates with the outside world on stdin/stdout."""
import base64
import os
import struct
import sys
from tempfile import mkstemp
from typing import BinaryIO

from nacl.secret import SecretBox

from ..permuter import Permuter
from ..scorer import Scorer
from ..compiler import Compiler
from .common import FilePort, Port, file_read_fixed, json_prop


def _setup_port() -> Port:
    """Set up communication with the outside world."""
    secret = base64.b64decode(os.environ["SECRET"])
    port = FilePort(
        sys.stdin.buffer, sys.stdout.buffer, SecretBox(secret), is_client=False
    )

    # Since we use sys.stdout for our own purposes, redirect it to stdout to
    # make print() debugging work.
    sys.stdout = sys.stderr

    # Follow the controlling process's sanity check protocol.
    magic = port.receive()
    port.send(magic)

    return port


def _receive_permuter(obj: dict, port: Port) -> Permuter:
    fn_name = json_prop(obj, "fn_name", str)
    filename = json_prop(obj, "filename", str)
    keep_prob = json_prop(obj, "keep_prob", float)
    stack_differences = json_prop(obj, "stack_differences", bool)
    compile_script = json_prop(obj, "compile_script", str)

    source = port.receive().decode("utf-8")
    target_o_bin = port.receive()

    fd, path = mkstemp(suffix=".o", prefix="permuter", text=False)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(target_o_bin)
        scorer = Scorer(target_o=path, stack_differences=stack_differences)
    finally:
        os.unlink(path)

    # TODO
    compiler = Compiler(compile_cmd="TODO", show_errors=False,)

    return Permuter(
        dir="unused",
        fn_name=fn_name,
        compiler=compiler,
        scorer=scorer,
        source_file=filename,
        source=source,
        force_rng_seed=None,
        keep_prob=keep_prob,
        need_all_sources=False,
    )


def main() -> None:
    port = _setup_port()

    while True:
        item = port.receive_json()
        tp = json_prop(item, "type", str)
        if tp == "add":
            perm = _receive_permuter(item, port)
        elif tp == "remove":
            pass
        elif tp == "work":
            pass
        else:
            raise Exception(f"Invalid work type {tp}")


if __name__ == "__main__":
    main()
