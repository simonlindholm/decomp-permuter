"""This file runs as a free-standing program within a sandbox, and processes
permutation requests. It communicates with the outside world on stdin/stdout."""
import base64
import os
import struct
import sys
from tempfile import mkstemp
import traceback
from typing import BinaryIO, Dict
import zlib

from nacl.secret import SecretBox

from ..error import CandidateConstructionFailure
from ..permuter import EvalError, EvalResult, Permuter
from ..profiler import Profiler
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

    fd, path = mkstemp(suffix=".sh", prefix="permuter", text=True)
    try:
        os.chmod(fd, 0o755)
        with os.fdopen(fd, "w") as f:
            f.write(compile_script)
        compiler = Compiler(compile_cmd=path, show_errors=False,)

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
    except:
        os.unlink(path)
        raise


def _remove_permuter(perm: Permuter) -> None:
    # TODO: deal with multiprocessing
    os.unlink(perm.compiler.compile_cmd)


def _send_result(res: EvalResult, perm: Permuter, port: Port) -> None:
    if isinstance(res, EvalError):
        port.send_json(
            {"type": "result", "error": res.exc_str,}
        )
        return

    send_source = res.source is not None and perm.need_to_send_source(res)
    port.send_json(
        {
            "score": res.score,
            "hash": res.hash,
            "has_source": send_source,
            "profiler": {st: res.profiler.time_stats[st] for st in Profiler.StatType},
        }
    )

    if send_source:
        assert res.source is not None, "checked above"
        port.send(zlib.compress(res.source.encode("utf-8")))


def main() -> None:
    num_threads = int(sys.argv[1])
    port = _setup_port()
    perms: Dict[str, Permuter] = {}

    while True:
        item = port.receive_json()
        msg_type = json_prop(item, "type", str)
        if msg_type == "add":
            perm_id = json_prop(item, "id", str)
            try:
                assert perm_id not in perms, perm_id
                perms[perm_id] = _receive_permuter(item, port)
                success = True
            except Exception as e:
                if isinstance(e, CandidateConstructionFailure):
                    print(e.message)
                else:
                    traceback.print_exc()
                success = False
            port.send_json(
                {"type": "init", "id": perm_id, "success": success,}
            )
        elif msg_type == "remove":
            perm_id = json_prop(item, "id", str)
            _remove_permuter(perms[perm_id])
            del perms[perm_id]
        elif msg_type == "work":
            # TODO: multiprocessing
            perm_id = json_prop(item, "id", str)
            seed = json_prop(item, "seed", int)
            perm = perms[perm_id]
            result = perm.try_eval_candidate(seed)
            _send_result(result, perm, port)
        else:
            raise Exception(f"Invalid message type {msg_type}")


if __name__ == "__main__":
    main()
