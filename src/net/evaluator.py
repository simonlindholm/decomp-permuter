"""This file runs as a free-standing program within a sandbox, and processes
permutation requests. It communicates with the outside world on stdin/stdout."""
import base64
from dataclasses import dataclass
from multiprocessing import Process, Queue
import os
import queue
import struct
import sys
from tempfile import mkstemp
import threading
import traceback
from typing import BinaryIO, Counter, Dict, List, Optional, Set, Union
import zlib

from nacl.secret import SecretBox

from ..candidate import CandidateResult
from ..compiler import Compiler
from ..error import CandidateConstructionFailure
from ..permuter import EvalError, EvalResult, Permuter
from ..profiler import Profiler
from ..scorer import Scorer
from .common import (
    FilePort,
    Port,
    file_read_fixed,
    json_prop,
    static_assert_unreachable,
)


@dataclass
class PermuterData:
    perm_id: str
    fn_name: str
    filename: str
    keep_prob: float
    stack_differences: bool
    compile_script: str
    source: str
    target_o_bin: bytes


def _setup_port(secret: bytes) -> Port:
    """Set up communication with the outside world."""
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


def _create_permuter(data: PermuterData) -> Permuter:
    fd, path = mkstemp(suffix=".o", prefix="permuter", text=False)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data.target_o_bin)
        scorer = Scorer(target_o=path, stack_differences=data.stack_differences)
    finally:
        os.unlink(path)

    fd, path = mkstemp(suffix=".sh", prefix="permuter", text=True)
    try:
        os.chmod(fd, 0o755)
        with os.fdopen(fd, "w") as f:
            f.write(data.compile_script)
        compiler = Compiler(compile_cmd=path, show_errors=False,)

        return Permuter(
            dir="unused",
            fn_name=data.fn_name,
            compiler=compiler,
            scorer=scorer,
            source_file=data.filename,
            source=data.source,
            force_seed=None,
            force_rng_seed=None,
            keep_prob=data.keep_prob,
            need_all_sources=False,
        )
    except:
        os.unlink(path)
        raise


def _remove_permuter(perm: Permuter) -> None:
    os.unlink(perm.compiler.compile_cmd)


def _send_result(perm_id: str, res: EvalResult, port: Port) -> None:
    if isinstance(res, EvalError):
        port.send_json(
            {"type": "result", "id": perm_id, "error": res.exc_str,}
        )
        return

    compressed_source = getattr(res, "compressed_source")
    port.send_json(
        {
            "type": "result",
            "id": perm_id,
            "score": res.score,
            "hash": res.hash,
            "has_source": compressed_source is not None,
            "profiler": {
                st.name: res.profiler.time_stats[st] for st in Profiler.StatType
            },
        }
    )

    if compressed_source is not None:
        port.send(compressed_source)


@dataclass
class AddPermuter:
    perm_id: str
    data: PermuterData


@dataclass
class AddPermuterLocal:
    perm_id: str
    permuter: Permuter


@dataclass
class RemovePermuter:
    perm_id: str


@dataclass
class WorkDone:
    perm_id: str
    result: EvalResult


@dataclass
class Work:
    perm_id: str
    seed: int


LocalWork = Union[AddPermuterLocal, RemovePermuter]
Task = Union[AddPermuter, RemovePermuter, Work, WorkDone]


def multiprocess_worker(
    worker_queue: "Queue[Work]",
    local_worker_queue: "Queue[LocalWork]",
    task_queue: "Queue[Task]",
) -> None:
    permuters: Dict[str, Permuter] = {}

    while True:
        work = worker_queue.get()
        while True:
            try:
                task = local_worker_queue.get_nowait()
            except queue.Empty:
                break
            if isinstance(task, AddPermuterLocal):
                permuters[task.perm_id] = task.permuter
            elif isinstance(task, RemovePermuter):
                del permuters[task.perm_id]
            else:
                static_assert_unreachable(task)

        permuter = permuters[work.perm_id]
        result = permuter.try_eval_candidate(work.seed)

        # Compress the source within the worker. (Why waste a free
        # multi-threading opportunity?)
        if isinstance(result, CandidateResult):
            compressed_source: Optional[bytes] = None
            if result.source is not None:
                compressed_source = zlib.compress(result.source.encode("utf-8"))
            setattr(result, "compressed_source", compressed_source)
            result.source = None

        task_queue.put(WorkDone(perm_id=work.perm_id, result=result))


def read_loop(task_queue: "Queue[Task]", port: Port) -> None:
    while True:
        item = port.receive_json()
        msg_type = json_prop(item, "type", str)
        if msg_type == "add":
            perm_id = json_prop(item, "id", str)
            fn_name = json_prop(item, "fn_name", str)
            filename = json_prop(item, "filename", str)
            keep_prob = json_prop(item, "keep_prob", float)
            stack_differences = json_prop(item, "stack_differences", bool)
            compile_script = json_prop(item, "compile_script", str)
            source = port.receive().decode("utf-8")
            target_o_bin = port.receive()
            task_queue.put(
                AddPermuter(
                    perm_id=perm_id,
                    data=PermuterData(
                        perm_id=perm_id,
                        fn_name=fn_name,
                        filename=filename,
                        keep_prob=keep_prob,
                        stack_differences=stack_differences,
                        compile_script=compile_script,
                        source=source,
                        target_o_bin=target_o_bin,
                    ),
                )
            )

        elif msg_type == "remove":
            perm_id = json_prop(item, "id", str)
            task_queue.put(RemovePermuter(perm_id=perm_id))

        elif msg_type == "work":
            perm_id = json_prop(item, "id", str)
            seed = json_prop(item, "seed", int)
            task_queue.put(Work(perm_id=perm_id, seed=seed))

        else:
            raise Exception(f"Invalid message type {msg_type}")


def main() -> None:
    num_threads = int(sys.argv[1])
    secret = base64.b64decode(os.environ["SECRET"])
    del os.environ["SECRET"]
    os.environ["PERMUTER_IS_REMOTE"] = "1"

    port = _setup_port(secret)

    worker_queue: "Queue[Work]" = Queue()
    task_queue: "Queue[Task]" = Queue()
    local_queues: "List[Queue[LocalWork]]" = []

    for i in range(num_threads):
        local_queue: "Queue[LocalWork]" = Queue()
        p = Process(
            target=multiprocess_worker, args=(worker_queue, local_queue, task_queue),
        )
        p.start()
        local_queues.append(local_queue)

    reader_thread = threading.Thread(target=read_loop, args=(task_queue, port))
    reader_thread.start()

    remaining_work: Counter[str] = Counter()
    should_remove: Set[str] = set()
    permuters: Dict[str, Permuter] = {}

    def try_remove(perm_id: str) -> None:
        assert perm_id in permuters
        if perm_id not in should_remove or remaining_work[perm_id] != 0:
            return
        del remaining_work[perm_id]
        should_remove.remove(perm_id)
        for queue in local_queues:
            queue.put(RemovePermuter(perm_id=perm_id))
        _remove_permuter(permuters[perm_id])
        del permuters[perm_id]

    while True:
        item = task_queue.get()

        if isinstance(item, AddPermuter):
            assert item.perm_id not in permuters
            success = True

            try:
                # Construct a permuter. This involves a compilation on the main
                # thread, which isn't great but we can live with it for now.
                permuter = _create_permuter(item.data)
                permuters[item.perm_id] = permuter

                # Tell all the workers about the new permuter.
                for queue in local_queues:
                    queue.put(AddPermuterLocal(perm_id=item.perm_id, permuter=permuter))
            except Exception as e:
                # This shouldn't practically happen, since the client compiled
                # the code successfully. Print a message if it does.
                success = False
                if isinstance(e, CandidateConstructionFailure):
                    print(e.message)
                else:
                    traceback.print_exc()

            port.send_json(
                {"type": "init", "id": item.perm_id, "success": success,}
            )

        elif isinstance(item, RemovePermuter):
            # Silently ignore requests to remove permuters that have already
            # been removed, which can occur when AddPermuter fails.
            if item.perm_id in permuters:
                should_remove.add(item.perm_id)
                try_remove(item.perm_id)

        elif isinstance(item, WorkDone):
            remaining_work[item.perm_id] -= 1
            try_remove(item.perm_id)
            _send_result(item.perm_id, item.result, port)

        elif isinstance(item, Work):
            remaining_work[item.perm_id] += 1
            worker_queue.put(item)

        else:
            static_assert_unreachable(item)


if __name__ == "__main__":
    main()
