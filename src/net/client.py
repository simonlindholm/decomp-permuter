from dataclasses import dataclass
import json
from multiprocessing import Queue
import re
import socket
import struct
import threading
from typing import List, Optional, Tuple, TypeVar
import zlib

from ..candidate import CandidateResult
from ..permuter import (
    EvalError,
    EvalResult,
    Feedback,
    FeedbackItem,
    Finished,
    Message,
    NeedMoreWork,
    Permuter,
    Task,
    WorkDone,
)
from ..profiler import Profiler
from .core import (
    Port,
    SocketPort,
    exception_to_string,
    json_array,
    json_prop,
)


def _profiler_from_json(obj: dict) -> Profiler:
    ret = Profiler()
    for key in obj:
        assert isinstance(key, str), "json properties are strings"
        stat = Profiler.StatType[key]
        time = json_prop(obj, key, float)
        ret.add_stat(stat, time)
    return ret


def _result_from_json(obj: dict, source: Optional[str]) -> EvalResult:
    if "error" in obj:
        return EvalError(exc_str=json_prop(obj, "error", str), seed=None)

    profiler = _profiler_from_json(json_prop(obj, "profiler", dict))
    return CandidateResult(
        score=json_prop(obj, "score", int),
        hash=json_prop(obj, "hash", str),
        source=source,
        profiler=profiler,
    )


def _make_script_portable(source: str) -> str:
    """Parse a shell script and get rid of the machine-specific parts that
    import.py introduces. The resulting script must be run in an environment
    that has the right binaries in its $PATH, and with a current working
    directory similar to where import.py found its target's make root."""
    lines = []
    for line in source.split("\n"):
        if re.match("cd '?/", line):
            # Skip cd's to absolute directory paths. Note that shlex quotes
            # its argument with ' if it contains spaces/single quotes.
            continue
        if re.match("'?/", line):
            quote = "'" if line[0] == "'" else ""
            ind = line.find(quote + " ")
            if ind == -1:
                ind = len(line)
            else:
                ind += len(quote)
            lastind = line.rfind("/", 0, ind)
            assert lastind != -1
            # Emit a call to "which" as the first part, to ensure the called
            # binary still sees an absolute path. qemu-irix requires this,
            # for some reason.
            line = "$(which " + quote + line[lastind + 1 : ind] + ")" + line[ind:]
        lines.append(line)
    return "\n".join(lines)


class PortablePermuter:
    def __init__(self, permuter: Permuter) -> None:
        self.fn_name = permuter.fn_name
        self.filename = permuter.source_file
        self.keep_prob = permuter.keep_prob
        self.stack_differences = permuter.scorer.stack_differences
        self.compressed_source = zlib.compress(permuter.source.encode("utf-8"))
        self.base_score = permuter.base_score
        self.base_hash = permuter.base_hash

        with open(permuter.scorer.target_o, "rb") as f:
            self.compressed_target_o_bin = zlib.compress(f.read())

        with open(permuter.compiler.compile_cmd, "r") as f2:
            self.compile_script = _make_script_portable(f2.read())


class Connection:
    _port: SocketPort
    _permuter: PortablePermuter
    _perm_index: int
    _task_queue: "Queue[Task]"
    _feedback_queue: "Queue[Feedback]"

    def __init__(
        self,
        port: SocketPort,
        permuter: PortablePermuter,
        perm_index: int,
        task_queue: "Queue[Task]",
        feedback_queue: "Queue[Feedback]",
    ) -> None:
        self._port = port
        self._permuter = permuter
        self._perm_index = perm_index
        self._task_queue = task_queue
        self._feedback_queue = feedback_queue

    def _send_permuter(self) -> None:
        permuter = self._permuter
        obj = {
            "score": permuter.base_score,
            "hash": permuter.base_hash,
            "fn_name": permuter.fn_name,
            "filename": permuter.filename,
            "keep_prob": permuter.keep_prob,
            "stack_differences": permuter.stack_differences,
            "compile_script": permuter.compile_script,
        }
        self._port.send_json(obj)
        self._port.send(permuter.compressed_source)
        self._port.send(permuter.compressed_target_o_bin)

    def _feedback(self, feedback: FeedbackItem, server_nick: Optional[str]) -> None:
        self._feedback_queue.put((feedback, self._perm_index, server_nick))

    def _need_work(self) -> None:
        self._feedback_queue.put((NeedMoreWork(), self._perm_index, None))

    def _receive_one(self) -> bool:
        """Receive a result/progress message and send it on. Returns true if
        more work should be requested."""
        msg = self._port.receive_json()
        msg_type = json_prop(msg, "type", str)
        if msg_type == "need_work":
            return True

        server_nick = json_prop(msg, "server", str)
        if msg_type == "init_done":
            base_hash = json_prop(msg, "hash", str)
            my_base_hash = self._permuter.base_hash
            text = "connected"
            if base_hash != my_base_hash:
                text += " (note: mismatching hash)"
            self._feedback(Message(text), server_nick)
            return True

        if msg_type == "init_failed":
            text = "failed to initialize: " + json_prop(msg, "reason", str)
            self._feedback(Message(text), server_nick)
            return False

        if msg_type == "disconnect":
            self._feedback(Message("disconnected"), server_nick)
            return False

        if msg_type == "result":
            source: Optional[str] = None
            if msg.get("has_source") == True:
                # Source is sent separately, compressed, since it can be
                # large (hundreds of kilobytes is not uncommon).
                compressed_source = self._port.receive()
                try:
                    source = zlib.decompress(compressed_source).decode("utf-8")
                except Exception as e:
                    text = "failed to decompress: " + exception_to_string(e)
                    self._feedback(Message(text), server_nick)
                    return True
            try:
                result = _result_from_json(msg, source)
                self._feedback(WorkDone(self._perm_index, result), server_nick)
            except Exception as e:
                text = "failed to parse result message: " + exception_to_string(e)
                self._feedback(Message(text), server_nick)
            return True

        raise ValueError(f"Invalid message type {msg_type}")

    def run(self) -> None:
        finish_reason: Optional[str] = None
        try:
            self._send_permuter()
            self._port.receive_json()
            msg = self._port.receive_json()

            finished = False

            # Main loop: send messages from the queue on to the server, and
            # vice versa. Currently we are being lazy and alternate between
            # sending and receiving; this is nicely simple and keeps us on a
            # single thread, however it could cause deadlocks if the server
            # receiver stops reading because we aren't reading fast enough.
            while True:
                if not self._receive_one():
                    continue
                self._need_work()

                # Read a task and send it on, unless there are no more tasks.
                if not finished:
                    task = self._task_queue.get()
                    if isinstance(task, Finished):
                        # We don't have a way of indicating to the server that
                        # all is done: the server currently doesn't track
                        # outstanding work so it doesn't know when to close
                        # the connection. (Even with this fixed we'll have the
                        # problem that servers may disconnect, losing work, so
                        # the task never truly finishes. But it might work well
                        # enough in practice.)
                        finished = True
                    else:
                        work = {
                            "type": "work",
                            "seed": task[1],
                        }
                        self._port.send_json(work)

        except EOFError:
            finish_reason = f"disconnected"

        except Exception as e:
            errmsg = exception_to_string(e)
            finish_reason = f"error: {errmsg}"

        finally:
            self._feedback(Finished(reason=finish_reason), None)
            self._port.shutdown()
            self._port.close()


def start_client(
    port: SocketPort,
    permuter: Permuter,
    perm_index: int,
    feedback_queue: "Queue[Feedback]",
    priority: float,
) -> "Tuple[threading.Thread, Queue[Task], Tuple[int, float]]":
    port.send_json(
        {
            "method": "connect_client",
            "priority": priority,
        }
    )
    obj = port.receive_json()
    if "error" in obj:
        err = json_prop(obj, "error", str)
        # TODO use another exception type
        raise Exception(f"Failed to connect: {err}")
    num_servers = json_prop(obj, "servers", int)
    num_cores = json_prop(obj, "cores", float)
    portable_permuter = PortablePermuter(permuter)
    task_queue: "Queue[Task]" = Queue()

    conn = Connection(
        port,
        portable_permuter,
        perm_index,
        task_queue,
        feedback_queue,
    )

    thread = threading.Thread(target=conn.run)
    thread.daemon = True
    thread.start()

    stats = (num_servers, num_cores)

    return thread, task_queue, stats
