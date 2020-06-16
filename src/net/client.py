from dataclasses import dataclass
import json
import multiprocessing
import socket
import struct
import threading
from typing import List, Optional, Tuple, TypeVar
import zlib

from nacl.public import Box, PrivateKey
from nacl.signing import SigningKey, VerifyKey

from ..candidate import CandidateResult
from ..permuter import EvalError, EvalResult, Feedback, Finished, NeedMoreWork, Task
from ..profiler import Profiler
from .common import Config, PROTOCOL_VERSION, Port, RemoteServer, json_prop


@dataclass
class ServerProps:
    min_priority: float
    num_cpus: float


def _profiler_from_json(obj: dict) -> Profiler:
    ret = Profiler()
    for key in obj:
        assert isinstance(key, str), "json properties are strings"
        stat = Profiler.StatType(key)
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


class Connection:
    def __init__(
        self,
        config: Config,
        server: RemoteServer,
        grant: bytes,
        task_queue: "multiprocessing.Queue[Task]",
        feedback_queue: "multiprocessing.Queue[Feedback]",
    ) -> None:
        self._config = config
        self._server = server
        self._grant = grant
        self._task_queue = task_queue
        self._feedback_queue = feedback_queue

    def _setup(self) -> Port:
        """Set up a secure connection with the server."""
        sock = socket.create_connection((self._server.ip, self._server.port))

        # Send over the protocol version, a verification key for our signatures,
        # and an ephemeral encryption key which we are going to use for all
        # communication. The ephemeral key serves double duty in protecting us
        # against replay attacks.
        ephemeral_key = PrivateKey.generate()
        sock.sendall(
            struct.pack(">I", PROTOCOL_VERSION)
            + self._config.signing_key.verify_key.encode()
            + self._config.signing_key.sign(ephemeral_key.public_key.encode())
        )

        box = Box(ephemeral_key, self._server.ver_key.to_curve25519_public_key())
        port = Port(sock, box, is_client=True)

        # To help guard the server against replay attacks, send a server-chosen
        # string as our first message.
        rand = port.receive()
        port.send(rand)

        return port

    def _init(self, port: Port) -> ServerProps:
        """Prove to the server that our request to it is valid, by presenting
        a grant from the auth server. Returns a bunch of server properties."""
        port.send(self._grant)
        obj = json.loads(port.receive())
        return ServerProps(
            min_priority=float(obj["min_priority"]), num_cpus=float(obj["num_cpus"]),
        )

    def run(self) -> None:
        try:
            port = self._setup()
            props = self._init(port)
            while True:
                # Read a task and send it on.
                task = self._task_queue.get()
                if isinstance(task, Finished):
                    break
                work = {
                    "type": "work",
                    "permuter": task[0],
                    "seed": task[1],
                }
                port.send_json(work)

                # Receive a result and send it on.
                msg = port.receive_json()
                msg_type = json_prop(msg, "type", str)
                if msg_type == "need_work":
                    self._feedback_queue.put(NeedMoreWork())
                elif msg_type == "result":
                    permuter_index = json_prop(msg, "permuter", int)
                    source: Optional[str] = None
                    if msg.get("has_source") == True:
                        # Source is sent separately, compressed, since it can be large
                        # (hundreds of kilobytes is not uncommon).
                        compressed_source = port.receive()
                        source = zlib.decompress(compressed_source).decode("utf-8")
                    result = _result_from_json(msg, source)
                    self._feedback_queue.put((permuter_index, result))
                else:
                    raise ValueError(f"Invalid message type {msg_type}")
        finally:
            self._feedback_queue.put(Finished())


def connect_to_servers(
    config: Config,
    servers: List[RemoteServer],
    grant: bytes,
    task_queue: "multiprocessing.Queue[Task]",
    feedback_queue: "multiprocessing.Queue[Feedback]",
) -> List[threading.Thread]:
    threads = []
    for server in servers:
        conn = Connection(config, server, grant, task_queue, feedback_queue)

        thread = threading.Thread(target=conn.run)
        thread.start()

        threads.append(thread)

    return threads
