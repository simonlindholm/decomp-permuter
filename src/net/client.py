from dataclasses import dataclass
import json
import multiprocessing
import struct
import threading
from typing import List, Tuple

from nacl.public import Box, PrivateKey
from nacl.signing import SigningKey, VerifyKey

from ..permuter import Feedback, Task
from .common import Config, Port, RemoteServer


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

    def _connect(self) -> None:
        pass

    def _setup(self) -> Port:
        ephemeral_key = PrivateKey.generate()
        msg = (
            struct.pack(">I", 1)
            + self._config.signing_key.verify_key.encode()
            + self._config.signing_key.sign(ephemeral_key.public_key.encode())
        )
        # TODO: send 'msg'

        sock = ...
        box = Box(ephemeral_key, self._server.ver_key.to_curve25519_public_key())
        port = Port(sock, box, is_client=True)
        # To help guard the server against replay attacks, send a server-chosen
        # string as part of our first message.
        rand = port.receive()
        port.send(rand + self._grant)
        resp = json.loads(port.receive())
        assert resp["status"] == "ok"

        return port

    def run(self) -> None:
        try:
            self._connect()
            self._port = self._setup()
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
