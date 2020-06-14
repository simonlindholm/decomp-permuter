from dataclasses import dataclass
import json
import multiprocessing
import socket
import struct
import threading
from typing import List, Tuple

from nacl.public import Box, PrivateKey
from nacl.signing import SigningKey, VerifyKey

from ..permuter import Feedback, Finished, Task
from .common import Config, PROTOCOL_VERSION, Port, RemoteServer


@dataclass
class ServerProps:
    min_priority: float
    num_cpus: float


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
