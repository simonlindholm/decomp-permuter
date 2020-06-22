import abc
import base64
from dataclasses import dataclass
import json
import os
import pathlib
import queue
import socket
import socketserver
import struct
import subprocess
import sys
from tempfile import mkstemp
import threading
import time
import traceback
from typing import BinaryIO, Dict, List, Tuple, Union
import zlib

import docker
from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey
import nacl.utils

from ..permuter import Permuter
from ..scorer import Scorer
from ..compiler import Compiler
from .common import (
    Config,
    PROTOCOL_VERSION,
    Port,
    SocketPort,
    file_read_fixed,
    json_prop,
    socket_read_fixed,
)


@dataclass
class ClientConnection:
    # Unique identifier for the connecting client
    client: bytes

    # Name of the connecting client
    nickname: str

    port: Port


@dataclass
class AddClient:
    handle: object
    permuters: List[Permuter]
    connection: ClientConnection


@dataclass
class RemoveClient:
    handle: object


@dataclass
class WakeUp:
    pass


Activity = Union[AddClient, RemoveClient, WakeUp]


@dataclass
class ServerOptions:
    host: str
    port: int
    num_cpus: float
    max_memory_gb: float
    min_priority: float
    systray: bool


@dataclass
class SharedServerData:
    config: Config
    options: ServerOptions
    queue: "queue.Queue[Activity]"


class ServerHandler(socketserver.BaseRequestHandler):
    def _setup(self, signing_key: SigningKey) -> Tuple[VerifyKey, Port]:
        """Set up a secure (but untrusted) connection with the client."""
        sock: socket.socket = self.request

        # Read and verify protocol version.
        msg = socket_read_fixed(sock, 4)
        version = struct.unpack(">I", msg)[0]
        assert version == PROTOCOL_VERSION

        # Read signing and (ephemeral) encryption keys from the client. We
        # don't know who the client is yet, so we don't fully trust these keys;
        # we'll start doing so when it presents proof signed by the central
        # server that its signature is legit.
        msg = socket_read_fixed(sock, 32 + 96)
        client_ver_key = VerifyKey(msg[:32])
        client_enc_key = PublicKey(client_ver_key.verify(msg[32:]))

        # Create an ephemeral encryption key for ourselves as well. Send it to
        # the client, signed by a key it trusts.
        ephemeral_key = PrivateKey.generate()
        sock.sendall(signing_key.sign(ephemeral_key))

        # Set up encrypted communication channel. Once we receive the first
        # message we'll know that this isn't a replay attack.
        box = Box(ephemeral_key, client_enc_key)
        port = SocketPort(sock, box, is_client=False)

        # Tell the client that this isn't a replay attack.
        port.send(b"")

        return client_ver_key, port

    def _confirm_grant(
        self, port: Port, client_ver_key: VerifyKey, auth_ver_key: VerifyKey
    ) -> str:
        """Check that the client can present proof from the central server that
        its request is valid. (We could also ask the central server itself, but
        this saves some complexity and network traffic.)"""
        msg = port.receive()
        granted_request = auth_ver_key.verify(msg)
        assert granted_request[:32] == client_ver_key
        request = json.loads(granted_request[32:])
        if not isinstance(request, dict):
            raise ValueError("Grant JSON must be a dict")

        # Verify that the client is not just presenting an old grant.
        valid_from = json_prop(request, "valid_from", int)
        valid_until = json_prop(request, "valid_until", int)
        assert valid_from <= time.time() <= valid_until

        # Read client nickname from the server, signed by the client during
        # registration. (Don't let the client spoof this.)
        signed_nickname = base64.b64decode(request["signed_nickname"])
        enc_nickname: bytes = client_ver_key.verify(signed_nickname)
        return enc_nickname.decode("utf-8")

    def _send_init(self, port: Port, options: ServerOptions) -> None:
        # TODO include current load
        props = {
            "min_priority": options.min_priority,
            "num_cpus": options.num_cpus,
        }
        port.send_json(props)

    def _receive_permuters(self, port: Port) -> List[Permuter]:
        msg = port.receive_json()
        permuters = json_prop(msg, "permuters", list)

        permuters = []
        for obj in permuters:
            if not isinstance(obj, dict):
                raise ValueError(f"Permuters must be dictionaries, found {obj}")
            fn_name = json_prop(obj, "fn_name", str)
            filename = json_prop(obj, "filename", str)
            keep_prob = json_prop(obj, "keep_prob", float)
            stack_differences = json_prop(obj, "stack_differences", bool)
            compile_script = json_prop(obj, "compile_script", str)

            source = zlib.decompress(port.receive()).decode("utf-8")
            target_o_bin = port.receive()

            fd, path = mkstemp(suffix=".o", prefix="permuter", text=False)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(target_o_bin)
                scorer = Scorer(target_o=path, stack_differences=stack_differences)
            finally:
                os.unlink(path)

            compiler = Compiler(compile_cmd="TODO", show_errors=False,)

            perm = Permuter(
                dir="TODO",
                fn_name=fn_name,
                compiler=compiler,
                scorer=scorer,
                source_file=filename,
                source=source,
                force_rng_seed=None,
                keep_prob=keep_prob,
                need_all_sources=False,
            )
            permuters.append(perm)

        return permuters

    def handle(self) -> None:
        shared: SharedServerData = getattr(self.server, "shared")
        signing_key = shared.config.signing_key
        client_ver_key, port = self._setup(signing_key)

        auth_ver_key = shared.config.auth_verify_key
        nickname = self._confirm_grant(port, client_ver_key, auth_ver_key)

        permuters = self._receive_permuters(port)

        # Create a key object that uniquely identifies the TCP connection
        handle: object = {}

        shared.queue.put(
            AddClient(
                handle=handle,
                permuters=permuters,
                connection=ClientConnection(
                    client=client_ver_key.encode(), nickname=nickname, port=port,
                ),
            )
        )
        try:
            self._send_init(port, shared.options)
            while True:
                msg = port.receive_json()
                tp = json_prop(msg, "type", str)
                if tp == "finish":
                    break
                elif tp == "work":
                    permuter_index = json_prop(msg, "permuter", int)
                    seed = json_prop(msg, "seed", int)
                    # TODO: put index and seed somewhere
                    shared.queue.put(WakeUp())
                else:
                    raise ValueError(f'Unrecognized message type "{tp}"')
        finally:
            shared.queue.put(RemoveClient(handle=handle))

    def finish(self) -> None:
        pass


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # When restarting the server, rebind the port instead of complaining that
    # "Address already in use". We do authentication as the first step of each
    # connection, so this is fine.
    allow_reuse_address = True

    # When the main program stops, it is fine for us to drop all server threads
    # on the floor.
    daemon_threads = True


class Server:
    _config: Config
    _options: ServerOptions
    _inner_server_port: Port
    _queue: "queue.Queue[Activity]"
    _tcp_server: ThreadedTCPServer
    _state: str

    def __init__(
        self, config: Config, options: ServerOptions, inner_server_port: Port
    ) -> None:
        self._config = config
        self._options = options
        self._inner_server_port = inner_server_port
        self._queue = queue.Queue()
        self._tcp_server = ThreadedTCPServer(
            (options.host, options.port), ServerHandler
        )
        self._state = "notstarted"

        shared = SharedServerData(config=config, options=options, queue=self._queue)
        setattr(self._tcp_server, "shared", shared)

    def _run_loop(self) -> None:
        clients: Dict[int, ClientConnection] = {}
        while True:
            item = self._queue.get()
            if isinstance(item, WakeUp):
                # Do nothing special, this was just a call for us to wake up
                # and schedule work.
                pass
            elif isinstance(item, AddClient):
                client = item.connection
                clients[id(item.handle)] = client
                filenames = ", ".join(p.fn_name for p in item.permuters)
                print(f"[{client.nickname}] connected ({filenames})")
            elif isinstance(item, RemoveClient):
                client = clients[id(item.handle)]
                del clients[id(item.handle)]
                print(f"[{client.nickname}] disconnected")

            # TODO: process work

    def start(self) -> None:
        assert self._state == "notstarted"
        self._state = "started"

        # Start a thread with the TCP server -- that thread will then start one
        # more thread for each request.
        server_thread = threading.Thread(target=self._tcp_server.serve_forever)
        server_thread.start()

        # Start a thread for the main loop.
        main_thread = threading.Thread(target=self._run_loop)
        main_thread.start()

    def stop(self) -> None:
        assert self._state == "started"
        self._state = "finished"
        self._tcp_server.shutdown()


class DockerPort(Port):
    """Port for communicating with Docker. Communication is encrypted for a few
    not-very-good reasons:
    - it allows code reuse
    - it adds error-checking
    - it was fun to implement"""

    _sock: BinaryIO
    _container: docker.models.containers.Container
    _stdout_buffer: bytes

    def __init__(
        self, container: docker.models.containers.Container, secret: bytes
    ) -> None:
        self._container = container
        self._stdout_buffer = b""

        # Set up a socket for reading from stdout/stderr and writing to
        # stdin for the container. The docker package does not seem to
        # expose an API for writing the stdin, but we can do so directly
        # by attaching a socket and poking at internal state. (See
        # https://github.com/docker/docker-py/issues/983.) For stdout/
        # stderr, we use the format described at
        # https://docs.docker.com/engine/api/v1.24/#attach-to-a-container.
        #
        # Hopefully this will keep working for at least a while...
        try:
            self._sock = container.attach_socket(
                params={"stdout": True, "stdin": True, "stderr": True, "stream": True}
            )
            self._sock._writing = True  # type: ignore
        except:
            try:
                container.remove(force=True)
            except Exception:
                pass
            raise

        super().__init__(SecretBox(secret), is_client=True)

    def shutdown(self) -> None:
        try:
            self._sock.close()
            self._container.remove(force=True)
        except Exception as e:
            print("Failed to shut down Docker")
            traceback.print_exc()

    def _read_one(self) -> None:
        header = file_read_fixed(self._sock, 8)
        stream, length = struct.unpack(">BxxxI", header)
        if stream not in [1, 2]:
            raise Exception("Unexpected output from Docker: " + repr(header))
        data = file_read_fixed(self._sock, length)
        if stream == 1:
            self._stdout_buffer += data
        else:
            sys.stderr.buffer.write(b"Docker stderr: " + data)
            sys.stderr.buffer.flush()

    def _receive(self, length: int) -> bytes:
        while len(self._stdout_buffer) < length:
            self._read_one()
        ret = self._stdout_buffer[:length]
        self._stdout_buffer = self._stdout_buffer[length:]
        return ret

    def _send(self, data: bytes) -> None:
        while data:
            written = self._sock.write(data)
            data = data[written:]
        self._sock.flush()


def start_inner_server(docker_image: str, options: ServerOptions) -> DockerPort:
    """Spawn a docker container and set it up to evaluate permutations in,
    returning a handle that we can use to communicate with it.

    We do this for a few reasons:
    - enforcing a known Linux environment, all while the outside server can run
      on e.g. Windows and display a systray
    - enforcing resource limits
    - sandboxing

    Docker does have the downside of requiring root access, so ideally we would
    also have a Docker-less mode, where we leave the sandboxing to some other
    tool, e.g. https://github.com/ioi/isolate/."""
    print("Starting docker...")
    command = ["python3", "-m", "src.net.inner_server"]
    secret = nacl.utils.random(32)
    box = SecretBox(secret)
    enc_secret = base64.b64encode(secret).decode("utf-8")
    src_path = pathlib.Path(__file__).parent.parent.absolute()

    try:
        client = docker.from_env()
        client.info()
    except Exception:
        print(
            "Failed to start docker. Make sure you have docker installed, "
            "and either run the permuter with sudo or add yourself to the "
            '"docker" UNIX group.'
        )
        sys.exit(1)

    container = client.containers.run(
        docker_image,
        command,
        detach=True,
        remove=True,
        stdin_open=True,
        stdout=True,
        environment={"SECRET": enc_secret},
        volumes={src_path: {"bind": "/src", "mode": "ro"}},
        tmpfs={"/tmp": "size=1G"},
        nano_cpus=int(options.num_cpus * 1e9),
        mem_limit=int(options.max_memory_gb * 2 ** 30),
        read_only=True,
        network_disabled=True,
    )

    port = DockerPort(container, secret)

    try:
        # Sanity-check that the Docker container started successfully and can
        # be communicated with.
        magic = b"\0" * 1000
        port.send(magic)
        r = port.receive()
        if r != magic:
            raise Exception("Failed initial sanity check.")
    except:
        port.shutdown()
        raise

    return port
