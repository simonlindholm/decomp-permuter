import abc
import base64
from dataclasses import dataclass, field
from enum import Enum
import json
import os
import pathlib
import queue
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import traceback
from typing import BinaryIO, Dict, List, Optional, Tuple, Union
import uuid
import zlib

import docker
from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey
import nacl.utils

from .common import (
    Config,
    MAX_PRIO,
    MIN_PRIO,
    PROTOCOL_VERSION,
    Port,
    SocketPort,
    file_read_fixed,
    json_prop,
    sign_with_magic,
    socket_read_fixed,
    static_assert_unreachable,
    verify_with_magic,
)


# Close connections that haven't sent input in 5 minutes.
HANG_TIMEOUT = 5 * 60


@dataclass
class PermuterData:
    fn_name: str
    filename: str
    keep_prob: float
    stack_differences: bool
    compile_script: str
    source: str
    target_o_bin: bytes


class InitState(Enum):
    UNINIT = 0
    WAITING = 1
    READY = 2


@dataclass
class ClientState:
    handle: str
    user: bytes
    nickname: str
    priority: float
    output_queue: "queue.Queue[Output]"
    initial_permuters: List[PermuterData]
    num_permuters: int
    work_queue: "queue.Queue[Work]" = field(default_factory=queue.Queue)
    active_work: int = 0
    requested_work_time: Optional[float] = None
    eof: bool = False
    init_state: InitState = InitState.UNINIT
    waiting_perms: int = 0
    perm_bases: List[Optional[Tuple[int, str]]] = field(default_factory=list)
    cooldown: float = 0.0


@dataclass
class AddClient:
    handle: str
    state: ClientState


@dataclass
class RemoveClient:
    handle: str


@dataclass
class NoMoreWork:
    handle: str


@dataclass
class InputError:
    handle: str
    errmsg: Optional[str]


@dataclass
class PermInitFail:
    perm_id: str
    error: str


@dataclass
class PermInitSuccess:
    perm_id: str
    base_score: int
    base_hash: str


@dataclass
class WorkDone:
    perm_id: str
    obj: dict
    compressed_source: Optional[bytes]


@dataclass
class Work:
    handle: str
    permuter_index: int
    seed: int


class Shutdown:
    pass


Activity = Union[
    AddClient,
    RemoveClient,
    NoMoreWork,
    InputError,
    Work,
    PermInitFail,
    PermInitSuccess,
    WorkDone,
    Shutdown,
]


@dataclass
class OutputInitFail:
    error: str


@dataclass
class OutputInitSuccess:
    perm_bases: List[Tuple[int, str]]


@dataclass
class OutputFinished:
    graceful: bool


@dataclass
class OutputNeedMoreWork:
    pass


@dataclass
class OutputWork:
    obj: dict
    compressed_source: Optional[bytes]


Output = Union[
    OutputInitFail, OutputInitSuccess, OutputFinished, OutputNeedMoreWork, OutputWork
]


@dataclass
class IoConnect:
    fn_names: List[str]


@dataclass
class IoDisconnect:
    reason: str


class IoShutdown:
    pass


class IoWillSleep:
    pass


@dataclass
class IoWorkDone:
    score: Optional[int]
    is_improvement: bool


IoMessage = Union[IoConnect, IoDisconnect, IoWorkDone]
IoGlobalMessage = Union[IoShutdown, IoWillSleep]
IoActivity = Union[Tuple[str, str, IoMessage], IoGlobalMessage]


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
    def _setup(
        self, signing_key: SigningKey, auth_ver_key: VerifyKey
    ) -> Tuple[VerifyKey, SocketPort]:
        """Set up a secure (but untrusted) connection with the client, or
        handle an auth server ping."""
        sock: socket.socket = self.request

        # Decrease network latency by disabling Nagle's algorithm.
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # Read and verify protocol version.
        msg = socket_read_fixed(sock, 4)
        version = struct.unpack(">I", msg)[0]

        if version == 2**32 - 1:
            # Auth server ping.
            msg = socket_read_fixed(sock, 9 + 32 + 64)
            magic = verify_with_magic(b"AUTHPING", auth_ver_key, msg)
            sock.sendall(sign_with_magic(b"AUTHPONG", signing_key, magic))

            # Close the connection and raise an exception that the caller will
            # silently swallow.
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            raise EOFError

        if version != PROTOCOL_VERSION:
            raise ValueError(f"Bad protocol version: {version} vs {PROTOCOL_VERSION}")

        # Read signing and (ephemeral) encryption keys from the client. We
        # don't know who the client is yet, so we don't fully trust these keys;
        # we'll start doing so when it presents proof signed by the central
        # server that its signature is legit.
        msg = socket_read_fixed(sock, 32 + 7 + 32 + 64)
        client_ver_key = VerifyKey(msg[:32])
        inner_msg = verify_with_magic(b"CLIENT", client_ver_key, msg[32:])
        client_enc_key = PublicKey(inner_msg)

        # Create an ephemeral encryption key for ourselves as well. Send it to
        # the client, signed by a key it trusts.
        ephemeral_key = PrivateKey.generate()
        sock.sendall(
            sign_with_magic(b"SERVER", signing_key, ephemeral_key.public_key.encode())
        )

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
        if granted_request[:32] != client_ver_key:
            raise ValueError("Grant is for another client")
        request = json.loads(granted_request[32:])
        if not isinstance(request, dict):
            raise ValueError("Grant JSON must be a dict")

        # Verify that the client is not just presenting an old grant.
        valid_from = json_prop(request, "valid_from", int)
        valid_until = json_prop(request, "valid_until", int)
        if not valid_from <= time.time() <= valid_until:
            raise ValueError("Grant is no longer valid")

        # Read client nickname from the server, signed by the client during
        # registration. (Don't let the client spoof this.)
        signed_nickname = base64.b64decode(request["signed_nickname"])
        enc_nickname: bytes = client_ver_key.verify(signed_nickname)
        return enc_nickname.decode("utf-8")

    def _receive_initial(
        self, port: Port, options: ServerOptions
    ) -> Tuple[List[PermuterData], float]:
        # TODO: include current load
        props = {
            "version": 1,
            "min_priority": options.min_priority,
            "num_cpus": options.num_cpus,
        }
        port.send_json(props)

        msg = port.receive_json()
        priority = json_prop(msg, "priority", float)

        if msg.get("files"):
            # TODO: support this
            raise ValueError("Additional files not supported")

        permuters = []
        for obj in json_prop(msg, "permuters", list):
            if not isinstance(obj, dict):
                raise ValueError(f"Permuters must be dictionaries, found {obj}")

            source = zlib.decompress(port.receive()).decode("utf-8")
            target_o_bin = port.receive()

            permuters.append(
                PermuterData(
                    fn_name=json_prop(obj, "fn_name", str),
                    filename=json_prop(obj, "filename", str),
                    keep_prob=json_prop(obj, "keep_prob", float),
                    stack_differences=json_prop(obj, "stack_differences", bool),
                    compile_script=json_prop(obj, "compile_script", str),
                    source=source,
                    target_o_bin=target_o_bin,
                )
            )

        if len(permuters) == 0:
            # We have a bit of code that assumes that there is at least one
            # permuter. Humor it by rejecting this case which shouldn't happen
            # in practice anyway.
            raise ValueError("Must send at least one permuter!")

        priority = min(MAX_PRIO, max(MIN_PRIO, priority))

        return permuters, priority

    def handle(self) -> None:
        shared: SharedServerData = getattr(self.server, "shared")
        signing_key = shared.config.signing_key
        auth_ver_key = shared.config.auth_verify_key

        try:
            client_ver_key, port = self._setup(signing_key, auth_ver_key)
            nickname = self._confirm_grant(port, client_ver_key, auth_ver_key)
        except Exception:
            # Connection attempt by someone who was not allowed access.
            return

        try:
            permuters, priority = self._receive_initial(port, shared.options)

            output_queue: queue.Queue[Output] = queue.Queue()
            init_done = threading.Event()

            def output_loop() -> None:
                try:
                    while True:
                        item = output_queue.get()

                        if isinstance(item, OutputInitFail):
                            assert not init_done.is_set()
                            port.send_json({"success": False, "error": item.error})
                            break

                        if isinstance(item, OutputInitSuccess):
                            assert not init_done.is_set()
                            perm_bases = [
                                {"perm_score": p[0], "perm_hash": p[1]}
                                for p in item.perm_bases
                            ]
                            port.send_json({"success": True, "perm_bases": perm_bases})
                            init_done.set()

                        elif isinstance(item, OutputFinished):
                            if item.graceful:
                                port.send_json({"type": "finish"})
                            break

                        elif isinstance(item, OutputNeedMoreWork):
                            assert init_done.is_set()
                            port.send_json({"type": "need_work"})

                        elif isinstance(item, OutputWork):
                            assert init_done.is_set()
                            port.send_json(item.obj)
                            if item.compressed_source is not None:
                                port.send(item.compressed_source)

                        else:
                            static_assert_unreachable(item)

                except BrokenPipeError:
                    pass

                finally:
                    port.shutdown()

            output_thread = threading.Thread(target=output_loop)
            output_thread.daemon = True
            output_thread.start()

            handle: str = str(uuid.uuid4())

            shared.queue.put(
                AddClient(
                    handle=handle,
                    state=ClientState(
                        handle=handle,
                        user=client_ver_key.encode(),
                        nickname=nickname,
                        priority=priority,
                        output_queue=output_queue,
                        initial_permuters=permuters,
                        num_permuters=len(permuters),
                    ),
                )
            )

            while True:
                msg = port.receive_json()
                if not init_done.is_set():
                    raise ValueError("Got messages before initialization finished.")

                msg_type = json_prop(msg, "type", str)

                if msg_type == "finish":
                    shared.queue.put(NoMoreWork(handle=handle))
                    port.shutdown(socket.SHUT_RD)
                    break

                elif msg_type == "work":
                    permuter_index = json_prop(msg, "permuter", int)
                    seed = json_prop(msg, "seed", int)
                    num_perm = len(permuters)
                    if not 0 <= permuter_index < num_perm:
                        raise ValueError(
                            f"Permuter index out of range ({permuter_index}/{num_perm})"
                        )
                    shared.queue.put(
                        Work(handle=handle, permuter_index=permuter_index, seed=seed)
                    )

                else:
                    raise ValueError(f'Unrecognized message type "{msg_type}"')

        except Exception as e:
            errmsg: Optional[str] = None
            if not isinstance(e, EOFError):
                # Errors due to clients disconnecting aren't worth logging.
                # Other errors can legitimately happen, but only due to
                # protocol violations, and are worth logging to aid debugging.
                errmsg = traceback.format_exc()
            shared.queue.put(InputError(handle=handle, errmsg=errmsg))
            port.shutdown()

        output_thread.join()
        port.close()

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
    _evaluator_port: Port
    _queue: "queue.Queue[Activity]"
    _io_queue: "queue.Queue[IoActivity]"
    _tcp_server: ThreadedTCPServer
    _state: str
    _states: Dict[str, ClientState]
    _active_work: int = 0

    def __init__(
        self,
        config: Config,
        options: ServerOptions,
        evaluator_port: Port,
        io_queue: "queue.Queue[IoActivity]",
    ) -> None:
        self._config = config
        self._options = options
        self._evaluator_port = evaluator_port
        self._queue = queue.Queue()
        self._io_queue = io_queue
        self._tcp_server = ThreadedTCPServer(
            (options.host, options.port), ServerHandler
        )
        self._state = "notstarted"
        self._states = {}

        shared = SharedServerData(config=config, options=options, queue=self._queue)
        setattr(self._tcp_server, "shared", shared)

    def _to_permid(self, state: ClientState, index: int) -> str:
        return state.handle + "," + str(index)

    def _from_permid(self, perm_id: str) -> Tuple[str, int]:
        id_parts = perm_id.split(",")
        assert len(id_parts) == 2, f"bad perm_id format: {perm_id}"
        return id_parts[0], int(id_parts[1])

    def _send_io(self, state: ClientState, io_msg: IoMessage) -> None:
        self._io_queue.put((state.handle, state.nickname, io_msg))

    def _send_io_global(self, io_msg: IoGlobalMessage) -> None:
        self._io_queue.put(io_msg)

    def _handle_message(self, msg: Activity) -> None:
        if isinstance(msg, Shutdown):
            # Handled by caller
            pass

        elif isinstance(msg, Work):
            if msg.handle not in self._states:
                return

            state = self._states[msg.handle]
            assert not state.eof, "cannot be sent after EOF"
            state.work_queue.put(msg)

        elif isinstance(msg, AddClient):
            state = msg.state
            assert msg.handle not in self._states, "unique IDs"
            self._states[msg.handle] = state
            fn_names = sorted({p.fn_name for p in state.initial_permuters})
            self._send_io(state, IoConnect(fn_names))

        elif isinstance(msg, RemoveClient):
            if msg.handle not in self._states:
                return

            state = self._states[msg.handle]
            self._remove(state)
            self._send_io(state, IoDisconnect("kicked"))
            state.output_queue.put(OutputFinished(graceful=False))

        elif isinstance(msg, NoMoreWork):
            if msg.handle not in self._states:
                return

            state = self._states[msg.handle]
            assert not state.eof, "cannot be sent after EOF"
            state.eof = True

        elif isinstance(msg, InputError):
            if msg.handle not in self._states:
                return

            state = self._states[msg.handle]
            self._remove(state)
            text = "disconnected"
            if msg.errmsg:
                text += f" with error:\n{msg.errmsg}"
            self._send_io(state, IoDisconnect(text))

        elif isinstance(msg, (PermInitFail, PermInitSuccess)):
            self._active_work -= 1

            handle, perm_index = self._from_permid(msg.perm_id)
            if handle not in self._states:
                return

            state = self._states[handle]
            assert state.init_state == InitState.WAITING

            if isinstance(msg, PermInitFail):
                self._remove(state)
                self._send_io(state, IoDisconnect("failed to compile"))
                state.output_queue.put(OutputInitFail(error=msg.error,))

            else:
                state.perm_bases[perm_index] = (msg.base_score, msg.base_hash)

                state.waiting_perms -= 1
                if state.waiting_perms == 0:
                    perm_bases: List[Tuple[int, str]] = []
                    for i in range(state.num_permuters):
                        perm_base = state.perm_bases[i]
                        assert perm_base is not None
                        perm_bases.append(perm_base)
                    state.init_state = InitState.READY
                    state.output_queue.put(OutputInitSuccess(perm_bases=perm_bases))

        elif isinstance(msg, WorkDone):
            self._active_work -= 1

            handle, perm_index = self._from_permid(msg.perm_id)
            if handle not in self._states:
                return

            state = self._states[handle]
            assert state.init_state == InitState.READY
            state.active_work -= 1
            obj = msg.obj
            obj["permuter"] = perm_index
            score = json_prop(obj, "score", int) if "score" in obj else None
            self._send_io(
                state,
                IoWorkDone(
                    score=score, is_improvement=(msg.compressed_source is not None)
                ),
            )
            state.output_queue.put(
                OutputWork(obj=obj, compressed_source=msg.compressed_source,)
            )

        else:
            static_assert_unreachable(msg)

    def _remove(self, state: ClientState) -> None:
        assert state.handle in self._states
        if state.init_state != InitState.UNINIT:
            for i in range(state.num_permuters):
                self._evaluator_port.send_json(
                    {"type": "remove", "id": self._to_permid(state, i),}
                )
        del self._states[state.handle]

    def _prune_finished(self) -> None:
        to_remove: List[ClientState] = [
            state
            for state in self._states.values()
            if state.eof
            and state.init_state == InitState.READY
            and state.work_queue.empty()
            and state.active_work == 0
        ]

        for state in to_remove:
            self._remove(state)
            self._send_io(state, IoDisconnect("disconnected"))
            state.output_queue.put(OutputFinished(graceful=True))

    def _send_permuter(self, id_: str, perm: PermuterData) -> None:
        self._evaluator_port.send_json(
            {
                "type": "add",
                "id": id_,
                "fn_name": perm.fn_name,
                "filename": perm.filename,
                "keep_prob": perm.keep_prob,
                "stack_differences": perm.stack_differences,
                "compile_script": perm.compile_script,
            }
        )
        self._evaluator_port.send(perm.source.encode("utf-8"))
        self._evaluator_port.send(perm.target_o_bin)
        self._active_work += 1

    def _next_work(self) -> Optional[ClientState]:
        """Select the next client state to perform work on, i.e. the active one
        with smallest cooldown. Additionally, tell clients with empty queues to
        send us more work, or disconnect them if they are slow."""
        smallest_cooldown = float("inf")
        chosen: Optional[ClientState] = None
        to_remove = []

        for state in self._states.values():
            if state.init_state == InitState.WAITING:
                # Ignore clients that are waiting on sandbox setup.
                pass

            elif state.init_state == InitState.READY and state.work_queue.empty():

                if state.requested_work_time is None:
                    state.requested_work_time = time.time()
                    state.output_queue.put(OutputNeedMoreWork())

                elif time.time() > state.requested_work_time + HANG_TIMEOUT:
                    to_remove.append(state)

            elif state.cooldown < smallest_cooldown:
                smallest_cooldown = state.cooldown
                chosen = state

        for state in to_remove:
            self._remove(state)
            self._send_io(state, IoDisconnect("not responding, dropping"))
            state.output_queue.put(OutputFinished(graceful=False))

        return chosen

    def _add_cooldown(self, chosen: ClientState) -> None:
        # Subtract a constant from all cooldowns, to make the selected client's
        # cooldown zero. This makes sure that new clients enter with a cooldown
        # similar to the existing ones. Also clamp clients that were skipped due
        # to empty queues to the same level, so that they don't take over once
        # their queues fill up.
        baseline = chosen.cooldown
        for state in self._states.values():
            state.cooldown = max(state.cooldown - baseline, 0.0)

        # Add a value to the selected client's cooldown corresponding to its
        # priority and how many other clients correspond to the same user.
        same_user = 0
        for state in self._states.values():
            if state.user == chosen.user and state.requested_work_time is None:
                same_user += 1

        chosen.cooldown += same_user / chosen.priority

    def _send_work(self, state: ClientState) -> None:
        state.requested_work_time = None
        if state.init_state == InitState.UNINIT:
            state.init_state = InitState.WAITING
            state.waiting_perms = state.num_permuters
            state.perm_bases = [None for _ in range(state.num_permuters)]
            for i, p in enumerate(state.initial_permuters):
                self._send_permuter(self._to_permid(state, i), p)
            state.initial_permuters = []
        else:
            work = state.work_queue.get_nowait()
            assert work is not None, "queue is non-empty"
            self._evaluator_port.send_json(
                {
                    "type": "work",
                    "id": self._to_permid(state, work.permuter_index),
                    "seed": work.seed,
                }
            )
            self._active_work += 1
            state.active_work += 1

    def _maybe_send_work(self) -> bool:
        # Go through the queues and check if anything needs to be sent to the
        # evaluator. We prioritize queues based on cooldown -- the queue with
        # the shortest remaining cooldown is processed first (and gets
        # normalized to have cooldown = 0).
        state = self._next_work()

        if state is not None:
            self._send_work(state)
            self._add_cooldown(state)
            return True

        return False

    def _read_eval_loop(self) -> None:
        try:
            while True:
                msg = self._evaluator_port.receive_json()
                msg_type = json_prop(msg, "type", str)

                if msg_type == "init":
                    perm_id = json_prop(msg, "id", str)
                    resp: Activity
                    if json_prop(msg, "success", bool):
                        resp = PermInitSuccess(
                            perm_id=perm_id,
                            base_score=json_prop(msg, "base_score", int),
                            base_hash=json_prop(msg, "base_hash", str),
                        )
                    else:
                        resp = PermInitFail(
                            perm_id=perm_id, error=json_prop(msg, "error", str),
                        )
                    self._queue.put(resp)

                elif msg_type == "result":
                    compressed_source: Optional[bytes] = None
                    if msg.get("has_source") == True:
                        compressed_source = self._evaluator_port.receive()
                    perm_id = json_prop(msg, "id", str)
                    del msg["id"]
                    self._queue.put(
                        WorkDone(
                            perm_id=perm_id,
                            obj=msg,
                            compressed_source=compressed_source,
                        )
                    )

                else:
                    raise Exception(f"Unknown message type from evaluator: {msg_type}")

        except EOFError:
            pass

    def _main_loop(self) -> None:
        max_work = int(self._options.num_cpus) * 2 + 4
        while True:
            msg = self._queue.get()
            if isinstance(msg, Shutdown):
                break

            self._handle_message(msg)

            while self._active_work < max_work:
                if not self._maybe_send_work():
                    break

            self._prune_finished()

            if not self._states and self._queue.empty():
                self._send_io_global(IoWillSleep())

    def start(self) -> None:
        assert self._state == "notstarted"
        self._state = "started"

        # Start a thread with the TCP server -- that thread will then start one
        # more thread for each request.
        server_thread = threading.Thread(target=self._tcp_server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        # Start a thread for reading evaluator results and sending them on to
        # the main loop queue.
        read_eval_thread = threading.Thread(target=self._read_eval_loop)
        read_eval_thread.daemon = True
        read_eval_thread.start()

        # Start a thread for the main loop.
        main_thread = threading.Thread(target=self._main_loop)
        main_thread.daemon = True
        main_thread.start()

    def remove_client(self, handle: str) -> None:
        self._queue.put(RemoveClient(handle=handle))

    def stop(self) -> None:
        assert self._state == "started"
        self._state = "finished"
        self._tcp_server.shutdown()
        self._queue.put(Shutdown())


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


def start_evaluator(docker_image: str, options: ServerOptions) -> DockerPort:
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
    num_threads = int(options.num_cpus + 0.5) + 1
    command = ["python3", "-m", "src.net.evaluator", str(num_threads)]
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
        tmpfs={"/tmp": "size=1G,exec"},
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
