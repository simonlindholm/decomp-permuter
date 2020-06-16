import base64
from dataclasses import dataclass
import json
from socket import socket
import socketserver
import struct
import threading
import time
from typing import Tuple

from nacl.signing import SigningKey, VerifyKey
from nacl.public import Box, PrivateKey, PublicKey
import nacl.utils

from .common import Config, PROTOCOL_VERSION, Port, json_prop, socket_read_fixed


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


class ServerHandler(socketserver.BaseRequestHandler):
    def _setup(self, signing_key: SigningKey) -> Tuple[VerifyKey, Port]:
        """Set up a secure (but untrusted) connection with the client."""
        sock: socket = self.request

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

        # Set up encrypted communication channel.
        box = Box(signing_key.to_curve25519_private_key(), client_enc_key)
        port = Port(sock, box, is_client=False)

        # To protect against replay attacks, send a random message and ask the
        # client to send it back. (The ephemeral encryption key solves the same
        # problem for the client.)
        rand = nacl.utils.random(32)
        port.send(rand)
        msg = port.receive()
        assert msg == rand

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

    def handle(self) -> None:
        shared: SharedServerData = getattr(self.server, "shared")
        signing_key = shared.config.signing_key
        client_ver_key, port = self._setup(signing_key)

        auth_ver_key = shared.config.auth_verify_key
        nickname = self._confirm_grant(port, client_ver_key, auth_ver_key)
        print(f"[{nickname}] connected")

        self._send_init(port, shared.options)
        # TODO: do stuff!
        time.sleep(2)
        print("done")

    def finish(self) -> None:
        print("finished()")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # When restarting the server, rebind the port instead of complaining that
    # "Address already in use". We do authentication as the first step of each
    # connection, so this is fine.
    allow_reuse_address = True

    # When the main program stops, it is fine for us to drop all server threads
    # on the floor.
    daemon_threads = True


def start_server(config: Config, options: ServerOptions) -> ThreadedTCPServer:
    shared = SharedServerData(config=config, options=options)

    server = ThreadedTCPServer((options.host, options.port), ServerHandler)
    setattr(server, "shared", shared)

    # Start a thread with the server -- that thread will then start one
    # more thread for each request.
    server_thread = threading.Thread(target=server.serve_forever)

    # Exit the server thread when the main thread terminates.
    server_thread.daemon = True
    server_thread.start()

    return server
