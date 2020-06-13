import base64
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

from .common import Config, Port, socket_read_fixed


class ServerHandler(socketserver.BaseRequestHandler):
    def _setup(self, signing_key: SigningKey) -> Tuple[VerifyKey, Port]:
        """Set up a secure (but untrusted) connection with the client."""
        sock: socket = self.request

        # TODO: Add a version number here

        # Read signing and (ephemeral) encryption keys from the client. We
        # don't know who the client is yet, so we don't fully trust these keys;
        # we'll start doing so when it presents proof signed by the central
        # server that its signature is legit.
        msg = socket_read_fixed(sock, 128)
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
        self, port: Port, client_ver_key: VerifyKey, server_ver_key: VerifyKey
    ) -> str:
        """Check that the client can present proof from the central server that
        its request is valid. (We could also ask the central server itself, but
        this saves some complexity and network traffic.)"""
        msg = port.receive()
        granted_request = server_ver_key.verify(msg)
        assert granted_request[:32] == client_ver_key
        request = json.loads(granted_request[32:])

        # Verify that the client is not just presenting an old grant.
        assert int(request["valid_from"]) <= time.time() <= int(request["valid_until"])

        # Read client nickname from the server, signed by the client during
        # registration. (Don't let the client spoof this.)
        signed_nickname = base64.b64decode(request["signed_nickname"])
        enc_nickname: bytes = client_ver_key.verify(signed_nickname)
        return enc_nickname.decode("utf-8")

    def _send_init(self, port: Port) -> None:
        # TODO
        props = {
            "priority_cap": 1.0,
            "num_cpus": 1.0,
        }
        port.send(json.dumps(props).encode("utf-8"))

    def handle(self) -> None:
        config = getattr(self.server, "config")
        signing_key = config.signing_key
        assert signing_key is not None, "checked on startup"
        client_ver_key, port = self._setup(signing_key)

        server_ver_key = config.server_verify_key
        assert server_ver_key is not None, "checked on startup"
        nickname = self._confirm_grant(port, client_ver_key, server_ver_key)
        print(f"[nickname] connected")

        self._send_init(port)
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


def start_server(host: str, port: int) -> ThreadedTCPServer:
    # TODO read config
    config = Config(
        signing_key=SigningKey.generate(),
        server_verify_key=SigningKey.generate().verify_key,
    )

    server = ThreadedTCPServer((host, port), ServerHandler)
    setattr(server, "config", config)

    # Start a thread with the server -- that thread will then start one
    # more thread for each request.
    server_thread = threading.Thread(target=server.serve_forever)

    # Exit the server thread when the main thread terminates.
    server_thread.daemon = True
    server_thread.start()

    return server
