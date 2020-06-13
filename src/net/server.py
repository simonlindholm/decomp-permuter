import base64
import json
import socketserver
import threading
import time

from nacl.signing import SigningKey, VerifyKey
from nacl.public import Box, PrivateKey
import nacl.util

from .common import Port


def talk_to_client() -> None:
    # TODO: read from config
    server_verify_key = SigningKey.generate().verify_key
    signing_key = SigningKey.generate()

    # TODO: receive from client
    msg = b""

    client_ver_key = VerifyKey(msg[:32])
    client_enc_key = client_ver_key.verify(msg[32:])
    box = Box(signing_key.to_curve25519_private_key(), client_enc_key)
    port = Port(box, is_client=False)
    rand = nacl.util.random(32)
    port.send(rand)
    msg = port.receive()
    assert msg[:32] == rand
    granted_request = server_verify_key.verify(msg[32:])
    assert granted_request[:32] == client_ver_key
    request = granted_request[32:]
    assert int(request["valid_from"]) <= time.time() <= int(request["valid_until"])
    signed_nickname = base64.b64decode(request["signed_nickname"])
    nickname = client_ver_key.verify(signed_nickname)
    resp = {
        "status": "ok",
    }
    port.send(json.dumps(resp).encode("utf-8"))
    print("connected to", nickname)


class ServerHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = str(self.request.recv(1024), "ascii")
        cur_thread = threading.current_thread()
        response = bytes("{}: {}".format(cur_thread.name, data), "ascii")
        self.request.sendall(response)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # When restarting the server, rebind the port instead of complaining that
    # "Address already in use". We do authentication as the first step of each
    # connection, so this is fine.
    allow_reuse_address = True

    # When the main program stops, it is fine for us to drop all server threads
    # on the floor.
    daemon_threads = True


def start_server(host: str, port: int) -> ThreadedTCPServer:
    server = ThreadedTCPServer((host, port), ServerHandler)
    ip, port = server.server_address

    # Start a thread with the server -- that thread will then start one
    # more thread for each request.
    server_thread = threading.Thread(target=server.serve_forever)

    # Exit the server thread when the main thread terminates.
    server_thread.daemon = True
    server_thread.start()

    return server
