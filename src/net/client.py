from dataclasses import dataclass
import json
import struct
from typing import List, Tuple

from nacl.public import Box, PrivateKey
from nacl.signing import SigningKey, VerifyKey

from .common import Config, Port, RemoteServer


@dataclass
class State:
    servers: List[RemoteServer]
    grant: bytes


def init_client(servers: List[RemoteServer], grant: bytes) -> State:
    return State(servers=servers, grant=grant)


def talk_to_server(
    config: Config, ip_port: Tuple[str, int], ver_key: VerifyKey, grant: bytes
) -> None:
    ephemeral_key = PrivateKey.generate()
    msg = (
        struct.pack(">I", 1)
        + config.signing_key.verify_key.encode()
        + config.signing_key.sign(ephemeral_key.public_key.encode())
    )
    # TODO: send 'msg'

    sock = ...
    box = Box(ephemeral_key, ver_key.to_curve25519_public_key())
    port = Port(sock, box, is_client=True)
    # To help guard the server against replay attacks, send a server-chosen
    # string as part of our first message.
    rand = port.receive()
    port.send(rand + grant)
    resp = json.loads(port.receive())
    assert resp["status"] == "ok"
