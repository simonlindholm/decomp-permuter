import json
from typing import Tuple

from nacl.public import Box, PrivateKey
from nacl.signing import SigningKey, VerifyKey

from .common import Port


def talk_to_server(ip_port: Tuple[str, int], ver_key: VerifyKey, grant: bytes) -> None:
    # TODO: read from config or bail
    signing_key = SigningKey.generate()

    ephemeral_key = PrivateKey.generate()
    msg = signing_key.verify_key.encode() + signing_key.sign(
        ephemeral_key.public_key.encode()
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
