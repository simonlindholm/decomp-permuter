import base64
import json
import os
import random
import string
import sys
from typing import List, Optional, Tuple

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.public import Box, PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

from .common import Port


def random_string() -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(5))


def ask(msg: str, *, default: bool) -> bool:
    if default:
        msg += " (Y/n)? "
    else:
        msg += " (y/N)? "
    res = input(msg).strip().lower()
    if not res:
        return default
    if res in ["y", "yes", "n", "no"]:
        return res[0] == "y"
    print("Bad response!")
    sys.exit(1)


def decode_hex_signature(sign: str) -> bytes:
    ret: bytes = HexEncoder.decode(sign)
    if len(ret) != 32:
        raise BadSignatureError("Signature has wrong length.")
    return ret


def initial_setup() -> None:
    signing_key: Optional[SigningKey] = None
    # TODO: read from config
    if not signing_key or not ask("Keep previous secret key", default=True):
        # TODO: signature key
        signing_key = SigningKey.generate()
        # TODO: write to config
    verify_key = signing_key.verify_key

    nickname: Optional[str] = None
    # TODO: read from config
    if not nickname or not ask(f"Keep previous nickname {nickname}", default=True):
        default_nickname = os.environ.get("USER") or random_string()
        nickname = (
            input(f"Nickname [default: {default_nickname}]: ") or default_nickname
        )
        # TODO: write to config

    signed_nickname = signing_key.sign(nickname.encode("utf-8"))

    vouch_data = verify_key.encode() + signed_nickname
    vouch_text = base64.b64encode(vouch_data).decode("utf-8")
    print("Ask someone to run the following command:")
    print(f"./permuter.py -J --vouch {vouch_text}")
    print()
    print("They should give you a token back in return. Paste that here:")
    inp = input().strip()

    try:
        token = base64.b64decode(inp.encode("utf-8"))
        data = SealedBox(signing_key.to_curve25519_private_key()).decrypt(token)
        server_verify_key = data[:32]
        url = data[32:].decode("utf-8")
        print("Server URL:", url)
        # TODO: verify that contacting server works and signs its messages
        # TODO: write to config
    except Exception:
        print("Invalid token!")


def vouch(vouch_text: str) -> None:
    # TODO: read from config or bail
    server_url = ""
    signing_key = SigningKey.generate()
    server_verify_key = SigningKey.generate().verify_key

    try:
        vouch_data = base64.b64decode(vouch_text.encode("utf-8"))
        verify_key = VerifyKey(vouch_data[:32])
        signed_nickname = vouch_data[32:]
        nickname = verify_key.verify(signed_nickname)
    except Exception:
        print("Could not parse data!")
        return

    if not ask(f"Grant permuter server access to {nickname}", default=True):
        return

    # TODO: send signature and signed nickname to central server

    token = SealedBox(verify_key.to_curve25519_public_key()).encrypt(server_url)
    print("Granted!")
    print()
    print("Send them the following token:")
    print(base64.b64encode(token).decode("utf-8"))


def get_servers() -> Tuple[List[Tuple[str, int, VerifyKey]], bytes]:
    # TODO: read from config or bail
    server_url = ""
    signing_key = SigningKey.generate()
    server_verify_key = SigningKey.generate().verify_key

    request_obj = {
        "version": 1,
    }
    request = json.dumps(request_obj).encode("utf-8")
    data = signing_key.sign(request)
    # TODO: send 'data' to server, receive 'resp'
    raw_resp = b""
    raw_resp = server_verify_key.verify(raw_resp)
    resp = json.loads(raw_resp)
    assert resp["version"] == 1
    grant = base64.b64decode(resp["grant"])
    granted_request = server_verify_key.verify(grant)
    assert granted_request[:32] == signing_key.verify_key.encode()

    server_list = resp["server_list"]

    ret = []
    for server in server_list:
        ip = server["ip"]
        port = server["port"]
        ver_key = VerifyKey(decode_hex_signature(server["verification_key"]))
        ret.append((ip, port, ver_key))

    return ret, grant


def talk_to_server(ip_port: Tuple[str, int], ver_key: VerifyKey, grant: bytes) -> None:
    # TODO: read from config or bail
    signing_key = SigningKey.generate()

    ephemeral_key = PrivateKey.generate()
    msg = signing_key.verify_key.encode() + signing_key.sign(
        ephemeral_key.public_key.encode()
    )
    # TODO: send 'msg'

    box = Box(ephemeral_key, ver_key.to_curve25519_public_key())
    port = Port(box, is_client=True)
    # To help guard the server against replay attacks, send a server-chosen
    # string as part of our first message.
    rand = port.receive()
    port.send(rand + grant)
    resp = json.loads(port.receive())
    assert resp["status"] == "ok"
