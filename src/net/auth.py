import base64
from dataclasses import dataclass
import json
import os
import random
import string
import sys
import time
from typing import List, Optional, Tuple

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.public import PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

from .common import Config, RawConfig, RemoteServer, read_config, write_config


def _random_name() -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(5))


def _decode_hex_key(sign: str) -> bytes:
    ret: bytes = HexEncoder.decode(sign)
    if len(ret) != 32:
        raise BadSignatureError("Key has wrong length.")
    return ret


def _ask(msg: str, *, default: bool) -> bool:
    if default:
        msg += " (Y/n)? "
    else:
        msg += " (y/N)? "
    res = input(msg).strip().lower()
    if not res:
        return default
    if res in ["y", "yes", "n", "no"]:
        return res[0] == "y"
    print("Bad response!", file=sys.stderr)
    sys.exit(1)


def _initial_setup(config: RawConfig) -> None:
    print(
        "Using permuter@home requires someone to give you access to a central -J server."
    )
    print()

    signing_key: Optional[SigningKey] = config.signing_key
    if not signing_key or not _ask("Keep previous secret key", default=True):
        signing_key = SigningKey.generate()
        config.signing_key = signing_key
        write_config(config)
    verify_key = signing_key.verify_key

    nickname: Optional[str] = config.initial_setup_nickname
    if not nickname or not _ask(f"Keep previous nickname [{nickname}]", default=True):
        default_nickname = os.environ.get("USER") or _random_name()
        nickname = (
            input(f"Nickname [default: {default_nickname}]: ") or default_nickname
        )
        config.initial_setup_nickname = nickname
        write_config(config)

    signed_nickname = signing_key.sign(nickname.encode("utf-8"))

    vouch_data = verify_key.encode() + signed_nickname
    vouch_text = base64.b64encode(vouch_data).decode("utf-8")
    print("Ask someone to run the following command:")
    print(f"./permuter.py --vouch {vouch_text}")
    print()
    print("They should give you a token back in return. Paste that here:")
    inp = input().strip()

    try:
        token = base64.b64decode(inp.encode("utf-8"))
        data = SealedBox(signing_key.to_curve25519_private_key()).decrypt(token)
        auth_verify_key = VerifyKey(data[:32])
        auth_server = data[32:].decode("utf-8")
        print(f"Server URL: {auth_server}")
        print("Testing connection...")
        time.sleep(1)

        # TODO: verify that contacting auth server works and signs its messages

        print("permuter@home successfully set up!")
        print()
        config.auth_server = auth_server
        config.auth_verify_key = auth_verify_key
        config.initial_setup_nickname = None
        write_config(config)
    except Exception:
        print("Invalid token!")
        sys.exit(1)


def setup() -> Config:
    raw_config = read_config()
    if (
        not raw_config.auth_verify_key
        or not raw_config.signing_key
        or not raw_config.auth_server
    ):
        _initial_setup(raw_config)
    assert (
        raw_config.auth_verify_key and raw_config.signing_key and raw_config.auth_server
    ), "set by _initial_setup"
    return Config(
        auth_server=raw_config.auth_server,
        auth_verify_key=raw_config.auth_verify_key,
        signing_key=raw_config.signing_key,
    )


def run_vouch(vouch_text: str) -> None:
    config = setup()

    try:
        vouch_data = base64.b64decode(vouch_text.encode("utf-8"))
        verify_key = VerifyKey(vouch_data[:32])
        signed_nickname = vouch_data[32:]
        nickname = verify_key.verify(signed_nickname)
    except Exception:
        print("Could not parse data!")
        return

    if not _ask(f"Grant permuter server access to {nickname}", default=True):
        return

    # TODO: send signature and signed nickname to central server

    data = config.auth_verify_key.encode() + config.auth_server.encode("utf-8")
    token = SealedBox(verify_key.to_curve25519_public_key()).encrypt(data)
    print("Granted!")
    print()
    print("Send them the following token:")
    print(base64.b64encode(token).decode("utf-8"))


def fetch_servers_and_grant(config: Config) -> Tuple[List[RemoteServer], bytes]:
    print("Connecting to permuter@home...")
    request_obj = {
        "version": 1,
    }
    request = json.dumps(request_obj).encode("utf-8")
    data = config.signing_key.sign(request)

    # TODO: send 'data' to auth server, receive 'resp'

    raw_resp = b""
    raw_resp = config.auth_verify_key.verify(raw_resp)
    resp = json.loads(raw_resp)
    assert resp["version"] == 1
    grant = base64.b64decode(resp["grant"])
    granted_request = config.auth_verify_key.verify(grant)
    assert granted_request[:32] == config.signing_key.verify_key.encode()

    server_list = resp["server_list"]

    ret = []
    for obj in server_list:
        server = RemoteServer(
            ip=obj["ip"],
            port=obj["port"],
            ver_key=VerifyKey(_decode_hex_key(obj["verification_key"])),
        )
        ret.append(server)

    return ret, grant


def fetch_docker_image_name(config: Config) -> str:
    print("Connecting to permuter@home...")
    # TODO
    return "ido"


def go_online(config: Config) -> None:
    # TODO
    pass


def go_offline(config: Config) -> None:
    # TODO
    pass
