import base64
from dataclasses import dataclass
import json
import os
import random
import string
import sys
import time
from typing import Dict, List, Optional, Tuple
import urllib.parse
import urllib.request

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.public import PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

from .common import (
    Config,
    RawConfig,
    RemoteServer,
    json_prop,
    read_config,
    sign_with_magic,
    verify_with_magic,
    write_config,
)


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
    print("Bad response!")
    sys.exit(1)


def _post_request(config: Config, path: str, params: Dict[str, bytes]) -> bytes:
    params["auth"] = sign_with_magic(b"AUTH", config.signing_key, b"")
    data = urllib.parse.urlencode(params).encode("utf-8")
    with urllib.request.urlopen(config.auth_server + path, data) as f:
        ret: bytes = f.read()
        return ret


def _get_request(config: Config, path: str) -> bytes:
    with urllib.request.urlopen(config.auth_server + path) as f:
        ret: bytes = f.read()
        return ret


def setup() -> Config:
    raw_config = read_config()
    if (
        not raw_config.auth_verify_key
        or not raw_config.signing_key
        or not raw_config.auth_server
    ):
        print(
            "Using permuter@home requires someone to give you access to a central -J server.\n"
            "Run `./pah.py setup` to set this up."
        )
        sys.exit(1)

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
        msg = verify_with_magic(b"NICK", verify_key, signed_nickname)
        nickname = msg.decode("utf-8")
    except Exception:
        print("Could not parse data!")
        return

    # TODO: don't allow escape codes
    if not _ask(f"Grant permuter server access to {nickname}", default=True):
        return

    _post_request(
        config,
        "/vouch",
        {
            "pubkey": config.signing_key.verify_key.encode(),
            "vouched_pubkey": verify_key.encode(),
            "signed_nickname": signed_nickname,
        },
    )

    data = config.auth_verify_key.encode() + config.auth_server.encode("utf-8")
    token = SealedBox(verify_key.to_curve25519_public_key()).encrypt(data)
    print("Granted!")
    print()
    print("Send them the following token:")
    print(base64.b64encode(token).decode("utf-8"))


def fetch_servers_and_grant(config: Config) -> Tuple[List[RemoteServer], bytes]:
    print("Connecting to permuter@home...")
    raw_resp = _post_request(
        config,
        "/list-servers",
        {
            "pubkey": config.signing_key.verify_key.encode(),
        },
    )
    raw_resp = verify_with_magic(b"SERVERLIST", config.auth_verify_key, raw_resp)
    resp = json.loads(raw_resp)

    version = json_prop(resp, "version", int)
    if version != 1:
        print("Permuter version too old; update to use -J.")
        sys.exit(1)

    grant = base64.b64decode(json_prop(resp, "grant", str))
    granted_request = verify_with_magic(b"GRANT", config.auth_verify_key, grant)
    assert granted_request[:32] == config.signing_key.verify_key.encode()

    server_list = json_prop(resp, "server_list", list)

    ret = []
    for obj in server_list:
        assert isinstance(obj, dict)
        server = RemoteServer(
            ip=json_prop(obj, "ip", str),
            port=json_prop(obj, "port", int),
            nickname=json_prop(obj, "nickname", str),
            ver_key=VerifyKey(
                HexEncoder.decode(json_prop(obj, "verification_key", str))
            ),
        )
        ret.append(server)

    return ret, grant


def fetch_docker_image_name(config: Config) -> str:
    print("Connecting to permuter@home...")
    resp = _get_request(config, "/docker")
    docker_image = verify_with_magic(b"DOCKER", config.auth_verify_key, resp)
    return docker_image.decode("utf-8")


def go_online(config: Config, port: int) -> None:
    _post_request(
        config,
        "/go-online",
        {
            "port": str(port).encode("utf-8"),
            "pubkey": config.signing_key.verify_key.encode(),
        },
    )


def go_offline(config: Config) -> None:
    _post_request(
        config,
        "/go-offline",
        {
            "pubkey": config.signing_key.verify_key.encode(),
        },
    )
