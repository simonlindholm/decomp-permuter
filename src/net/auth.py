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

from .core import (
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
