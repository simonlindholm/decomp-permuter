from dataclasses import dataclass
from socket import socket
import struct
import sys
import toml
from typing import Optional

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey, VerifyKey
from nacl.public import Box, PrivateKey, PublicKey, SealedBox


PROTOCOL_VERSION = 1

CONFIG_FILENAME = "pah.conf"


@dataclass
class RemoteServer:
    ip: str
    port: int
    ver_key: VerifyKey


@dataclass
class RawConfig:
    auth_server: Optional[str] = None
    auth_verify_key: Optional[VerifyKey] = None
    signing_key: Optional[SigningKey] = None
    initial_setup_nickname: Optional[str] = None


@dataclass
class Config:
    auth_server: str
    auth_verify_key: VerifyKey
    signing_key: SigningKey


def read_config() -> RawConfig:
    config = RawConfig()
    try:
        with open(CONFIG_FILENAME) as f:
            obj = toml.load(f)
        temp = obj.get("auth_public_key")
        if temp:
            config.auth_verify_key = VerifyKey(HexEncoder.decode(temp))
        temp = obj.get("secret_key")
        if temp:
            config.signing_key = SigningKey(HexEncoder.decode(temp))
        temp = obj.get("initial_setup_nickname")
        if isinstance(temp, str):
            config.initial_setup_nickname = temp
        temp = obj.get("initial_setup_nickname")
        if isinstance(temp, str):
            config.initial_setup_nickname = temp
    except FileNotFoundError:
        pass
    except Exception:
        print(f"Malformed configuration file {CONFIG_FILENAME}.\n")
        raise
    return config


def write_config(config: RawConfig) -> None:
    obj = {}
    key_hex: bytes
    if config.auth_verify_key:
        key_hex = config.auth_verify_key.encode(HexEncoder)
        obj["auth_public_key"] = key_hex.decode("utf-8")
    if config.signing_key:
        key_hex = config.signing_key.encode(HexEncoder)
        obj["secret_key"] = key_hex.decode("utf-8")
    if config.initial_setup_nickname:
        obj["initial_setup_nickname"] = config.initial_setup_nickname
    if config.auth_server:
        obj["auth_server"] = config.auth_server
    with open(CONFIG_FILENAME, "w") as f:
        toml.dump(obj, f)


def socket_read_fixed(sock: socket, n: int) -> bytes:
    ret = []
    while n > 0:
        data = sock.recv(min(n, 4096))
        if not data:
            raise Exception("eof")
        ret.append(data)
        n -= len(data)
    return b"".join(ret)


class Port:
    def __init__(self, sock: socket, box: Box, *, is_client: bool) -> None:
        self._sock = sock
        self._box = box
        self._send_nonce = 0 if is_client else 1
        self._receive_nonce = 1 if is_client else 0

    def send(self, msg: bytes) -> None:
        nonce = struct.pack(">24xQ", self._send_nonce)
        self._send_nonce += 2
        data = self._box.encrypt(msg, nonce)
        length_data = struct.pack(">Q", len(data))
        self._sock.sendall(length_data + data)

    def receive(self) -> bytes:
        length_data = socket_read_fixed(self._sock, 8)
        length = struct.unpack(">Q", length_data)[0]
        data = socket_read_fixed(self._sock, length)
        nonce = struct.pack(">24xQ", self._receive_nonce)
        self._receive_nonce += 2
        ret: bytes = self._box.decrypt(data, nonce)
        return ret
