from dataclasses import dataclass
from socket import socket
import struct
from typing import Optional

from nacl.signing import SigningKey
from nacl.public import Box, PrivateKey, PublicKey, SealedBox, VerifyKey


@dataclass
class Config:
    server_verify_key: Optional[VerifyKey] = None
    signing_key: Optional[SigningKey] = None
    nickname: Optional[str] = None


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
