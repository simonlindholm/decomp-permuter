import struct

from nacl.public import Box, PrivateKey, PublicKey, SealedBox


class Port:
    def __init__(self, box: Box, *, is_client: bool) -> None:
        self.box = box
        self.send_nonce = 0 if is_client else 1
        self.receive_nonce = 1 if is_client else 0

    def send(self, msg: bytes) -> None:
        nonce = struct.pack(">24xQ", self.send_nonce)
        self.send_nonce += 2
        self.box.encrypt(msg, nonce)
        # TODO: send

    def receive(self) -> bytes:
        # TODO: receive
        data = b""
        nonce = struct.pack(">24xQ", self.receive_nonce)
        self.receive_nonce += 2
        ret: bytes = self.box.decrypt(data, nonce)
        return ret
