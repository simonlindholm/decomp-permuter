import base64
import os
import struct
import sys
from typing import BinaryIO, cast

from nacl.secret import SecretBox


class Communicator:
    def __init__(self, inf: BinaryIO, outf: BinaryIO, secret: bytes) -> None:
        self._inf = inf
        self._outf = outf
        self._box = SecretBox(secret)

    def send(self, data: bytes) -> None:
        """Send a message to the outside server, potentially blocking."""
        data = self._box.encrypt(data)
        data = struct.pack(">I", len(data)) + data
        self._outf.write(data)
        self._outf.flush()

    def _read_fixed(self, length: int) -> bytes:
        ret = []
        while length > 0:
            data = self._inf.read(length)
            ret.append(data)
            length -= len(data)
        return b"".join(ret)

    def read(self) -> bytes:
        """Read a message from the outside server, blocking."""
        length = struct.unpack(">I", self._read_fixed(4))[0]
        data = self._read_fixed(length)
        return cast(bytes, self._box.decrypt(data))


def _setup_comm() -> Communicator:
    """Set up communication with the outside world."""
    secret = base64.b64decode(os.environ["SECRET"])
    comm = Communicator(sys.stdin.buffer, sys.stdout.buffer, secret)

    # Since we use sys.stdout for our own purposes, redirect it to stdout to
    # make print() debugging work.
    sys.stdout = sys.stderr

    # Follow the controlling process's sanity check protocol.
    magic = comm.read()
    comm.send(magic)

    return comm


def main() -> None:
    comm = _setup_comm()


if __name__ == "__main__":
    main()
