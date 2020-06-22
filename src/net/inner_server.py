import base64
import os
import struct
import sys
from typing import BinaryIO

from nacl.secret import SecretBox

from .common import FilePort, Port, file_read_fixed


def _setup_comm() -> Port:
    """Set up communication with the outside world."""
    secret = base64.b64decode(os.environ["SECRET"])
    comm = FilePort(
        sys.stdin.buffer, sys.stdout.buffer, SecretBox(secret), is_client=False
    )

    # Since we use sys.stdout for our own purposes, redirect it to stdout to
    # make print() debugging work.
    sys.stdout = sys.stderr

    # Follow the controlling process's sanity check protocol.
    magic = comm.receive()
    comm.send(magic)

    return comm


def main() -> None:
    comm = _setup_comm()


if __name__ == "__main__":
    main()
