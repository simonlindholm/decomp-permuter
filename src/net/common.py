import abc
from dataclasses import dataclass
import json
import socket
import struct
import sys
import toml
from typing import BinaryIO, NoReturn, Optional, Type, TypeVar, Union

from nacl.encoding import HexEncoder
from nacl.public import Box, PrivateKey, PublicKey, SealedBox
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey

T = TypeVar("T")
AnyBox = Union[Box, SecretBox]

PROTOCOL_VERSION = 1

CONFIG_FILENAME = "pah.conf"

MIN_PRIO = 0.01
MAX_PRIO = 2.0


@dataclass
class RemoteServer:
    ip: str
    port: int
    nickname: str
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


def static_assert_unreachable(x: NoReturn) -> NoReturn:
    raise Exception("Unreachable! " + repr(x))


def read_config() -> RawConfig:
    config = RawConfig()
    try:
        with open(CONFIG_FILENAME) as f:
            obj = toml.load(f)

        def read(key: str, t: Type[T]) -> Optional[T]:
            ret = obj.get(key)
            return ret if isinstance(ret, t) else None

        temp = read("auth_public_key", str)
        if temp:
            config.auth_verify_key = VerifyKey(HexEncoder.decode(temp))
        temp = read("secret_key", str)
        if temp:
            config.signing_key = SigningKey(HexEncoder.decode(temp))
        config.initial_setup_nickname = read("initial_setup_nickname", str)
        config.auth_server = read("auth_server", str)
    except FileNotFoundError:
        pass
    except Exception:
        print(f"Malformed configuration file {CONFIG_FILENAME}.\n")
        raise
    return config


def write_config(config: RawConfig) -> None:
    obj = {}

    def write(key: str, val: Union[None, str, int]) -> None:
        if val is not None:
            obj[key] = val

    write("initial_setup_nickname", config.initial_setup_nickname)
    write("auth_server", config.auth_server)

    key_hex: bytes
    if config.auth_verify_key:
        key_hex = config.auth_verify_key.encode(HexEncoder)
        write("auth_public_key", key_hex.decode("utf-8"))
    if config.signing_key:
        key_hex = config.signing_key.encode(HexEncoder)
        write("secret_key", key_hex.decode("utf-8"))

    with open(CONFIG_FILENAME, "w") as f:
        toml.dump(obj, f)


def file_read_fixed(inf: BinaryIO, n: int) -> bytes:
    try:
        ret = []
        while n > 0:
            data = inf.read(n)
            if not data:
                raise EOFError
            ret.append(data)
            n -= len(data)
        return b"".join(ret)
    except ValueError as e:
        if e.args == ("I/O operation on closed file.",):
            raise EOFError
        raise


def socket_read_fixed(sock: socket.socket, n: int) -> bytes:
    try:
        ret = []
        while n > 0:
            data = sock.recv(min(n, 4096))
            if not data:
                raise EOFError
            ret.append(data)
            n -= len(data)
        return b"".join(ret)
    except OSError as e:
        if e.errno == 107:
            # Ignore ENOTCONN
            raise EOFError
        raise


def json_prop(obj: dict, prop: str, t: Type[T]) -> T:
    ret = obj.get(prop)
    if not isinstance(ret, t):
        found_type = type(ret).__name__
        raise ValueError(f"Member {prop} must have type {t.__name__}; got {found_type}")
    return ret


def sign_with_magic(magic: bytes, signing_key: SigningKey, data: bytes) -> bytes:
    ret: bytes = signing_key.sign(magic + b":" + data)
    return ret


def verify_with_magic(magic: bytes, verify_key: VerifyKey, data: bytes) -> bytes:
    verified_data: bytes = verify_key.verify(data)
    if not verified_data.startswith(magic + b":"):
        raise ValueError("Bad magic")
    return verified_data[len(magic) + 1 :]


class Port(abc.ABC):
    def __init__(self, box: AnyBox, *, is_client: bool) -> None:
        self._box = box
        self._send_nonce = 0 if is_client else 1
        self._receive_nonce = 1 if is_client else 0

    @abc.abstractmethod
    def _send(self, data: bytes) -> None:
        ...

    @abc.abstractmethod
    def _receive(self, length: int) -> bytes:
        ...

    def send(self, msg: bytes) -> None:
        """Send a binary message, potentially blocking."""
        nonce = struct.pack(">16xQ", self._send_nonce)
        self._send_nonce += 2
        data = self._box.encrypt(msg, nonce).ciphertext
        length_data = struct.pack(">Q", len(data))
        self._send(length_data + data)

    def send_json(self, msg: dict) -> None:
        """Send a message in the form of a JSON dict, potentially blocking."""
        self.send(json.dumps(msg).encode("utf-8"))

    def receive(self) -> bytes:
        """Read a binary message, blocking."""
        length_data = self._receive(8)
        if length_data[0]:
            # Lengths above 2^56 are unreasonable, so if we get one someone is
            # sending us bad data. Raise an exception to help debugging.
            raise Exception("Got unexpected data: " + repr(length_data))
        length = struct.unpack(">Q", length_data)[0]
        data = self._receive(length)
        nonce = struct.pack(">16xQ", self._receive_nonce)
        self._receive_nonce += 2
        ret: bytes = self._box.decrypt(data, nonce)
        return ret

    def receive_json(self) -> dict:
        """Read a message in the form of a JSON dict, blocking."""
        ret = json.loads(self.receive())
        if not isinstance(ret, dict):
            # We always pass dictionaries as messages and no other data types,
            # to ensure future extensibility. (Other types are rare in
            # practice, anyway.)
            raise ValueError("Top-level JSON value must be a dictionary")
        return ret


class SocketPort(Port):
    def __init__(self, sock: socket.socket, box: AnyBox, *, is_client: bool) -> None:
        self._sock = sock
        super().__init__(box, is_client=is_client)

    def _send(self, data: bytes) -> None:
        self._sock.sendall(data)

    def _receive(self, length: int) -> bytes:
        return socket_read_fixed(self._sock, length)

    def shutdown(self, how: int = socket.SHUT_RDWR) -> None:
        try:
            self._sock.shutdown(how)
        except OSError as e:
            # Ignore ENOTCONN
            if e.errno != 107:
                raise

    def close(self) -> None:
        self._sock.close()


class FilePort(Port):
    def __init__(
        self, inf: BinaryIO, outf: BinaryIO, box: AnyBox, *, is_client: bool
    ) -> None:
        self._inf = inf
        self._outf = outf
        super().__init__(box, is_client=is_client)

    def _send(self, data: bytes) -> None:
        self._outf.write(data)
        self._outf.flush()

    def _receive(self, length: int) -> bytes:
        return file_read_fixed(self._inf, length)
