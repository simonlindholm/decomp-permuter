import abc
from dataclasses import dataclass
import json
import socket
import struct
import sys
import toml
import traceback
from typing import BinaryIO, List, Optional, Tuple, Type, TypeVar, Union

from nacl.encoding import HexEncoder
from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey

from ..error import ServerError

T = TypeVar("T")
AnyBox = Union[Box, SecretBox]

PERMUTER_VERSION = 1

CONFIG_FILENAME = "pah.conf"

MIN_PRIO = 0.01
MAX_PRIO = 2.0


@dataclass
class Config:
    server_address: Optional[str] = None
    server_verify_key: Optional[VerifyKey] = None
    signing_key: Optional[SigningKey] = None
    initial_setup_nickname: Optional[str] = None


def exception_to_string(e: object) -> str:
    return str(e) or e.__class__.__name__


def read_config() -> Config:
    config = Config()
    try:
        with open(CONFIG_FILENAME) as f:
            obj = toml.load(f)

        def read(key: str, t: Type[T]) -> Optional[T]:
            ret = obj.get(key)
            return ret if isinstance(ret, t) else None

        temp = read("server_public_key", str)
        if temp:
            config.server_verify_key = VerifyKey(HexEncoder.decode(temp))
        temp = read("secret_key", str)
        if temp:
            config.signing_key = SigningKey(HexEncoder.decode(temp))
        config.initial_setup_nickname = read("initial_setup_nickname", str)
        config.server_address = read("server_address", str)
    except FileNotFoundError:
        pass
    except Exception:
        print(f"Malformed configuration file {CONFIG_FILENAME}.\n")
        raise
    return config


def write_config(config: Config) -> None:
    obj = {}

    def write(key: str, val: Union[None, str, int]) -> None:
        if val is not None:
            obj[key] = val

    write("initial_setup_nickname", config.initial_setup_nickname)
    write("server_address", config.server_address)

    key_hex: bytes
    if config.server_verify_key:
        key_hex = config.server_verify_key.encode(HexEncoder)
        write("server_public_key", key_hex.decode("utf-8"))
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
    except EOFError:
        raise
    except Exception as e:
        raise EOFError from e


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
    except EOFError:
        raise
    except Exception as e:
        raise EOFError from e


def socket_shutdown(sock: socket.socket, how: int) -> None:
    try:
        sock.shutdown(how)
    except Exception:
        pass


def json_prop(obj: dict, prop: str, t: Type[T]) -> T:
    ret = obj.get(prop)
    if not isinstance(ret, t):
        found_type = type(ret).__name__
        raise ValueError(f"Member {prop} must have type {t.__name__}; got {found_type}")
    return ret


def json_array(obj: list, t: Type[T]) -> List[T]:
    for elem in obj:
        if not isinstance(elem, t):
            found_type = type(elem).__name__
            raise ValueError(
                f"Array elements must have type {t.__name__}; got {found_type}"
            )
    return obj


def sign_with_magic(magic: bytes, signing_key: SigningKey, data: bytes) -> bytes:
    signature: bytes = signing_key.sign(magic + b":" + data).signature
    return signature + data


def verify_with_magic(magic: bytes, verify_key: VerifyKey, data: bytes) -> bytes:
    if len(data) < 64:
        raise ValueError("String is too small to contain a signature")
    signature = data[:64]
    data = data[64:]
    verify_key.verify(magic + b":" + data, signature)
    return data


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
        if isinstance(ret, str):
            # Raw strings indicate errors.
            raise ServerError(ret)
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
        socket_shutdown(self._sock, how)

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


def _do_connect(config: Config) -> SocketPort:
    if (
        not config.server_verify_key
        or not config.signing_key
        or not config.server_address
    ):
        print(
            "Using permuter@home requires someone to give you access to a central -J server.\n"
            "Run `./pah.py setup` to set this up."
        )
        print()
        sys.exit(1)

    host, port_str = config.server_address.split(":")
    sock = socket.create_connection((host, int(port_str)))

    # Send over the protocol version and an ephemeral encryption key which we
    # are going to use for all communication.
    ephemeral_key = PrivateKey.generate()
    ephemeral_key_data = ephemeral_key.public_key.encode()
    sock.sendall(b"p@h0" + ephemeral_key_data)

    # Receive the server's encryption key, plus a signature of it and our own
    # ephemeral key -- this guarantees that we are talking to the server and
    # aren't victim to a replay attack. Use it to set up a communication port.
    msg = socket_read_fixed(sock, 32 + 64)
    server_enc_key_data = msg[:32]
    config.server_verify_key.verify(
        b"HELLO:" + ephemeral_key_data + server_enc_key_data, msg[32:]
    )
    box = Box(ephemeral_key, PublicKey(server_enc_key_data))
    port = SocketPort(sock, box, is_client=True)

    # Use the encrypted port to send over our public key, proof that we are
    # able to sign new things with it, as well as permuter version.
    signature: bytes = config.signing_key.sign(
        b"WORLD:" + server_enc_key_data
    ).signature
    port.send(
        config.signing_key.verify_key.encode()
        + signature
        + struct.pack(">I", PERMUTER_VERSION)
    )

    # Get an acknowledgement that the server wants to talk to us.
    obj = port.receive_json()

    if "message" in obj:
        print(obj["message"])

    return port


def connect(config: Optional[Config] = None) -> SocketPort:
    try:
        if not config:
            config = read_config()
        return _do_connect(config)
    except ServerError as e:
        print(f"Failed to connect: {e.message}")
        sys.exit(1)
    except Exception as e:
        print(f"Failed to connect.")
        traceback.print_exc()
        sys.exit(1)
    print("Connected!")
