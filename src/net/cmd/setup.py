from argparse import ArgumentParser, Namespace
import base64
import os
import random
import string
import sys
import time
from typing import Optional

from nacl.public import SealedBox
from nacl.signing import SigningKey, VerifyKey

from .base import Command
from ..core import RawConfig, read_config, sign_with_magic, write_config
from .util import ask


class SetupCommand(Command):
    command = "setup"
    help = (
        "Set up permuter@home. This will require someone else to grant you "
        "access to the central server."
    )

    @staticmethod
    def add_arguments(parser: ArgumentParser) -> None:
        pass

    @staticmethod
    def run(args: Namespace) -> None:
        config = read_config()
        _run_initial_setup(config)


def _random_name() -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(5))


def _run_initial_setup(config: RawConfig) -> None:
    signing_key: Optional[SigningKey] = config.signing_key
    if not signing_key or not ask("Keep previous secret key", default=True):
        signing_key = SigningKey.generate()
        config.signing_key = signing_key
        write_config(config)
    verify_key = signing_key.verify_key

    nickname: Optional[str] = config.initial_setup_nickname
    if not nickname or not ask(f"Keep previous nickname [{nickname}]", default=True):
        default_nickname = os.environ.get("USER") or _random_name()
        nickname = (
            input(f"Nickname [default: {default_nickname}]: ") or default_nickname
        )
        config.initial_setup_nickname = nickname
        write_config(config)

    signed_nickname = sign_with_magic(b"NICK", signing_key, nickname.encode("utf-8"))

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
