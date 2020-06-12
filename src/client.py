import base64
import os
import random
import string
import sys
from typing import Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.public import SealedBox, PrivateKey, PublicKey


def random_string() -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(5))


def ask(msg: str, *, default: bool) -> bool:
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


def initial_setup() -> None:
    signing_key: Optional[SigningKey] = None
    # TODO: read from config
    if not signing_key or not ask("Keep previous secret key", default=True):
        # TODO: signature key
        signing_key = SigningKey.generate()
        # TODO: write to config
    verify_key = signing_key.verify_key

    nickname: Optional[str] = None
    # TODO: read from config
    if not nickname or not ask(f"Keep previous nickname {nickname}", default=True):
        default_nickname = os.environ.get("USER") or random_string()
        nickname = (
            input(f"Nickname [default: {default_nickname}]: ") or default_nickname
        )
        # TODO: write to config

    enc_secret_key = signing_key.to_curve25519_private_key()
    enc_public_key = enc_secret_key.public_key
    signed_nickname = signing_key.sign(nickname.encode("utf-8"))

    vouch_data = verify_key.encode() + enc_public_key.encode() + signed_nickname
    vouch_text = base64.b64encode(vouch_data).decode("utf-8")
    print("Ask someone to run the following command:")
    print(f"./permuter.py -J --vouch {vouch_text}")
    print()
    print("They should give you a token back in return. Paste that here:")
    inp = input().strip()

    try:
        token = base64.b64decode(inp.encode("utf-8"))
        url = SealedBox(enc_secret_key).decrypt(token).decode("utf-8")
        print("Server URL:", url)
        # TODO: verify that contacting server works
        # TODO: write to config
    except Exception:
        print("Invalid token!")


def vouch(vouch_text: str) -> None:
    # TODO: read from config or bail
    server_url = ""
    signing_key = SigningKey.generate()

    try:
        vouch_data = base64.b64decode(vouch_text.encode("utf-8"))
        verify_key = VerifyKey(vouch_data[:32])
        enc_public_key = PublicKey(vouch_data[32:64])
        signed_nickname = vouch_data[64:]
        nickname = verify_key.verify(signed_nickname)
    except Exception:
        print("Could not parse data!")
        return

    if not ask(f"Grant permuter server access to {nickname}", default=True):
        return

    # TODO: send signature and signed nickname to central server

    token = SealedBox(enc_public_key).encrypt(server_url)
    print("Granted!")
    print()
    print("Send them the following token:")
    print(base64.b64encode(token).decode("utf-8"))
