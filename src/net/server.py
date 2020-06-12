from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey
import nacl.util


def talk_to_client() -> None:
    # TODO: read from config
    server_verify_key = SigningKey.generate().verify_key
    signing_key = SigningKey.generate()

    # TODO: receive from client
    msg = b""

    ver_key = VerifyKey(msg[:32])
    ephemeral_key = ver_key.verify(msg[32:])
    box = Box(signing_key.to_curve25519_private_key(), ephemeral_key)
    port = Port(box, is_client=False)
    rand = nacl.util.random(32)
    port.send(rand)
    msg = port.receive()
    assert msg[:32] == rand
    granted_request = server_verify_key.verify(msg[32:])
    assert granted_request[:32] == ver_key
    request = granted_request[32:]
    assert abs(time.time() - int(request["time"])) < 5 * 60
    resp = {
        "status": "ok",
    }
    port.send(json.dumps(resp).encode("utf-8"))
