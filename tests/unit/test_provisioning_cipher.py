import pytest

from sigsig.crypto import provisioning_cipher
from sigsig.crypto.curve25519 import KeyPair
from sigsig.errors import ProtocolError


def test_round_trip() -> None:
    primary = KeyPair.generate()
    secondary = KeyPair.generate()
    plaintext = b"hello from the primary device"

    body = provisioning_cipher.encrypt(
        plaintext, their_public=secondary.public, our_keypair=primary
    )
    out = provisioning_cipher.decrypt(
        body, their_public=primary.public, our_private=secondary.private
    )
    assert out == plaintext


def test_round_trip_empty() -> None:
    primary = KeyPair.generate()
    secondary = KeyPair.generate()
    body = provisioning_cipher.encrypt(
        b"", their_public=secondary.public, our_keypair=primary
    )
    out = provisioning_cipher.decrypt(
        body, their_public=primary.public, our_private=secondary.private
    )
    assert out == b""


def test_round_trip_large() -> None:
    primary = KeyPair.generate()
    secondary = KeyPair.generate()
    plaintext = b"A" * 4096
    body = provisioning_cipher.encrypt(
        plaintext, their_public=secondary.public, our_keypair=primary
    )
    out = provisioning_cipher.decrypt(
        body, their_public=primary.public, our_private=secondary.private
    )
    assert out == plaintext


def test_bad_mac_rejected() -> None:
    primary = KeyPair.generate()
    secondary = KeyPair.generate()
    body = bytearray(
        provisioning_cipher.encrypt(
            b"x", their_public=secondary.public, our_keypair=primary
        )
    )
    # Flip a bit inside the MAC region.
    body[-1] ^= 0x01
    with pytest.raises(ProtocolError, match="MAC mismatch"):
        provisioning_cipher.decrypt(
            bytes(body), their_public=primary.public, our_private=secondary.private
        )


def test_wrong_peer_key_rejected() -> None:
    primary = KeyPair.generate()
    secondary = KeyPair.generate()
    attacker = KeyPair.generate()
    body = provisioning_cipher.encrypt(
        b"x", their_public=secondary.public, our_keypair=primary
    )
    with pytest.raises(ProtocolError):
        provisioning_cipher.decrypt(
            body, their_public=attacker.public, our_private=secondary.private
        )


def test_unsupported_version() -> None:
    primary = KeyPair.generate()
    secondary = KeyPair.generate()
    body = bytearray(
        provisioning_cipher.encrypt(
            b"x", their_public=secondary.public, our_keypair=primary
        )
    )
    body[0] = 0x02
    with pytest.raises(ProtocolError, match="version"):
        provisioning_cipher.decrypt(
            bytes(body), their_public=primary.public, our_private=secondary.private
        )
