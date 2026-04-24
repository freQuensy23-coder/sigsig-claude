import pytest

from sigsig.attachments import (
    ATTACHMENT_KEY_LENGTH,
    decrypt_attachment,
    encrypt_attachment,
)
from sigsig.errors import ProtocolError


def test_round_trip_small() -> None:
    pt = b"hi"
    blob, key, digest = encrypt_attachment(pt)
    assert len(key) == ATTACHMENT_KEY_LENGTH
    assert len(digest) == 32
    assert decrypt_attachment(blob, key, digest, len(pt)) == pt


def test_round_trip_binary() -> None:
    pt = bytes(range(256)) * 40
    blob, key, digest = encrypt_attachment(pt)
    assert decrypt_attachment(blob, key, digest, len(pt)) == pt


def test_digest_mismatch_rejected() -> None:
    blob, key, digest = encrypt_attachment(b"foo")
    with pytest.raises(ProtocolError, match="digest"):
        decrypt_attachment(blob, key, b"\x00" * 32, 3)


def test_mac_mismatch_rejected() -> None:
    blob, key, digest = encrypt_attachment(b"foo")
    # corrupt the inner MAC without changing the overall digest path: tamper
    # with the ciphertext region, then recompute the digest to isolate the
    # MAC check.
    import hashlib

    tampered = bytearray(blob)
    tampered[20] ^= 0x01
    new_digest = hashlib.sha256(bytes(tampered)).digest()
    with pytest.raises(ProtocolError, match="MAC"):
        decrypt_attachment(bytes(tampered), key, new_digest, 3)


def test_key_wrong_length_rejected() -> None:
    blob, _key, digest = encrypt_attachment(b"foo")
    with pytest.raises(ValueError):
        decrypt_attachment(blob, b"\x00" * 32, digest, 3)
