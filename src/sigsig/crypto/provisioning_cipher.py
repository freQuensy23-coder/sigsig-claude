"""The encryption envelope used during the QR linked-device flow.

Primary and secondary derive a shared DH secret from Curve25519 public keys
exchanged over the provisioning WebSocket (secondary's key is embedded in
the QR URL; primary's key rides with the ``ProvisionEnvelope``). From that
shared secret HKDF-SHA256 produces a 32-byte AES-CBC key and a 32-byte
HMAC-SHA256 key. The serialized inner ``ProvisionMessage`` is then framed as

    0x01 || IV(16) || AES-256-CBC(ProvisionMessage) || HMAC-SHA256-truncated(...)

The trailing MAC covers the ``version`` byte, the IV and the ciphertext.

This is the one cipher we can safely reimplement in pure Python because the
outer framing is explicit and the keys live only for the duration of the
link — if we get the format wrong, linking simply fails with a bad-MAC
error; there's no silent corruption risk.

Reference: signal-cli ``ProvisioningManagerImpl.java:101-149`` and
Signal-Android ``ProvisioningCipher.java``.
"""

from __future__ import annotations

import hashlib
import hmac

from sigsig.config import PROVISIONING_INFO, PROVISIONING_KEY_MATERIAL_BYTES
from sigsig.crypto.aes import aes_cbc_decrypt, aes_cbc_encrypt, random_iv
from sigsig.crypto.curve25519 import KeyPair, PrivateKey, PublicKey
from sigsig.crypto.kdf import hkdf
from sigsig.errors import ProtocolError

VERSION = 0x01
MAC_LENGTH = 32
# HMAC output is truncated to 32 bytes on the wire.
TRUNCATED_MAC_LENGTH = 32


def _derive_keys(shared_secret: bytes) -> tuple[bytes, bytes]:
    """Run HKDF over the DH output to produce (aes_key, hmac_key)."""
    material = hkdf(
        shared_secret,
        salt=b"",
        info=PROVISIONING_INFO,
        length=PROVISIONING_KEY_MATERIAL_BYTES,
    )
    return material[:32], material[32:]


def encrypt(
    plaintext: bytes,
    *,
    their_public: PublicKey,
    our_keypair: KeyPair,
) -> bytes:
    """Produce the ``body`` field of a ProvisionEnvelope.

    The caller sends the envelope with ``publicKey = our_keypair.public`` and
    this return value as ``body``.
    """
    shared = our_keypair.private.agree(their_public)
    aes_key, mac_key = _derive_keys(shared)
    iv = random_iv()
    ciphertext = aes_cbc_encrypt(aes_key, iv, plaintext)
    version = bytes([VERSION])
    mac = hmac.new(mac_key, version + iv + ciphertext, hashlib.sha256).digest()
    return version + iv + ciphertext + mac[:TRUNCATED_MAC_LENGTH]


def decrypt(
    body: bytes,
    *,
    their_public: PublicKey,
    our_private: PrivateKey,
) -> bytes:
    """Parse the outer framing and return the plaintext ProvisionMessage.

    Raises :class:`ProtocolError` on bad version or MAC.
    """
    if len(body) < 1 + 16 + TRUNCATED_MAC_LENGTH:
        raise ProtocolError(f"provisioning body too short ({len(body)} bytes)")
    if body[0] != VERSION:
        raise ProtocolError(f"unsupported provisioning version {body[0]:#x}")

    mac = body[-TRUNCATED_MAC_LENGTH:]
    version_iv_ct = body[:-TRUNCATED_MAC_LENGTH]
    iv = version_iv_ct[1:17]
    ciphertext = version_iv_ct[17:]

    shared = our_private.agree(their_public)
    aes_key, mac_key = _derive_keys(shared)
    expected = hmac.new(mac_key, version_iv_ct, hashlib.sha256).digest()[:TRUNCATED_MAC_LENGTH]
    if not hmac.compare_digest(mac, expected):
        raise ProtocolError("provisioning MAC mismatch")
    return aes_cbc_decrypt(aes_key, iv, ciphertext)
