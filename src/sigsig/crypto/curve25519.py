"""Curve25519 operations with libsignal-compatible wire format.

A public key is 32 bytes on the wire but the Signal protocol prepends a
1-byte "DJB" type tag (``0x05``) when serialising — so
``PublicKey.serialize()`` is 33 bytes. :meth:`PublicKey.deserialize` accepts
either length.

Signatures
----------

libsignal signs with **XEd25519**: the X25519 private scalar doubles as an
Ed25519 signing scalar. Implementing XEd25519 in pure Python (without a
wire format libsignal-compatible) is possible but tricky, and the wire
format **matters** — remote Signal clients will validate signed-prekey
signatures using XEd25519 against the X25519 identity public.

For now we produce signatures using **plain Ed25519 with the X25519 scalar
as the Ed25519 seed**. These signatures round-trip inside sigsig (tests,
mock server) via :meth:`PrivateKey.self_verify`, but they are **not**
interoperable with real Signal peers. Swapping in a libsignal binding
replaces this module unchanged — the API stays put.
"""

from __future__ import annotations

from dataclasses import dataclass

import nacl.signing
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

DJB_TYPE = 0x05
PUBLIC_KEY_WIRE_LENGTH = 33
PRIVATE_KEY_LENGTH = 32
SIGNATURE_LENGTH = 64


@dataclass(frozen=True, slots=True)
class PublicKey:
    """A 32-byte Curve25519 (X25519) public key."""

    raw: bytes  # 32 bytes, no DJB tag

    def __post_init__(self) -> None:
        if len(self.raw) != 32:
            raise ValueError(f"expected 32-byte key, got {len(self.raw)}")

    def serialize(self) -> bytes:
        """Wire format: 0x05 || 32-byte point."""
        return bytes([DJB_TYPE]) + self.raw

    @classmethod
    def deserialize(cls, data: bytes) -> "PublicKey":
        if len(data) == 32:
            return cls(data)
        if len(data) == PUBLIC_KEY_WIRE_LENGTH:
            if data[0] != DJB_TYPE:
                raise ValueError(f"unsupported key type {data[0]:#x}")
            return cls(data[1:])
        raise ValueError(f"unexpected public-key length {len(data)}")


@dataclass(frozen=True, slots=True)
class PrivateKey:
    """A 32-byte Curve25519 private scalar."""

    raw: bytes

    def __post_init__(self) -> None:
        if len(self.raw) != PRIVATE_KEY_LENGTH:
            raise ValueError(f"expected 32-byte private key, got {len(self.raw)}")

    def serialize(self) -> bytes:
        return self.raw

    def public_key(self) -> PublicKey:
        pub = X25519PrivateKey.from_private_bytes(self.raw).public_key()
        return PublicKey(pub.public_bytes(Encoding.Raw, PublicFormat.Raw))

    def agree(self, peer: PublicKey) -> bytes:
        """X25519 Diffie-Hellman shared secret."""
        sk = X25519PrivateKey.from_private_bytes(self.raw)
        pk = X25519PublicKey.from_public_bytes(peer.raw)
        return sk.exchange(pk)

    def sign(self, message: bytes) -> bytes:
        """Sign ``message`` with this private scalar as an Ed25519 seed.

        Not libsignal-wire-compatible; see module docstring.
        """
        return bytes(nacl.signing.SigningKey(self.raw).sign(message).signature)

    def self_verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature we produced. Requires the private key."""
        verify_key = nacl.signing.SigningKey(self.raw).verify_key
        try:
            verify_key.verify(message, signature)
            return True
        except Exception:  # noqa: BLE001
            return False


# ---------------------------------------------------------------------------
# Keypair factories
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KeyPair:
    """An X25519 private+public pair."""

    private: PrivateKey
    public: PublicKey

    @classmethod
    def generate(cls) -> "KeyPair":
        sk = X25519PrivateKey.generate()
        priv = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return cls(PrivateKey(priv), PublicKey(pub))

    @classmethod
    def from_private(cls, private: PrivateKey | bytes) -> "KeyPair":
        priv = private if isinstance(private, PrivateKey) else PrivateKey(private)
        return cls(priv, priv.public_key())


@dataclass(frozen=True, slots=True)
class IdentityKeyPair:
    """A long-lived X25519 keypair used as a Signal account identity.

    Same bytes as :class:`KeyPair`; the separate name mirrors libsignal so
    callers can't mix identity keys up with ephemeral ones.
    """

    private: PrivateKey
    public: PublicKey

    @classmethod
    def generate(cls) -> "IdentityKeyPair":
        kp = KeyPair.generate()
        return cls(kp.private, kp.public)

    @classmethod
    def from_bytes(cls, public: bytes, private: bytes) -> "IdentityKeyPair":
        # Accept either raw 32-byte or tagged 33-byte public key.
        pub = PublicKey.deserialize(public)
        return cls(PrivateKey(private[-32:]), pub)

    def to_keypair(self) -> KeyPair:
        return KeyPair(self.private, self.public)
