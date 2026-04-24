"""HKDF-SHA256 — the key-derivation function Signal uses everywhere."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand


def hkdf(
    ikm: bytes,
    *,
    salt: bytes = b"",
    info: bytes = b"",
    length: int,
) -> bytes:
    """Extract-and-expand HKDF with SHA-256. Returns ``length`` bytes."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt if salt else None,
        info=info,
    ).derive(ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """Expand-only variant; ``prk`` must already be a pseudo-random key."""
    return HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=info,
    ).derive(prk)
