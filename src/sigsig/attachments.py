"""Signal attachment encryption / decryption.

Wire format produced by ``AttachmentCipherStreamUtil`` /
``AttachmentCipherOutputStream`` in libsignal-service-java:

    blob = IV(16) || AES-256-CBC(PKCS7, padded_plaintext, aes_key, iv)
                   || HMAC-SHA256(hmac_key, IV || ciphertext)[0..32]

- ``key`` in ``AttachmentPointer`` is 64 bytes: ``aes_key(32) || hmac_key(32)``.
- ``digest`` in ``AttachmentPointer`` is ``SHA-256(blob)`` — recipients verify
  it matches the downloaded bytes before decrypting.
- ``size`` is the unpadded plaintext length. The recipient pads to the
  same bucket size (``_padded_size``) and trims back after decrypt.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import mimetypes
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from sigsig.errors import ProtocolError


IV_LENGTH = 16
AES_KEY_LENGTH = 32
HMAC_KEY_LENGTH = 32
MAC_LENGTH = 32
ATTACHMENT_KEY_LENGTH = AES_KEY_LENGTH + HMAC_KEY_LENGTH  # 64


def _padded_size(plaintext_length: int) -> int:
    """Signal's ``PaddingInputStream.getPaddedSize``: bucket sizes on a 1.05
    geometric curve, with a floor of 541."""
    if plaintext_length <= 0:
        return 541
    exp = math.ceil(math.log(plaintext_length) / math.log(1.05))
    return max(541, int(math.floor(math.pow(1.05, exp))))


def encrypt_attachment(plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt + MAC + digest a plaintext.

    Returns ``(blob, key, digest)`` where ``key`` is the 64-byte
    ``aes_key || hmac_key`` suitable for ``AttachmentPointer.key``.
    """
    aes_key = os.urandom(AES_KEY_LENGTH)
    hmac_key = os.urandom(HMAC_KEY_LENGTH)
    iv = os.urandom(IV_LENGTH)

    padded = plaintext + b"\x00" * (_padded_size(len(plaintext)) - len(plaintext))
    padder = padding.PKCS7(128).padder()
    pkcs7_padded = padder.update(padded) + padder.finalize()

    enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ciphertext = enc.update(pkcs7_padded) + enc.finalize()

    mac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    blob = iv + ciphertext + mac
    digest = hashlib.sha256(blob).digest()
    return blob, aes_key + hmac_key, digest


def decrypt_attachment(blob: bytes, key: bytes, digest: bytes, plaintext_size: int) -> bytes:
    """Inverse of :func:`encrypt_attachment`. Raises on MAC / digest mismatch."""
    if len(key) != ATTACHMENT_KEY_LENGTH:
        raise ValueError(f"attachment key must be {ATTACHMENT_KEY_LENGTH} bytes")
    if hashlib.sha256(blob).digest() != digest:
        raise ProtocolError("attachment digest mismatch")
    if len(blob) < IV_LENGTH + MAC_LENGTH:
        raise ProtocolError(f"attachment blob too short ({len(blob)} bytes)")

    aes_key = key[:AES_KEY_LENGTH]
    hmac_key = key[AES_KEY_LENGTH:]
    iv = blob[:IV_LENGTH]
    ciphertext = blob[IV_LENGTH : len(blob) - MAC_LENGTH]
    mac = blob[len(blob) - MAC_LENGTH :]

    expected_mac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ProtocolError("attachment MAC mismatch")

    dec = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded_plaintext = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    pkcs_stripped = unpadder.update(padded_plaintext) + unpadder.finalize()
    # Signal also zero-pads to the bucket size before PKCS7; trim to declared size.
    return pkcs_stripped[:plaintext_size]


# ---------------------------------------------------------------------------
# Outbound attachment inputs
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class Attachment:
    """An attachment to include in an outgoing message.

    Build via :classmethod:`from_file` or :classmethod:`from_bytes`.
    """

    data: bytes
    content_type: str
    file_name: str | None = None
    caption: str | None = None
    width: int | None = None
    height: int | None = None

    @classmethod
    def from_file(
        cls,
        path: str | os.PathLike[str],
        *,
        content_type: str | None = None,
        file_name: str | None = None,
        caption: str | None = None,
    ) -> "Attachment":
        p = Path(path).expanduser()
        data = p.read_bytes()
        ct = content_type or mimetypes.guess_type(p.name)[0] or "application/octet-stream"
        return cls(data=data, content_type=ct, file_name=file_name or p.name, caption=caption)

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
        file_name: str | None = None,
        caption: str | None = None,
    ) -> "Attachment":
        return cls(data=data, content_type=content_type, file_name=file_name, caption=caption)


@dataclass(slots=True, frozen=True)
class InboundAttachment:
    """An attachment referenced in an inbound message.

    The encrypted blob lives on the CDN; call :meth:`download` to fetch +
    decrypt + verify the bytes.
    """

    cdn_key: str
    cdn_number: int
    key: bytes
    digest: bytes
    size: int
    content_type: str
    file_name: str | None
    caption: str | None
    width: int
    height: int
    _downloader: "AttachmentDownloader"

    async def download(self) -> bytes:
        return await self._downloader.download(self)


class AttachmentDownloader:
    """Interface used by :class:`InboundAttachment.download`."""

    async def download(self, att: "InboundAttachment") -> bytes:  # pragma: no cover - interface
        raise NotImplementedError
