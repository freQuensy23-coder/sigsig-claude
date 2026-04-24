"""AES helpers — CBC+PKCS7 for ProvisioningCipher, GCM for session payloads."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-256-CBC with PKCS#7 padding."""
    if len(key) != 32:
        raise ValueError("AES-256-CBC needs a 32-byte key")
    if len(iv) != 16:
        raise ValueError("AES-CBC needs a 16-byte IV")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256-CBC needs a 32-byte key")
    if len(iv) != 16:
        raise ValueError("AES-CBC needs a 16-byte IV")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad if aad else None)


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad if aad else None)


def random_iv() -> bytes:
    return os.urandom(16)


def random_nonce() -> bytes:
    """12-byte nonce for AES-GCM."""
    return os.urandom(12)
