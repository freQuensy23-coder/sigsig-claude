"""Cryptographic primitives used by sigsig.

This subpackage contains pure-Python implementations that are safe to vendor:

- :mod:`curve25519` — X25519 DH, XEd25519 signing/verification.
- :mod:`kdf` — HKDF-SHA256 wrapper.
- :mod:`aes` — AES-256-CBC and AES-256-GCM helpers.
- :mod:`provisioning_cipher` — the AES-CBC+HMAC envelope used during QR linking.
- :mod:`double_ratchet` — the Signal Double Ratchet (session cipher).
- :mod:`sealed_sender` — the UnidentifiedSender envelope (best-effort pure Python).
"""
