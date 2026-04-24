"""UnidentifiedAccessKey derivation.

For sealed-sender messages the sender attaches an ``Unidentified-Access-Key``
HTTP header whose value is HMAC-SHA256 of 32 zero bytes under the recipient's
32-byte profile key, truncated to 16 bytes.

See signal-cli ``UnidentifiedAccessHelper.java:159`` and
``org.whispersystems.signalservice.api.crypto.UnidentifiedAccess``.
"""

from __future__ import annotations

import hashlib
import hmac

PROFILE_KEY_LENGTH = 32
ACCESS_KEY_LENGTH = 16


def derive_access_key(profile_key: bytes) -> bytes:
    if len(profile_key) != PROFILE_KEY_LENGTH:
        raise ValueError(f"profile key must be {PROFILE_KEY_LENGTH} bytes")
    tag = hmac.new(profile_key, b"\x00" * 32, hashlib.sha256).digest()
    return tag[:ACCESS_KEY_LENGTH]
