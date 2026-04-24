"""Small stateless helpers used during linking."""

from __future__ import annotations

import base64
import secrets


def generate_password() -> str:
    """Random 18-byte base64 token — the HTTP Basic auth password."""
    return base64.b64encode(secrets.token_bytes(18)).decode("ascii")
