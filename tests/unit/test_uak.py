import hashlib
import hmac

import pytest

from sigsig.crypto.uak import derive_access_key


def test_length() -> None:
    key = b"\x01" * 32
    assert len(derive_access_key(key)) == 16


def test_matches_reference() -> None:
    """Check against the libsignal-service definition directly."""
    profile_key = bytes(range(32))
    expected = hmac.new(profile_key, b"\x00" * 32, hashlib.sha256).digest()[:16]
    assert derive_access_key(profile_key) == expected


def test_rejects_wrong_length() -> None:
    with pytest.raises(ValueError):
        derive_access_key(b"\x01" * 31)
