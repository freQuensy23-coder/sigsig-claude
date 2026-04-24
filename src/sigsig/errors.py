"""Exception hierarchy for sigsig."""

from __future__ import annotations


class SigsigError(Exception):
    """Base class for every error raised by sigsig."""


class TransportError(SigsigError):
    """Network-level failure (connection, TLS, WebSocket disconnect)."""


class ServerError(SigsigError):
    """The Signal server rejected a request with a non-success status."""

    def __init__(self, status: int, message: str, body: bytes | None = None) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.body = body


class ProvisioningError(SigsigError):
    """Something went wrong during the QR linked-device flow."""


class ProtocolError(SigsigError):
    """The remote violated the Signal protocol (bad MAC, bad signature, etc.)."""


class SessionError(SigsigError):
    """Problem loading/saving the on-disk session."""


class MismatchedDevices(SigsigError):
    """The server reports the sender has an out-of-date device list for a recipient.

    Raised on HTTP 409. Caller should fetch fresh prekeys for ``missing`` and
    retry (and drop sessions to ``extra``).
    """

    def __init__(self, missing: list[int], extra: list[int]) -> None:
        super().__init__(f"mismatched devices: missing={missing} extra={extra}")
        self.missing = missing
        self.extra = extra


class StaleDevices(SigsigError):
    """The server reports some of the sender's own devices are stale.

    Raised on HTTP 410.
    """

    def __init__(self, stale: list[int]) -> None:
        super().__init__(f"stale devices: {stale}")
        self.stale = stale


class AuthenticationFailed(SigsigError):
    """The server rejected our credentials (HTTP 401/403)."""
