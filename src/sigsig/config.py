"""Static production configuration (Signal server URLs, trust roots, user agent)."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

PACKAGE_VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# Live environment
# ---------------------------------------------------------------------------

CHAT_SERVICE_URL = "https://chat.signal.org"
CHAT_WS_URL = "wss://chat.signal.org"
STORAGE_SERVICE_URL = "https://storage.signal.org"
CDN0_URL = "https://cdn.signal.org"
CDN2_URL = "https://cdn2.signal.org"
CDN3_URL = "https://cdn3.signal.org"
CDSI_URL = "https://cdsi.signal.org"

# WebSocket paths (see libsignal/rust/net/src/env.rs:869-870).
AUTHENTICATED_WS_PATH = "/v1/websocket/"
PROVISIONING_WS_PATH = "/v1/websocket/provisioning/"
KEEPALIVE_PATH = "/v1/keepalive"

# The Curve25519 public key signal-server uses to sign SenderCertificates
# (signal-cli LiveConfig.java:28-31).
UNIDENTIFIED_SENDER_TRUST_ROOT = base64.b64decode(
    "BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF"
)
UNIDENTIFIED_SENDER_TRUST_ROOT2 = base64.b64decode(
    "BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6"
)

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

PRIMARY_DEVICE_ID = 1
DEFAULT_DEVICE_ID = 1

# How many one-time prekeys to upload at first linking and when refilling.
PREKEY_BATCH_SIZE = 100
# Ask the server to report low prekey counts at this threshold.
PREKEY_MINIMUM_COUNT = 10

# HKDF info string used by Signal's ProvisioningCipher (since long before v1).
PROVISIONING_INFO = b"TextSecure Provisioning Message"

# HKDF derived keys are 32 bytes cipher + 32 bytes MAC.
PROVISIONING_KEY_MATERIAL_BYTES = 64

# The WebSocket keepalive interval the server expects (signal-cli uses 30s).
KEEPALIVE_INTERVAL_S = 30.0

# How often the server's queue-empty push triggers us to refill one-time
# prekeys if we've dropped below PREKEY_MINIMUM_COUNT.
PREKEY_REFILL_THRESHOLD = 10


# ---------------------------------------------------------------------------
# User agent
# ---------------------------------------------------------------------------

USER_AGENT = f"Signal-Android/8.8.0 sigsig/{PACKAGE_VERSION}"
SIGNAL_AGENT = "sigsig"


# ---------------------------------------------------------------------------
# Capability advertisement — sent in AccountAttributes when linking.
# Lines up with the capability flags signal-cli sets (spqr, storage, etc.).
# ---------------------------------------------------------------------------

DEFAULT_CAPABILITIES: dict[str, bool] = {
    "storage": True,
    "versionedExpirationTimer": True,
    "attachmentBackfill": True,
    "spqr": True,
}


@dataclass(frozen=True, slots=True)
class Environment:
    """Bundle of all endpoints for a given deployment.

    Swap out for a staging ``Environment`` when testing against a dev server.
    """

    chat_http_url: str = CHAT_SERVICE_URL
    chat_ws_url: str = CHAT_WS_URL
    storage_url: str = STORAGE_SERVICE_URL
    cdn_urls: dict[int, str] = field(
        default_factory=lambda: {0: CDN0_URL, 2: CDN2_URL, 3: CDN3_URL}
    )
    cdsi_url: str = CDSI_URL
    unidentified_sender_trust_root: bytes = UNIDENTIFIED_SENDER_TRUST_ROOT


LIVE = Environment()
