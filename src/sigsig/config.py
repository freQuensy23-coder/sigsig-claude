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

# Public params of Signal's zkgroup server, used to verify AuthCredentialWithPni
# responses and build group-auth presentations. From signal-cli LiveConfig.java.
ZKGROUP_SERVER_PUBLIC_PARAMS = base64.b64decode(
    "AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR3"
    "1IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn"
    "+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X36"
    "nOoGPs54XsEGzPdEV+itQNGUFEjY6X9Uv+Acuks7NpyGvCoKxGwgKgE5XyJ+nNKlyHHOLb6N"
    "1NuHyBrZrgtY/JYJHRooo5CEqYKBqdFnmbTVGEkCvJKxLnjwKWf+fEPoWeQFj5ObDjcKMZf2"
    "Jm2Ae69x+ikU5gBXsRmoF94GXTLfN0/vLt98KDPnxwAQL9j5V1jGOY8jQl6MLxEs56cwXN0d"
    "qCnImzVH3TZT1cJ8SW1BRX6qIVxEzjsSGx3yxF3suAilPMqGRp4ffyopjMD1JXiKR2RwLKzi"
    "zUe5e8XyGOy9fplzhw3jVzTRyUZTRSZKkMLWcQ/gv0E4aONNqs4P+NameAZYOD12qRkxosQQ"
    "P5uux6B2nRyZ7sAV54DgFyLiRcq1FvwKw2EPQdk4HDoePrO/RNUbyNddnM/mMgj4FW65xCoT"
    "1LmjrIjsv/Ggdlx46ueczhMgtBunx1/w8k8V+l8LVZ8gAT6wkU5J+DPQalQguMg12Jzug3q4"
    "TbdHiGCmD9EunCwOmsLuLJkz6EcSYXtrlDEnAM+hicw7iergYLLlMXpfTdGxJCWJmP4zqUFe"
    "TTmsmhsjGBt7NiEB/9pFFEB3pSbf4iiUukw63Eo8Aqnf4iwob6X1QviCWuc8t0LUlT9vALgh"
    "/f2DPVOOmR0RW6bgRvc7DSF20V/omg+YBw=="
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


# /v2/groups/… lives on storage.signal.org (see PushServiceSocket.java
# makeStorageRequest usage).
GROUPS_V2_HOST = STORAGE_SERVICE_URL


@dataclass(frozen=True, slots=True)
class Environment:
    """Bundle of all endpoints for a given deployment."""

    chat_http_url: str = CHAT_SERVICE_URL
    chat_ws_url: str = CHAT_WS_URL
    storage_url: str = STORAGE_SERVICE_URL
    cdn_urls: dict[int, str] = field(
        default_factory=lambda: {0: CDN0_URL, 2: CDN2_URL, 3: CDN3_URL}
    )
    cdsi_url: str = CDSI_URL
    unidentified_sender_trust_root: bytes = UNIDENTIFIED_SENDER_TRUST_ROOT


LIVE = Environment()
