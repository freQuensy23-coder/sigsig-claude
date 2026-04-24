"""Pinned TLS trust store for Signal's chat endpoints.

Signal Messenger, LLC runs its own certificate authority — the chat.signal.org
endpoint presents a chain rooted in a Signal-owned self-signed CA, not in a
public CA that ships in Mozilla's / certifi's bundle. Every official client
(Signal-Android, Signal-iOS, Signal-Desktop, signal-cli) pins this CA; we do
the same.

The file ``signal_ca.pem`` is the self-signed root. Subject:

    C=US, ST=California, L=Mountain View, O=Signal Messenger, LLC, CN=Signal Messenger

SHA-256 fingerprint:

    DD:B0:F9:2B:B9:5C:8D:6F:D2:02:EA:6E:8C:C5:CC:D1:82:B5:44:F8:CD:69:6F:47:D5:80:65:9D:DC:9D:F6:5A

Valid until 2032-01-24.

To refresh (if Signal rotates the CA, which they've signalled they do roughly
every 10 years):

    echo | openssl s_client -servername chat.signal.org -connect chat.signal.org:443 -showcerts 2>/dev/null \\
        | awk '/BEGIN CERT/{i++} i==2' \\
        > src/sigsig/certs/signal_ca.pem
"""

from __future__ import annotations

import importlib.resources
import ssl
from functools import lru_cache


@lru_cache(maxsize=1)
def signal_ca_pem() -> bytes:
    """Return the pinned Signal CA as a PEM-encoded bytes blob."""
    return importlib.resources.files(__package__).joinpath("signal_ca.pem").read_bytes()


@lru_cache(maxsize=1)
def signal_ssl_context() -> ssl.SSLContext:
    """Build an SSL context that trusts only Signal's CA.

    Using this context is how sigsig connects to ``chat.signal.org``. The
    system trust store is **not** consulted — Signal's chain does not chain
    up to any public CA.
    """
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cadata=signal_ca_pem().decode("ascii"))
    return ctx
