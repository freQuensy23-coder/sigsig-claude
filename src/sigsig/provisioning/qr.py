"""QR URL construction + ASCII rendering.

Signal's secondary device renders the following URL as a QR code for the
primary to scan:

    sgnl://linkdevice?uuid={session_uuid}&pub_key={b64_no_padding(pubkey)}

- ``session_uuid`` is the opaque ``ProvisioningAddress.address`` string the
  server assigns over the provisioning WebSocket.
- ``pub_key`` is the secondary's temporary Curve25519 public key
  (``PublicKey.serialize()`` — 33 bytes including the 0x05 tag),
  base64-encoded **without padding** (stripped ``=``).

See signal-cli ``DeviceLinkUrl.java:47-57``.
"""

from __future__ import annotations

import base64
import urllib.parse

import qrcode

from sigsig.crypto.curve25519 import PublicKey


def _b64_no_padding(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def build_link_url(*, session_uuid: str, public_key: PublicKey) -> str:
    """Build the ``sgnl://linkdevice`` URL.

    Matches signal-cli ``DeviceLinkUrl.java:47-57``: both the uuid and the
    padding-stripped base64 pub_key are URL-encoded (``URLEncoder.encode``)
    before being spliced into the query string. Signal's QR-code scanner
    decodes the URL-encoded values back to their raw form.
    """
    pub = _b64_no_padding(public_key.serialize())
    # Use quote with no safe characters so "+" and "/" in base64 and "="
    # in the uuid all get percent-encoded — matching Java's URLEncoder.
    return (
        "sgnl://linkdevice?uuid="
        + urllib.parse.quote(session_uuid, safe="")
        + "&pub_key="
        + urllib.parse.quote(pub, safe="")
    )


def render_qr_ascii(url: str, *, border: int = 1, invert: bool = False) -> str:
    """Return the given URL rendered as a terminal-friendly QR code.

    ``invert=True`` swaps foreground / background. Useful on dark-theme
    terminals where a naive render produces light modules on dark ground —
    which Signal's scanner (and most scanners) reject because QR specs
    require dark modules on a light background.
    """
    q = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=1,
        border=border,
    )
    q.add_data(url)
    q.make(fit=True)

    matrix = q.get_matrix()
    if invert:
        matrix = [[not cell for cell in row] for row in matrix]
    lines: list[str] = []
    row_iter = iter(matrix)
    for top in row_iter:
        bottom = next(row_iter, [False] * len(top))
        line_chars: list[str] = []
        for t, b in zip(top, bottom, strict=False):
            if t and b:
                line_chars.append("█")
            elif t and not b:
                line_chars.append("▀")
            elif (not t) and b:
                line_chars.append("▄")
            else:
                line_chars.append(" ")
        lines.append("".join(line_chars))
    return "\n".join(lines)


def save_qr_image(url: str, path: str, *, box_size: int = 10, border: int = 4) -> str:
    """Render ``url`` as a QR code image on disk. Returns the resolved path.

    The file format is decided by the extension (``.png``, ``.jpg`` /
    ``.jpeg`` / ``.bmp`` supported by PIL). Always black modules on white
    background — the canonical orientation QR scanners expect.
    """
    import os.path

    ext = os.path.splitext(path)[1].lower().lstrip(".") or "png"
    # qrcode.make returns a PIL Image.
    img = qrcode.make(
        url,
        box_size=box_size,
        border=border,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
    )
    # PIL's JPEG encoder refuses 1-bit images; convert to RGB for JPEG.
    if ext in ("jpg", "jpeg"):
        img = img.convert("RGB")
        img.save(path, format="JPEG", quality=95)
    else:
        img.save(path)
    return path
