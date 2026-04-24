"""CDN HTTP client — upload to cdn2/cdn3.signal.org, download from any cdn.

Upload path (CDN3 TUS "creation-with-upload", the modern one):

    POST <signed_upload_url>
    Upload-Length: <size>
    Tus-Resumable: 1.0.0
    Content-Type: application/offset+octet-stream
    <all of uploadForm.headers>

    <body: encrypted blob>

Download path (any CDN):

    GET https://cdn<N>.signal.org/attachments/<cdnKey>
"""

from __future__ import annotations

import httpx

from sigsig.certs import signal_ssl_context
from sigsig.config import USER_AGENT
from sigsig.errors import ServerError, TransportError


_CDN_HOSTS = {
    0: "https://cdn.signal.org",
    2: "https://cdn2.signal.org",
    3: "https://cdn3.signal.org",
}


async def upload_cdn3(
    *,
    signed_upload_url: str,
    upload_headers: dict[str, str],
    body: bytes,
) -> None:
    async with httpx.AsyncClient(
        timeout=60.0,
        verify=signal_ssl_context(),
        headers={"User-Agent": USER_AGENT},
    ) as client:
        headers = {
            "Upload-Length": str(len(body)),
            "Tus-Resumable": "1.0.0",
            "Content-Type": "application/offset+octet-stream",
            **{k: v for k, v in upload_headers.items() if k.lower() != "host"},
        }
        try:
            resp = await client.post(signed_upload_url, headers=headers, content=body)
        except httpx.HTTPError as exc:
            raise TransportError(f"CDN upload failed: {exc}") from exc
    if resp.status_code not in (200, 201, 204):
        raise ServerError(resp.status_code, resp.reason_phrase, resp.content)


async def download(cdn_number: int, cdn_key: str) -> bytes:
    host = _CDN_HOSTS.get(cdn_number)
    if host is None:
        raise TransportError(f"unknown CDN number {cdn_number}")
    async with httpx.AsyncClient(
        timeout=60.0,
        verify=signal_ssl_context(),
        headers={"User-Agent": USER_AGENT},
    ) as client:
        try:
            resp = await client.get(f"{host}/attachments/{cdn_key}")
        except httpx.HTTPError as exc:
            raise TransportError(f"CDN download failed: {exc}") from exc
    if resp.status_code != 200:
        raise ServerError(resp.status_code, resp.reason_phrase, resp.content)
    return resp.content
