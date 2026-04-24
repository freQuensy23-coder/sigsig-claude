"""Async HTTP client for Signal's REST endpoints.

Thin wrapper around :class:`httpx.AsyncClient` that knows how to:

- Attach Basic auth (``{aci}.{deviceId}:{password}``) or omit it for the
  unauthenticated endpoints.
- Set the User-Agent / X-Signal-Agent headers Signal expects.
- Translate Signal's 409/410/428 responses into typed exceptions so higher
  layers can retry correctly.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from sigsig.certs import signal_ssl_context
from sigsig.config import LIVE, SIGNAL_AGENT, USER_AGENT, Environment
from sigsig.errors import (
    AuthenticationFailed,
    MismatchedDevices,
    ServerError,
    StaleDevices,
    TransportError,
)


@dataclass(slots=True)
class HttpCredentials:
    """Credentials for Signal's HTTP Basic auth.

    ``username`` is ``{ACI-uuid}.{deviceId}`` for authenticated calls; it is
    ``None`` for unauthenticated ones.
    """

    username: str | None
    password: str | None

    @classmethod
    def for_account(cls, aci: str, device_id: int, password: str) -> "HttpCredentials":
        return cls(username=f"{aci}.{device_id}", password=password)

    @classmethod
    def unauthenticated(cls) -> "HttpCredentials":
        return cls(username=None, password=None)


class HttpClient:
    """Async HTTP client bound to a Signal environment + credentials."""

    def __init__(
        self,
        *,
        credentials: HttpCredentials,
        environment: Environment = LIVE,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
        verify: bool | object = True,
    ) -> None:
        auth: httpx.Auth | None = None
        if credentials.password is not None:
            auth = httpx.BasicAuth(credentials.username or "", credentials.password)
        # Default: pin Signal's self-signed CA. Tests pass their own
        # transport and want the system default, so only apply the pinned
        # context when we're actually pointing at a Signal-hosted URL.
        client_kwargs: dict[str, object] = {
            "base_url": environment.chat_http_url,
            "timeout": timeout,
            "auth": auth,
            "headers": {
                "User-Agent": USER_AGENT,
                "X-Signal-Agent": SIGNAL_AGENT,
            },
            "http2": False,
        }
        if transport is not None:
            client_kwargs["transport"] = transport
        elif verify is True and _is_signal_url(environment.chat_http_url):
            client_kwargs["verify"] = signal_ssl_context()
        elif verify is False:
            client_kwargs["verify"] = False
        self._client = httpx.AsyncClient(**client_kwargs)  # type: ignore[arg-type]
        self._env = environment
        self._credentials = credentials

    @property
    def environment(self) -> Environment:
        return self._env

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    # ----- core request helper --------------------------------------------

    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        unidentified_access: bytes | None = None,
        expected_status: tuple[int, ...] = (200, 204),
    ) -> httpx.Response:
        req_headers: dict[str, str] = dict(headers or {})
        kwargs: dict[str, Any] = {
            "method": method,
            "url": path,
            "headers": req_headers,
            "params": params,
        }
        if json_body is not None:
            kwargs["json"] = json_body
        elif content is not None:
            kwargs["content"] = content

        if unidentified_access is not None:
            # Sealed-sender path: attach UAK header and strip Basic auth so
            # Signal doesn't see both.
            req_headers["Unidentified-Access-Key"] = base64.b64encode(
                unidentified_access
            ).decode("ascii")
            kwargs["auth"] = None

        try:
            resp = await self._client.request(**kwargs)
        except httpx.HTTPError as exc:
            raise TransportError(str(exc)) from exc

        if resp.status_code in expected_status:
            return resp
        if resp.status_code in (401, 403):
            raise AuthenticationFailed(resp.text or str(resp.status_code))
        if resp.status_code == 409:
            payload = _safe_json(resp)
            raise MismatchedDevices(
                missing=list(payload.get("missingDevices", [])),
                extra=list(payload.get("extraDevices", [])),
            )
        if resp.status_code == 410:
            payload = _safe_json(resp)
            raise StaleDevices(stale=list(payload.get("staleDevices", [])))
        raise ServerError(resp.status_code, resp.reason_phrase, resp.content)

    # ----- convenience wrappers -------------------------------------------

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", path, **kwargs)

    async def put(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request(
            "DELETE", path, expected_status=(200, 204), **kwargs
        )


def _safe_json(resp: httpx.Response) -> dict[str, Any]:
    try:
        return json.loads(resp.content or b"{}")
    except ValueError:
        return {}


def _is_signal_url(url: str) -> bool:
    """Heuristic: only pin Signal's CA when talking to Signal-owned hosts."""
    return any(host in url for host in ("signal.org", "signalusers.org"))
