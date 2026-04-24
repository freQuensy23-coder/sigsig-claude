"""Async WebSocket framing for Signal's chat service.

Signal's chat WebSocket uses a custom protobuf wire format
(:mod:`sigsig._proto.WebSocketResources_pb2`): every frame is a
``WebSocketMessage`` of either REQUEST (server → client push) or RESPONSE
(ack). Clients reply to each REQUEST with a matching RESPONSE carrying the
same ``id``. There are two distinct streams:

- :class:`ProvisioningWebSocket` — unauthenticated, used only for the
  initial QR linked-device handshake.
- :class:`AuthenticatedWebSocket` — the long-lived auth stream that
  carries incoming messages and keepalives.
"""

from __future__ import annotations

import asyncio
import base64
import itertools
import ssl
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Self

import websockets
from websockets.asyncio.client import ClientConnection, connect as ws_connect

from sigsig.certs import signal_ssl_context


def _ssl_for(url: str, *, verify: bool) -> ssl.SSLContext | None:
    """Return the SSL context to use for ``url``.

    - When ``verify=True`` and the URL is a Signal-hosted host, use the
      pinned Signal CA.
    - When ``verify=False``, return a context that disables verification
      (intended for ``--insecure`` testing only).
    - Otherwise return ``None`` so websockets picks its default.
    """
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if "signal.org" in url or "signalusers.org" in url:
        return signal_ssl_context()
    return None

from sigsig._proto import WebSocketResources_pb2 as ws_pb
from sigsig.config import (
    AUTHENTICATED_WS_PATH,
    KEEPALIVE_INTERVAL_S,
    KEEPALIVE_PATH,
    PROVISIONING_WS_PATH,
    SIGNAL_AGENT,
    USER_AGENT,
    Environment,
    LIVE,
)
from sigsig.errors import TransportError


# ---------------------------------------------------------------------------
# Typed wrappers around the protobuf message types.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class WsRequest:
    """An inbound WebSocket REQUEST as delivered by the server.

    ``respond`` closes over the transport + request ``id`` so that the
    handler can ack with a single call.
    """

    verb: str
    path: str
    headers: list[str]
    body: bytes
    id: int
    _respond: Callable[[int, bytes | None], Awaitable[None]]

    async def ack(self, status: int = 200, body: bytes | None = None) -> None:
        await self._respond(status, body)


@dataclass(slots=True)
class WsResponse:
    """An inbound RESPONSE (ack)."""

    id: int
    status: int
    message: str
    headers: list[str]
    body: bytes


# ---------------------------------------------------------------------------
# Low-level framing helpers
# ---------------------------------------------------------------------------


def _encode_request(verb: str, path: str, body: bytes | None, headers: list[str], rid: int) -> bytes:
    msg = ws_pb.WebSocketMessage()
    msg.type = ws_pb.WebSocketMessage.REQUEST
    msg.request.verb = verb
    msg.request.path = path
    if body is not None:
        msg.request.body = body
    if headers:
        msg.request.headers.extend(headers)
    msg.request.id = rid
    return msg.SerializeToString()


def _encode_response(rid: int, status: int, body: bytes | None) -> bytes:
    msg = ws_pb.WebSocketMessage()
    msg.type = ws_pb.WebSocketMessage.RESPONSE
    msg.response.id = rid
    msg.response.status = status
    msg.response.message = "OK" if 200 <= status < 300 else "ERR"
    if body is not None:
        msg.response.body = body
    return msg.SerializeToString()


# ---------------------------------------------------------------------------
# Base class: read loop + keepalive scheduling
# ---------------------------------------------------------------------------


class _BaseWs:
    def __init__(self, conn: ClientConnection, *, keepalive: float | None) -> None:
        self._conn = conn
        self._request_queue: asyncio.Queue[WsRequest] = asyncio.Queue()
        self._pending_responses: dict[int, asyncio.Future[WsResponse]] = {}
        self._request_id_seq = itertools.count(1)
        self._read_task: asyncio.Task[None] | None = None
        self._keepalive_task: asyncio.Task[None] | None = None
        self._closed = asyncio.Event()
        self._keepalive = keepalive

    async def start(self) -> None:
        self._read_task = asyncio.create_task(self._read_loop(), name="sigsig-ws-read")
        if self._keepalive is not None:
            self._keepalive_task = asyncio.create_task(
                self._keepalive_loop(), name="sigsig-ws-keepalive"
            )

    async def close(self) -> None:
        self._closed.set()
        for t in (self._read_task, self._keepalive_task):
            if t is not None:
                t.cancel()
                with suppress(asyncio.CancelledError):
                    await t
        await self._conn.close()

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    # ---- low-level send/recv ---------------------------------------------

    async def _send_request(
        self, verb: str, path: str, body: bytes | None = None, headers: list[str] | None = None
    ) -> WsResponse:
        rid = next(self._request_id_seq)
        fut: asyncio.Future[WsResponse] = asyncio.get_running_loop().create_future()
        self._pending_responses[rid] = fut
        try:
            await self._conn.send(_encode_request(verb, path, body, headers or [], rid))
            return await fut
        finally:
            self._pending_responses.pop(rid, None)

    async def _respond(self, rid: int, status: int, body: bytes | None) -> None:
        await self._conn.send(_encode_response(rid, status, body))

    # ---- read loop --------------------------------------------------------

    async def _read_loop(self) -> None:
        try:
            async for data in self._conn:
                if isinstance(data, str):
                    # Signal speaks only binary frames; ignore anything else.
                    continue
                msg = ws_pb.WebSocketMessage()
                try:
                    msg.ParseFromString(data)
                except Exception as exc:  # noqa: BLE001
                    raise TransportError(f"bad WebSocketMessage: {exc}") from exc
                if msg.type == ws_pb.WebSocketMessage.REQUEST:
                    r = msg.request
                    rid = r.id

                    async def respond(
                        status: int, body: bytes | None, _rid: int = rid
                    ) -> None:
                        await self._respond(_rid, status, body)

                    req = WsRequest(
                        verb=r.verb or "",
                        path=r.path or "",
                        headers=list(r.headers),
                        body=bytes(r.body) if r.HasField("body") else b"",
                        id=rid,
                        _respond=respond,
                    )
                    await self._request_queue.put(req)
                elif msg.type == ws_pb.WebSocketMessage.RESPONSE:
                    r = msg.response
                    resp = WsResponse(
                        id=r.id,
                        status=r.status,
                        message=r.message or "",
                        headers=list(r.headers),
                        body=bytes(r.body) if r.HasField("body") else b"",
                    )
                    fut = self._pending_responses.get(resp.id)
                    if fut is not None and not fut.done():
                        fut.set_result(resp)
        except websockets.ConnectionClosed:
            pass
        except asyncio.CancelledError:
            raise
        finally:
            # Wake anything still awaiting a response.
            for fut in self._pending_responses.values():
                if not fut.done():
                    fut.set_exception(TransportError("websocket closed"))
            self._pending_responses.clear()
            self._closed.set()
            await self._request_queue.put(_SENTINEL_REQUEST)

    # ---- keepalive loop ---------------------------------------------------

    async def _keepalive_loop(self) -> None:
        try:
            while not self._closed.is_set():
                await asyncio.sleep(self._keepalive or KEEPALIVE_INTERVAL_S)
                if self._closed.is_set():
                    break
                try:
                    await self._send_request("GET", KEEPALIVE_PATH)
                except TransportError:
                    break
        except asyncio.CancelledError:
            raise

    # ---- public helpers ---------------------------------------------------

    async def requests(self) -> AsyncIterator[WsRequest]:
        """Iterate inbound server pushes until the socket closes."""
        while True:
            req = await self._request_queue.get()
            if req is _SENTINEL_REQUEST:
                return
            yield req


_SENTINEL_REQUEST = WsRequest(
    verb="", path="", headers=[], body=b"", id=0, _respond=lambda *_: _noop()
)


async def _noop() -> None:  # pragma: no cover
    return None


# ---------------------------------------------------------------------------
# Concrete connections
# ---------------------------------------------------------------------------


class ProvisioningWebSocket(_BaseWs):
    """Unauthenticated WebSocket used during the QR linked-device flow.

    Signal's server applies an **application-level** idle timeout of ~90s.
    Raw TCP WebSocket pings do not reset it — the server only resets the
    timer when it sees a Signal-framed ``WebSocketRequestMessage``. We
    therefore send ``GET /v1/keepalive`` every 30s while we wait for the
    primary to scan the QR.
    """

    @classmethod
    async def connect(
        cls, *, environment: Environment = LIVE, verify: bool = True
    ) -> "ProvisioningWebSocket":
        url = environment.chat_ws_url + PROVISIONING_WS_PATH
        try:
            conn = await ws_connect(
                url,
                user_agent_header=USER_AGENT,
                additional_headers={"X-Signal-Agent": SIGNAL_AGENT},
                max_size=2 * 1024 * 1024,
                ssl=_ssl_for(url, verify=verify),
                ping_interval=None,
            )
        except Exception as exc:  # noqa: BLE001
            raise TransportError(f"provisioning WS dial failed: {exc}") from exc
        obj = cls(conn, keepalive=KEEPALIVE_INTERVAL_S)
        await obj.start()
        return obj


class AuthenticatedWebSocket(_BaseWs):
    """Authenticated WebSocket for incoming messages.

    Uses ``Authorization: Basic`` header — the path libsignal's chat.rs
    takes (see ``AuthenticatedChatHeaders::iter_headers``).
    """

    @classmethod
    async def connect(
        cls,
        *,
        aci: str,
        device_id: int,
        password: str,
        environment: Environment = LIVE,
        keepalive: float = KEEPALIVE_INTERVAL_S,
        verify: bool = True,
    ) -> "AuthenticatedWebSocket":
        url = f"{environment.chat_ws_url}{AUTHENTICATED_WS_PATH}"
        credentials = f"{aci}.{device_id}:{password}".encode()
        auth = "Basic " + base64.b64encode(credentials).decode("ascii")
        try:
            conn = await ws_connect(
                url,
                user_agent_header=USER_AGENT,
                additional_headers={
                    "Authorization": auth,
                    "X-Signal-Agent": SIGNAL_AGENT,
                    "X-Signal-Receive-Stories": "true",
                },
                max_size=2 * 1024 * 1024,
                ssl=_ssl_for(url, verify=verify),
                ping_interval=None,
            )
        except Exception as exc:  # noqa: BLE001
            raise TransportError(f"authenticated WS dial failed: {exc}") from exc
        obj = cls(conn, keepalive=keepalive)
        await obj.start()
        return obj
