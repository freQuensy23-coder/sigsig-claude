"""A tiny async mock of Signal's chat service.

This is **not** a faithful reimplementation of the server — it only handles
the requests our integration tests care about. Each test can inject
behaviour via the ``on_*`` / ``enqueue_*`` hooks on :class:`MockSignalServer`.

The server exposes both the HTTP endpoints sigsig talks to and the two
WebSocket paths (``/v1/websocket/provisioning/`` and ``/v1/websocket/``)
with the correct protobuf-framed request/response protocol.
"""

from __future__ import annotations

import asyncio
import itertools
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from contextlib import suppress

from aiohttp import WSCloseCode, WSMsgType, web

from sigsig._proto import Provisioning_pb2 as prov_pb
from sigsig._proto import SignalService_pb2 as svc_pb
from sigsig._proto import WebSocketResources_pb2 as ws_pb


# ---------------------------------------------------------------------------
# Request capture records
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class CapturedRequest:
    """An HTTP request the mock observed, retained for assertions."""

    method: str
    path: str
    headers: dict[str, str]
    json_body: Any | None
    raw_body: bytes


@dataclass(slots=True)
class LinkRequest(CapturedRequest):
    provisioning_code: str = ""


@dataclass(slots=True)
class MessageRequest(CapturedRequest):
    destination: str = ""


# ---------------------------------------------------------------------------
# Mock server
# ---------------------------------------------------------------------------


class MockSignalServer:
    """Controllable mock of Signal's chat service."""

    def __init__(self) -> None:
        self.captured_link_requests: list[LinkRequest] = []
        self.captured_message_requests: list[MessageRequest] = []
        self.captured_prekey_uploads: list[CapturedRequest] = []

        # Responses that pending device-link PUTs will receive.
        self.link_response: dict[str, Any] = {"deviceId": 3}

        # PreKeyBundle payload per recipient. Each value is the full
        # ``{identityKey, devices: [...]}`` JSON served by `GET /v2/keys/{id}/*`.
        # Per-device GETs carve out the matching entry in ``devices``.
        self.prekey_bundles: dict[str, dict[str, Any]] = {}

        # Pushes to deliver on the next provisioning WS connection.
        self._provisioning_scripts: asyncio.Queue[_ProvisioningScript] = asyncio.Queue()

        # Server-side state.
        self._provisioning_addresses: list[str] = []
        self._authenticated_ws_events: list[asyncio.Queue[bytes]] = []
        self._message_id_counter = itertools.count(1)

    # ------------------------------------------------------------------
    # Provisioning helpers
    # ------------------------------------------------------------------

    async def enqueue_provisioning_session(
        self,
        *,
        session_uuid: str | None = None,
        envelope_body: bytes,
        envelope_public_key: bytes,
    ) -> str:
        """Schedule a provisioning session. Returns the session uuid.

        When a secondary connects to ``/v1/websocket/provisioning/``, the
        server pushes ``ProvisioningAddress(address=session_uuid)`` first
        and then the supplied ``ProvisionEnvelope`` body.
        """
        session_uuid = session_uuid or str(uuid.uuid4())
        script = _ProvisioningScript(
            session_uuid=session_uuid,
            envelope=prov_pb.ProvisionEnvelope(
                publicKey=envelope_public_key, body=envelope_body
            ),
        )
        await self._provisioning_scripts.put(script)
        return session_uuid

    # ------------------------------------------------------------------
    # Authenticated WS: push a fake inbound envelope
    # ------------------------------------------------------------------

    async def push_envelope(self, envelope: svc_pb.Envelope) -> None:
        """Deliver an inbound envelope to every connected auth WS."""
        msg = ws_pb.WebSocketMessage()
        msg.type = ws_pb.WebSocketMessage.REQUEST
        msg.request.verb = "PUT"
        msg.request.path = "/api/v1/message"
        msg.request.body = envelope.SerializeToString()
        msg.request.id = next(self._message_id_counter)
        raw = msg.SerializeToString()
        for q in list(self._authenticated_ws_events):
            await q.put(raw)

    # ------------------------------------------------------------------
    # aiohttp app factory
    # ------------------------------------------------------------------

    def build_app(self) -> web.Application:
        app = web.Application()
        app.router.add_put("/v1/devices/link", self._link_handler)
        app.router.add_put("/v1/messages/{destination}", self._messages_handler)
        app.router.add_get("/v2/keys/{service_id}/{device}", self._get_prekey_bundle)
        app.router.add_get("/v2/keys/{service_id}/{device}/", self._get_prekey_bundle)
        app.router.add_put("/v2/keys", self._upload_prekeys)
        app.router.add_get("/v1/websocket/provisioning/", self._ws_provisioning)
        app.router.add_get("/v1/websocket/", self._ws_authenticated)
        app.router.add_get("/v1/keepalive", self._keepalive)
        return app

    # ------------------------------------------------------------------
    # HTTP handlers
    # ------------------------------------------------------------------

    async def _link_handler(self, request: web.Request) -> web.Response:
        body = await request.read()
        parsed = await request.json()
        self.captured_link_requests.append(
            LinkRequest(
                method=request.method,
                path=request.path,
                headers=dict(request.headers),
                json_body=parsed,
                raw_body=body,
                provisioning_code=parsed["verificationCode"],
            )
        )
        return web.json_response(self.link_response)

    async def _messages_handler(self, request: web.Request) -> web.Response:
        body = await request.read()
        parsed = await request.json()
        self.captured_message_requests.append(
            MessageRequest(
                method=request.method,
                path=request.path,
                headers=dict(request.headers),
                json_body=parsed,
                raw_body=body,
                destination=request.match_info["destination"],
            )
        )
        return web.json_response({"needsSync": False})

    async def _get_prekey_bundle(self, request: web.Request) -> web.Response:
        service_id = request.match_info["service_id"]
        device = request.match_info["device"]
        bundle = self.prekey_bundles.get(service_id)
        if bundle is None:
            return web.json_response({"error": "not found"}, status=404)
        if device == "*":
            return web.json_response(bundle)
        devices = [d for d in bundle["devices"] if int(d["deviceId"]) == int(device)]
        if not devices:
            return web.json_response({"error": "not found"}, status=404)
        return web.json_response({"identityKey": bundle["identityKey"], "devices": devices})

    async def _upload_prekeys(self, request: web.Request) -> web.Response:
        body = await request.read()
        parsed = await request.json()
        self.captured_prekey_uploads.append(
            CapturedRequest(
                method=request.method,
                path=request.path,
                headers=dict(request.headers),
                json_body=parsed,
                raw_body=body,
            )
        )
        return web.Response(status=204)

    async def _keepalive(self, request: web.Request) -> web.Response:
        return web.Response(status=200)

    # ------------------------------------------------------------------
    # WebSocket handlers
    # ------------------------------------------------------------------

    async def _ws_provisioning(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(max_msg_size=2 * 1024 * 1024)
        await ws.prepare(request)

        try:
            script = await asyncio.wait_for(
                self._provisioning_scripts.get(), timeout=30
            )
        except asyncio.TimeoutError:
            await ws.close()
            return ws

        # Push 1: ProvisioningAddress
        addr = prov_pb.ProvisioningAddress(address=script.session_uuid)
        await _send_request(ws, verb="PUT", path="/v1/address", body=addr.SerializeToString(), rid=1)

        # Wait for client ack (ignored).
        ack = await ws.receive(timeout=30)
        if ack.type is not WSMsgType.BINARY:
            await ws.close(code=WSCloseCode.PROTOCOL_ERROR)
            return ws

        # Push 2: ProvisionEnvelope
        await _send_request(
            ws,
            verb="PUT",
            path="/v1/message",
            body=script.envelope.SerializeToString(),
            rid=2,
        )
        ack2 = await ws.receive(timeout=30)
        _ = ack2

        await ws.close()
        return ws

    async def _ws_authenticated(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(max_msg_size=2 * 1024 * 1024)
        await ws.prepare(request)

        queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._authenticated_ws_events.append(queue)

        async def _writer() -> None:
            while not ws.closed:
                try:
                    data = await queue.get()
                except asyncio.CancelledError:
                    return
                if ws.closed:
                    return
                await ws.send_bytes(data)

        writer = asyncio.create_task(_writer())
        try:
            async for msg in ws:
                # Client sends RESPONSE acks + keepalive REQUESTs.
                if msg.type is WSMsgType.BINARY:
                    parsed = ws_pb.WebSocketMessage()
                    parsed.ParseFromString(msg.data)
                    if parsed.type == ws_pb.WebSocketMessage.REQUEST:
                        resp = ws_pb.WebSocketMessage()
                        resp.type = ws_pb.WebSocketMessage.RESPONSE
                        resp.response.id = parsed.request.id
                        resp.response.status = 200
                        resp.response.message = "OK"
                        await ws.send_bytes(resp.SerializeToString())
                elif msg.type is WSMsgType.ERROR:
                    break
        finally:
            writer.cancel()
            with suppress(asyncio.CancelledError):
                await writer
            self._authenticated_ws_events.remove(queue)
        return ws


async def _send_request(
    ws: web.WebSocketResponse, *, verb: str, path: str, body: bytes, rid: int
) -> None:
    msg = ws_pb.WebSocketMessage()
    msg.type = ws_pb.WebSocketMessage.REQUEST
    msg.request.verb = verb
    msg.request.path = path
    msg.request.body = body
    msg.request.id = rid
    await ws.send_bytes(msg.SerializeToString())


@dataclass(slots=True)
class _ProvisioningScript:
    session_uuid: str
    envelope: prov_pb.ProvisionEnvelope


# ---------------------------------------------------------------------------
# Context manager: run the mock and hand back base URLs
# ---------------------------------------------------------------------------


@asynccontextmanager
async def running_mock_server() -> AsyncIterator[tuple[MockSignalServer, str, str]]:
    """Start the mock server on a random port.

    Yields ``(mock, http_base_url, ws_base_url)``.
    """
    mock = MockSignalServer()
    app = mock.build_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    # Figure out the actual port.
    assert site._server is not None  # noqa: SLF001
    port = site._server.sockets[0].getsockname()[1]  # noqa: SLF001
    http_base = f"http://127.0.0.1:{port}"
    ws_base = f"ws://127.0.0.1:{port}"
    try:
        yield mock, http_base, ws_base
    finally:
        await runner.cleanup()
