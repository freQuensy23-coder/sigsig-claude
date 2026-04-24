"""Message receive loop and envelope dispatcher.

Given an :class:`AuthenticatedWebSocket`, :func:`run_receive_loop` reads
inbound ``WebSocketRequestMessage`` frames, classifies each envelope by
type, and delegates decryption to libsignal via
:class:`sigsig_libsignal._libsignal.SignalStore`:

- ``DOUBLE_RATCHET`` (1) → :meth:`SignalStore.decrypt_signal`
- ``PREKEY_MESSAGE`` (3) → :meth:`SignalStore.decrypt_prekey`
- ``UNIDENTIFIED_SENDER`` (6) → :meth:`SignalStore.sealed_sender_decrypt`

Failed decrypts surface as :class:`sigsig.events.DecryptionError`
rather than aborting the loop — the server expects the ack either way.
"""

from __future__ import annotations

import logging

from sigsig_libsignal._libsignal import SignalStore  # type: ignore[import-not-found]

from sigsig._proto import SignalService_pb2 as svc_pb
from sigsig.config import UNIDENTIFIED_SENDER_TRUST_ROOT, UNIDENTIFIED_SENDER_TRUST_ROOT2
from sigsig.events import (
    DecryptionError,
    Event,
    Receipt,
    SelfSent,
    TextMessage,
    Typing,
    UnknownMessage,
)
from sigsig.handlers import HandlerRegistry
from sigsig.transport.ws import AuthenticatedWebSocket, WsRequest
from sigsig.types import ServiceId

log = logging.getLogger(__name__)


async def run_receive_loop(
    *,
    ws: AuthenticatedWebSocket,
    store: SignalStore,
    registry: HandlerRegistry,
    our_aci: str,
    our_device_id: int,
) -> None:
    async for req in ws.requests():
        try:
            await _handle_request(
                req,
                store=store,
                registry=registry,
                our_aci=our_aci,
                our_device_id=our_device_id,
            )
        except Exception:
            log.exception("error handling WS request %s %s", req.verb, req.path)
        finally:
            try:
                await req.ack(200)
            except Exception:
                log.exception("failed to ack WS request id=%s", req.id)


async def _handle_request(
    req: WsRequest,
    *,
    store: SignalStore,
    registry: HandlerRegistry,
    our_aci: str,
    our_device_id: int,
) -> None:
    if req.verb != "PUT":
        log.debug("ignoring inbound verb=%s path=%s", req.verb, req.path)
        return

    if req.path.endswith("/api/v1/queue/empty"):
        log.debug("server reports queue empty")
        return

    if not req.path.endswith("/api/v1/message"):
        log.debug("ignoring unknown path=%s", req.path)
        return

    envelope = svc_pb.Envelope()
    envelope.ParseFromString(req.body)
    for ev in _dispatch_envelope(
        envelope=envelope, store=store, our_aci=our_aci, our_device_id=our_device_id
    ):
        await registry.dispatch(ev)


def _strip_padding(plaintext: bytes) -> bytes:
    """Strip Signal's 0x80-terminator padding (PushTransportDetails.java)."""
    for i in range(len(plaintext) - 1, -1, -1):
        if plaintext[i] == 0x80:
            return plaintext[:i]
        if plaintext[i] != 0x00:
            return plaintext
    return plaintext


def _dispatch_envelope(
    *,
    envelope: svc_pb.Envelope,
    store: SignalStore,
    our_aci: str,
    our_device_id: int,
) -> list[Event]:
    events: list[Event] = []

    source: ServiceId | None = (
        ServiceId.parse(envelope.sourceServiceId) if envelope.sourceServiceId else None
    )
    source_device: int | None = (
        envelope.sourceDeviceId if envelope.HasField("sourceDeviceId") else None
    )

    if envelope.type == svc_pb.Envelope.SERVER_DELIVERY_RECEIPT:
        if source is not None and source_device is not None:
            events.append(
                Receipt(
                    sender=source,
                    sender_device=source_device,
                    kind="delivery",
                    referenced_timestamps=(
                        (envelope.clientTimestamp,) if envelope.clientTimestamp else ()
                    ),
                )
            )
        return events

    if envelope.type == svc_pb.Envelope.UNIDENTIFIED_SENDER:
        try:
            sender_uuid, sender_e164, sender_device, plaintext = store.sealed_sender_decrypt(
                bytes(envelope.content),
                [UNIDENTIFIED_SENDER_TRUST_ROOT, UNIDENTIFIED_SENDER_TRUST_ROOT2],
                int(envelope.serverTimestamp),
                our_aci,
                our_device_id,
            )
        except Exception as exc:  # noqa: BLE001
            events.append(
                DecryptionError(
                    sender=source,
                    sender_device=source_device,
                    envelope_type=envelope.type,
                    error=f"sealed sender decrypt: {exc}",
                )
            )
            return events
        events.extend(
            _events_from_content(
                plaintext=_strip_padding(plaintext),
                source=ServiceId.parse(sender_uuid),
                source_device=sender_device,
                envelope=envelope,
            )
        )
        return events

    if envelope.type in (svc_pb.Envelope.DOUBLE_RATCHET, svc_pb.Envelope.PREKEY_MESSAGE):
        if source is None or source_device is None:
            events.append(
                DecryptionError(
                    sender=source,
                    sender_device=source_device,
                    envelope_type=envelope.type,
                    error="missing source identifiers",
                )
            )
            return events
        try:
            if envelope.type == svc_pb.Envelope.DOUBLE_RATCHET:
                plaintext = store.decrypt_signal(
                    source.service_id_string, source_device, bytes(envelope.content)
                )
            else:
                plaintext = store.decrypt_prekey(
                    source.service_id_string, source_device, bytes(envelope.content)
                )
        except Exception as exc:  # noqa: BLE001
            events.append(
                DecryptionError(
                    sender=source,
                    sender_device=source_device,
                    envelope_type=envelope.type,
                    error=str(exc),
                )
            )
            return events
        events.extend(
            _events_from_content(
                plaintext=_strip_padding(plaintext),
                source=source,
                source_device=source_device,
                envelope=envelope,
            )
        )
        return events

    events.append(
        UnknownMessage(
            sender=source,
            sender_device=source_device,
            timestamp_ms=envelope.clientTimestamp,
            server_timestamp_ms=envelope.serverTimestamp,
            raw_content=bytes(envelope.content) if envelope.HasField("content") else b"",
            envelope_type=envelope.type,
        )
    )
    return events


def _events_from_content(
    *,
    plaintext: bytes,
    source: ServiceId,
    source_device: int,
    envelope: svc_pb.Envelope,
) -> list[Event]:
    content = svc_pb.Content()
    try:
        content.ParseFromString(plaintext)
    except Exception as exc:  # noqa: BLE001
        return [
            DecryptionError(
                sender=source,
                sender_device=source_device,
                envelope_type=envelope.type,
                error=f"bad Content protobuf: {exc}",
            )
        ]

    events: list[Event] = []

    if content.HasField("dataMessage"):
        dm = content.dataMessage
        events.append(
            TextMessage(
                sender=source,
                sender_device=source_device,
                timestamp_ms=dm.timestamp,
                server_timestamp_ms=envelope.serverTimestamp,
                text=dm.body or "",
                expires_in_seconds=dm.expireTimer or 0,
                is_view_once=bool(dm.isViewOnce),
            )
        )
    if content.HasField("receiptMessage"):
        rm = content.receiptMessage
        kind_map = {
            svc_pb.ReceiptMessage.DELIVERY: "delivery",
            svc_pb.ReceiptMessage.READ: "read",
            svc_pb.ReceiptMessage.VIEWED: "viewed",
        }
        events.append(
            Receipt(
                sender=source,
                sender_device=source_device,
                kind=kind_map.get(rm.type, "unknown"),
                referenced_timestamps=tuple(rm.timestamp),
            )
        )
    if content.HasField("typingMessage"):
        tm = content.typingMessage
        events.append(
            Typing(
                sender=source,
                sender_device=source_device,
                timestamp_ms=tm.timestamp,
                started=tm.action == svc_pb.TypingMessage.STARTED,
                group_id=bytes(tm.groupId) if tm.HasField("groupId") else None,
            )
        )
    if content.HasField("syncMessage") and content.syncMessage.HasField("sent"):
        sent = content.syncMessage.sent
        dest_service: ServiceId | None = None
        if sent.HasField("destinationServiceId"):
            dest_service = ServiceId.parse(sent.destinationServiceId)
        text = sent.message.body if sent.HasField("message") else None
        events.append(
            SelfSent(
                destination=dest_service,
                destination_e164=sent.destinationE164 if sent.HasField("destinationE164") else None,
                timestamp_ms=sent.timestamp,
                text=text,
            )
        )

    if not events:
        events.append(
            UnknownMessage(
                sender=source,
                sender_device=source_device,
                timestamp_ms=envelope.clientTimestamp,
                server_timestamp_ms=envelope.serverTimestamp,
                raw_content=plaintext,
                envelope_type=envelope.type,
            )
        )
    return events
