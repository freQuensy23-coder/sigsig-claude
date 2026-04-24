"""Event types delivered to user handlers.

Every inbound, decrypted, validated Signal message is normalised into one
of these dataclasses before being dispatched. Use them as the type argument
to ``@client.on(...)`` — e.g. ``@client.on(TextMessage)``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sigsig.attachments import InboundAttachment
from sigsig.types import DeviceId, ServiceId


@dataclass(slots=True, frozen=True)
class Event:
    """Base class for dispatchable events."""


@dataclass(slots=True, frozen=True)
class TextMessage(Event):
    """A plain text DataMessage from a peer."""

    sender: ServiceId
    sender_device: DeviceId
    timestamp_ms: int
    server_timestamp_ms: int
    text: str
    expires_in_seconds: int = 0
    is_view_once: bool = False
    attachments: tuple[InboundAttachment, ...] = ()


@dataclass(slots=True, frozen=True)
class GroupTextMessage(Event):
    """A text message delivered in a Groups V2 chat.

    ``group_master_key`` is the raw 32-byte master key from the inbound
    ``DataMessage.groupV2``. Handlers can use it to match against known
    groups.
    """

    sender: ServiceId
    sender_device: DeviceId
    group_master_key: bytes
    group_revision: int
    timestamp_ms: int
    server_timestamp_ms: int
    text: str
    expires_in_seconds: int = 0
    attachments: tuple[InboundAttachment, ...] = ()


@dataclass(slots=True, frozen=True)
class Receipt(Event):
    """A delivery or read receipt from a peer."""

    sender: ServiceId
    sender_device: DeviceId
    kind: str                   # "delivery" | "read" | "viewed"
    referenced_timestamps: tuple[int, ...] = field(default_factory=tuple)


@dataclass(slots=True, frozen=True)
class Typing(Event):
    """A typing indicator."""

    sender: ServiceId
    sender_device: DeviceId
    timestamp_ms: int
    started: bool
    group_id: bytes | None = None


@dataclass(slots=True, frozen=True)
class SelfSent(Event):
    """A SyncMessage.Sent from our own primary — we sent something elsewhere
    and the server is mirroring it to this linked device."""

    destination: ServiceId | None
    destination_e164: str | None
    timestamp_ms: int
    text: str | None


@dataclass(slots=True, frozen=True)
class UnknownMessage(Event):
    """Catch-all for inbound ``Content`` payloads we don't recognise.

    Handlers registered on :class:`UnknownMessage` get the raw bytes and the
    envelope metadata so they can dig in without sigsig needing to grow
    dedicated types for rarely-used message kinds.
    """

    sender: ServiceId | None
    sender_device: DeviceId | None
    timestamp_ms: int
    server_timestamp_ms: int
    raw_content: bytes
    envelope_type: int


@dataclass(slots=True, frozen=True)
class DecryptionError(Event):
    """Raised as an event when we couldn't decrypt an inbound envelope.

    Your handler can log it or prompt a rekey flow. The default logger in
    ``Client`` already logs decryption failures at WARNING level.
    """

    sender: ServiceId | None
    sender_device: DeviceId | None
    envelope_type: int
    error: str
