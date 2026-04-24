import asyncio

import pytest

from sigsig.events import Event, TextMessage, UnknownMessage
from sigsig.handlers import HandlerRegistry
from sigsig.types import ServiceId


@pytest.mark.asyncio
async def test_dispatch_exact_type() -> None:
    registry = HandlerRegistry()
    received: list[TextMessage] = []

    async def handle(ev: TextMessage) -> None:
        received.append(ev)

    registry.register(TextMessage, handle)
    ev = TextMessage(
        sender=ServiceId.parse("d8f1a6c2-4f1b-4c0a-9e3a-0123456789ab"),
        sender_device=1,
        timestamp_ms=0,
        server_timestamp_ms=0,
        text="hi",
    )
    await registry.dispatch(ev)
    assert received == [ev]


@pytest.mark.asyncio
async def test_dispatch_to_base_event() -> None:
    registry = HandlerRegistry()
    seen: list[Event] = []

    async def any_event(ev: Event) -> None:
        seen.append(ev)

    registry.register(Event, any_event)

    sid = ServiceId.parse("d8f1a6c2-4f1b-4c0a-9e3a-0123456789ab")
    events: list[Event] = [
        TextMessage(sender=sid, sender_device=1, timestamp_ms=0, server_timestamp_ms=0, text="x"),
        UnknownMessage(
            sender=sid,
            sender_device=1,
            timestamp_ms=0,
            server_timestamp_ms=0,
            raw_content=b"",
            envelope_type=6,
        ),
    ]
    for ev in events:
        await registry.dispatch(ev)
    assert seen == events


@pytest.mark.asyncio
async def test_handler_exception_does_not_block_others() -> None:
    registry = HandlerRegistry()
    good: list[int] = []

    async def first(_ev: TextMessage) -> None:
        raise RuntimeError("boom")

    async def second(_ev: TextMessage) -> None:
        good.append(1)

    registry.register(TextMessage, first)
    registry.register(TextMessage, second)

    ev = TextMessage(
        sender=ServiceId.parse("d8f1a6c2-4f1b-4c0a-9e3a-0123456789ab"),
        sender_device=1,
        timestamp_ms=0,
        server_timestamp_ms=0,
        text="x",
    )
    await registry.dispatch(ev)
    assert good == [1]


@pytest.mark.asyncio
async def test_sync_handler_supported() -> None:
    registry = HandlerRegistry()
    seen: list[str] = []

    def handler(ev: TextMessage) -> None:
        seen.append(ev.text)

    registry.register(TextMessage, handler)
    await registry.dispatch(
        TextMessage(
            sender=ServiceId.parse("d8f1a6c2-4f1b-4c0a-9e3a-0123456789ab"),
            sender_device=1,
            timestamp_ms=0,
            server_timestamp_ms=0,
            text="x",
        )
    )
    assert seen == ["x"]
