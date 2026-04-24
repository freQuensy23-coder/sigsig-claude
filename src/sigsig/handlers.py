"""Handler registry + dispatch used by :class:`sigsig.client.Client`.

The :class:`HandlerRegistry` is a tiny per-event-type fan-out: each call to
``register(Event, handler)`` appends to a list; :meth:`dispatch` awaits all
of them in registration order. Exceptions in one handler don't block the
others — they're logged and raised after the fan-out completes.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import TypeVar

from sigsig.events import Event

log = logging.getLogger(__name__)

E = TypeVar("E", bound=Event)

Handler = Callable[[E], Awaitable[None] | None]


class HandlerRegistry:
    def __init__(self) -> None:
        self._by_type: dict[type[Event], list[Handler[Event]]] = {}

    def register(self, event_type: type[E], handler: Handler[E]) -> None:
        self._by_type.setdefault(event_type, []).append(handler)  # type: ignore[arg-type]

    def unregister(self, event_type: type[E], handler: Handler[E]) -> None:
        lst = self._by_type.get(event_type)
        if lst is not None:
            with _suppress_errors():
                lst.remove(handler)  # type: ignore[arg-type]

    async def dispatch(self, event: Event) -> None:
        # Invoke handlers registered for the exact type and any superclass
        # (so an `@on(Event)` handler sees everything).
        handlers: list[Handler[Event]] = []
        for cls in type(event).__mro__:
            if cls is object:
                continue
            handlers.extend(self._by_type.get(cls, []))  # type: ignore[arg-type]
        if not handlers:
            return

        results = await asyncio.gather(
            *(self._call(h, event) for h in handlers), return_exceptions=True
        )
        for res in results:
            if isinstance(res, Exception):
                log.exception("handler error", exc_info=res)

    @staticmethod
    async def _call(handler: Handler[Event], event: Event) -> None:
        result = handler(event)
        if inspect.isawaitable(result):
            await result


class _suppress_errors:  # noqa: N801 - contextmanager-as-class pattern
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: object) -> bool:
        return True
