"""Public :class:`Client` orchestrator."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Self, TypeVar

from sigsig.config import LIVE, Environment
from sigsig.errors import SessionError, SigsigError
from sigsig.events import Event
from sigsig.handlers import Handler, HandlerRegistry
from sigsig.groups import Group
from sigsig.groups_api import fetch_group_members as _fetch_group_members
from sigsig.provisioning.flow import link_device
from sigsig.receive import run_receive_loop
from sigsig.send import SendResult, send_group_text_message, send_text_message
from sigsig.session.store import (
    SigsigStore,
    load_session_file,
    save_session_file,
)
from sigsig.transport.http import HttpClient, HttpCredentials
from sigsig.transport.ws import AuthenticatedWebSocket
from sigsig.types import ServiceId

log = logging.getLogger(__name__)

E = TypeVar("E", bound=Event)


class Client:
    """Async Signal client.

    Either :meth:`qr_login` (first time) or :meth:`load_session` /
    :meth:`from_session` (subsequent runs) must be called before any
    messaging operation.
    """

    def __init__(self, *, environment: Environment = LIVE) -> None:
        self._env = environment
        self._store: SigsigStore | None = None
        self._http: HttpClient | None = None
        self._ws: AuthenticatedWebSocket | None = None
        self._registry = HandlerRegistry()
        self._receive_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    async def qr_login(
        self,
        *,
        device_name: str = "sigsig",
        on_url: Callable[[str], Awaitable[None] | None] | None = None,
        timeout: float = 5 * 60,
    ) -> None:
        result = await link_device(
            device_name=device_name,
            environment=self._env,
            on_url=on_url,
            timeout=timeout,
        )
        self._install_store(result.store)

    async def save_session(self, path: str) -> None:
        if self._store is None:
            raise SessionError("no session to save; call qr_login or load_session first")
        save_session_file(path, self._store.snapshot())
        log.info("saved session to %s", path)

    async def load_session(self, path: str) -> None:
        file = load_session_file(path)
        self._install_store(SigsigStore.from_file(file))
        log.info(
            "loaded session for %s.%d from %s", file.aci, file.device_id, path
        )

    @classmethod
    async def from_session(cls, path: str, *, environment: Environment = LIVE) -> Self:
        obj = cls(environment=environment)
        await obj.load_session(path)
        return obj

    def _install_store(self, store: SigsigStore) -> None:
        self._store = store
        f = store.file
        self._http = HttpClient(
            credentials=HttpCredentials.for_account(
                aci=f.aci, device_id=f.device_id, password=f.password
            ),
            environment=self._env,
        )

    # ------------------------------------------------------------------
    # Handler registration
    # ------------------------------------------------------------------

    def on(self, event_type: type[E]) -> Callable[[Handler[E]], Handler[E]]:
        def _register(handler: Handler[E]) -> Handler[E]:
            self._registry.register(event_type, handler)
            return handler

        return _register

    def off(self, event_type: type[E], handler: Handler[E]) -> None:
        self._registry.unregister(event_type, handler)

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    async def send_message(
        self,
        recipient: ServiceId | Group | str,
        *,
        text: str,
        expires_in_seconds: int = 0,
    ) -> SendResult:
        self._ensure_session()
        assert self._http is not None and self._store is not None

        if isinstance(recipient, Group):
            return await send_group_text_message(
                http=self._http,
                store=self._store.aci_store,
                group=recipient,
                text=text,
                expire_timer_s=expires_in_seconds,
                our_aci=self._store.file.aci,
                our_device_id=self._store.file.device_id,
            )
        recipient_id = self._coerce_recipient(recipient)
        return await send_text_message(
            http=self._http,
            store=self._store.aci_store,
            recipient=recipient_id,
            text=text,
            expire_timer_s=expires_in_seconds,
            our_aci=self._store.file.aci,
            our_device_id=self._store.file.device_id,
        )

    # ------------------------------------------------------------------
    # Groups V2
    # ------------------------------------------------------------------

    async def fetch_group_members(self, master_key: bytes) -> Group:
        """Return a :class:`Group` with its members populated from the server.

        Requires that the current account is actually a member of the group
        (the server rejects auth-credential presentations otherwise).
        """
        import time

        self._ensure_session()
        assert self._http is not None and self._store is not None
        members = await _fetch_group_members(
            master_key=master_key,
            aci=self._store.file.aci,
            pni=self._store.file.pni,
            chat_http=self._http,
            today_seconds=int(time.time()),
        )
        return Group(master_key=master_key, members=tuple(members))

    # ------------------------------------------------------------------
    # Receive loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        self._ensure_session()
        assert self._store is not None
        f = self._store.file

        self._ws = await AuthenticatedWebSocket.connect(
            aci=f.aci,
            device_id=f.device_id,
            password=f.password,
            environment=self._env,
        )
        self._receive_task = asyncio.create_task(
            run_receive_loop(
                ws=self._ws,
                store=self._store.aci_store,
                registry=self._registry,
                our_aci=f.aci,
                our_device_id=f.device_id,
            ),
            name="sigsig-receive",
        )
        try:
            await self._receive_task
        finally:
            await self._ws.close()
            self._ws = None

    async def stop(self) -> None:
        if self._receive_task is not None:
            self._receive_task.cancel()
            try:
                await self._receive_task
            except (asyncio.CancelledError, SigsigError):
                pass
            self._receive_task = None
        if self._ws is not None:
            await self._ws.close()
            self._ws = None

    async def aclose(self) -> None:
        await self.stop()
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def __aenter__(self) -> "Client":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    # ------------------------------------------------------------------
    # Helpers / introspection
    # ------------------------------------------------------------------

    def _ensure_session(self) -> None:
        if self._store is None:
            raise SessionError("client not logged in; call qr_login or load_session first")

    @staticmethod
    def _coerce_recipient(recipient: ServiceId | str) -> ServiceId:
        if isinstance(recipient, ServiceId):
            return recipient
        return ServiceId.parse(recipient)

    @property
    def aci(self) -> str | None:
        return self._store.file.aci if self._store else None

    @property
    def pni(self) -> str | None:
        return self._store.file.pni if self._store else None

    @property
    def number(self) -> str | None:
        return self._store.file.number if self._store else None

    @property
    def device_id(self) -> int | None:
        return self._store.file.device_id if self._store else None
