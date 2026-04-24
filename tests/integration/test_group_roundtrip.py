"""Groups V2 send/receive over libsignal + mock server.

Alice sends a ``DataMessage`` with ``groupV2`` set to every member's ACI.
Bob is a member; his receive loop decrypts and emits a
:class:`sigsig.events.GroupTextMessage` with the group master key echoed
back through.
"""

from __future__ import annotations

import asyncio
import base64

import pytest

from sigsig import Group
from sigsig._proto import SignalService_pb2 as svc_pb
from sigsig.config import Environment
from sigsig.events import GroupTextMessage
from sigsig.types import ServiceId
from tests.fixtures.mock_signal_server import running_mock_server
from tests.integration.test_sigsig_roundtrip import _make_client, _prekey_bundle_dict


@pytest.mark.asyncio
async def test_group_send_and_receive() -> None:
    async with running_mock_server() as (mock, http_base, ws_base):
        env = Environment(chat_http_url=http_base, chat_ws_url=ws_base)

        alice_aci = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        bob_aci = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

        alice, _ = _make_client(
            aci=alice_aci,
            pni="11111111-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            device_id=1,
            number="+1",
            password="alice-pw",
        )
        bob, bob_store = _make_client(
            aci=bob_aci,
            pni="22222222-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            device_id=1,
            number="+2",
            password="bob-pw",
        )
        alice._env = env  # type: ignore[attr-defined]
        bob._env = env  # type: ignore[attr-defined]
        alice._install_store(alice._store)  # type: ignore[attr-defined]
        bob._install_store(bob._store)  # type: ignore[attr-defined]

        mock.prekey_bundles[bob_aci] = _prekey_bundle_dict(
            store=bob_store.aci_store, device_id=1
        )

        master_key = bytes(range(32))
        group = Group(master_key=master_key, members=(ServiceId.parse(bob_aci),))

        received: list[GroupTextMessage] = []
        done = asyncio.Event()

        @bob.on(GroupTextMessage)
        async def on_group(msg: GroupTextMessage) -> None:
            received.append(msg)
            done.set()

        run_task = asyncio.create_task(bob.run())
        try:
            for _ in range(100):
                if mock._authenticated_ws_events:  # noqa: SLF001
                    break
                await asyncio.sleep(0.01)

            send_result = await alice.send_message(group, text="hello group, from alice")

            assert mock.captured_message_requests, "alice's group send didn't hit the mock"
            msg_req = mock.captured_message_requests[-1]
            payload = msg_req.json_body["messages"][0]
            ciphertext = base64.b64decode(payload["content"])

            envelope = svc_pb.Envelope()
            envelope.type = payload["type"]
            envelope.sourceServiceId = alice_aci
            envelope.sourceDeviceId = 1
            envelope.destinationServiceId = bob_aci
            envelope.clientTimestamp = send_result.timestamp_ms
            envelope.serverTimestamp = send_result.timestamp_ms + 100
            envelope.content = ciphertext

            await mock.push_envelope(envelope)
            await asyncio.wait_for(done.wait(), timeout=5)
        finally:
            await bob.stop()
            run_task.cancel()
            try:
                await run_task
            except asyncio.CancelledError:
                pass
            await alice.aclose()
            await bob.aclose()

    assert len(received) == 1
    ev = received[0]
    assert ev.text == "hello group, from alice"
    assert ev.group_master_key == master_key
    assert str(ev.sender) == alice_aci
