"""End-to-end sigsig ↔ sigsig exchange through libsignal + mock server.

Two SigsigStore / Client instances are wired against the same mock Signal
server. Client B publishes a PreKeyBundle; Client A processes it and
sends a DataMessage; the mock relays the envelope to Client B's
authenticated WS; Client B's receive loop decrypts via libsignal and
emits a TextMessage event.

This exercises *every* piece of the stack except real Signal server
authentication: the Rust wrapper (X3DH + PQXDH, Double Ratchet,
signature verification), the transport layer, the protobuf framing, the
session/store round-trip, and the event dispatcher.
"""

from __future__ import annotations

import asyncio
import base64

import pytest

from sigsig_libsignal._libsignal import (  # type: ignore[import-not-found]
    SignalStore,
    generate_identity_key_pair,
    generate_registration_id,
)

from sigsig._proto import SignalService_pb2 as svc_pb
from sigsig.client import Client
from sigsig.config import Environment
from sigsig.events import TextMessage
from sigsig.session.state import SessionFile
from sigsig.session.store import SigsigStore
from sigsig.types import ServiceId
from tests.fixtures.mock_signal_server import running_mock_server


def _make_client(*, aci: str, pni: str, device_id: int, number: str, password: str) -> tuple[Client, SigsigStore]:
    ikp = generate_identity_key_pair()
    rid = generate_registration_id()
    aci_store = SignalStore.from_identity(ikp, rid)
    pni_ikp = generate_identity_key_pair()
    file = SessionFile(
        number=number,
        device_id=device_id,
        aci=aci,
        pni=pni,
        password=password,
        pni_identity_key_pair=pni_ikp,
        signal_store_blob=aci_store.serialize(),
    )
    store = SigsigStore(file=file, aci_store=aci_store, pni_identity_bytes=pni_ikp)
    client = Client()
    client._install_store(store)  # type: ignore[attr-defined]
    return client, store


def _prekey_bundle_dict(*, store: SignalStore, device_id: int) -> dict:
    """Create and store a fresh PreKeyBundle on ``store`` side, then shape it
    into the JSON PreKeyBundle response the sender's ``send`` code expects."""
    spk_id, spk_pub, spk_sig = store.generate_signed_pre_key(100)
    kyb_id, kyb_pub, kyb_sig = store.generate_kyber_pre_key(100)
    [(otp_id, otp_pub)] = store.generate_pre_keys(200, 1)

    def _b64(v: bytes) -> str:
        return base64.b64encode(v).decode("ascii").rstrip("=")

    return {
        "identityKey": _b64(store.identity_public()),
        "devices": [
            {
                "deviceId": device_id,
                "registrationId": store.registration_id(),
                "signedPreKey": {
                    "keyId": spk_id,
                    "publicKey": _b64(spk_pub),
                    "signature": _b64(spk_sig),
                },
                "pqPreKey": {
                    "keyId": kyb_id,
                    "publicKey": _b64(kyb_pub),
                    "signature": _b64(kyb_sig),
                },
                "preKey": {
                    "keyId": otp_id,
                    "publicKey": _b64(otp_pub),
                },
            }
        ],
    }


@pytest.mark.asyncio
async def test_sigsig_to_sigsig_message() -> None:
    async with running_mock_server() as (mock, http_base, ws_base):
        env = Environment(chat_http_url=http_base, chat_ws_url=ws_base)

        alice_aci = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        alice_pni = "11111111-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        bob_aci = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        bob_pni = "22222222-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

        alice, _ = _make_client(
            aci=alice_aci, pni=alice_pni, device_id=1, number="+1", password="alice-pw"
        )
        bob, bob_store = _make_client(
            aci=bob_aci, pni=bob_pni, device_id=1, number="+2", password="bob-pw"
        )
        alice._env = env  # type: ignore[attr-defined]
        bob._env = env  # type: ignore[attr-defined]
        # HttpClient was built with the default LIVE environment — rebuild.
        alice._install_store(alice._store)  # type: ignore[attr-defined]
        bob._install_store(bob._store)  # type: ignore[attr-defined]

        mock.prekey_bundles[bob_aci] = _prekey_bundle_dict(
            store=bob_store.aci_store, device_id=1
        )

        received: list[TextMessage] = []
        done = asyncio.Event()

        @bob.on(TextMessage)
        async def on_text(msg: TextMessage) -> None:
            received.append(msg)
            done.set()

        run_task = asyncio.create_task(bob.run())
        try:
            # Wait for Bob's WS to connect.
            for _ in range(100):
                if mock._authenticated_ws_events:  # noqa: SLF001
                    break
                await asyncio.sleep(0.01)

            # Alice sends. This triggers: GET /v2/keys, process_pre_key_bundle,
            # encrypt (type 3 PreKeySignalMessage the first time),
            # PUT /v1/messages.
            send_result = await alice.send_message(ServiceId.parse(bob_aci), text="hello bob, from alice")

            # The mock intercepts the PUT /v1/messages and captures it, but
            # doesn't automatically forward to Bob's WS. Do that manually by
            # pulling the last message and re-wrapping in an Envelope.
            assert mock.captured_message_requests, "alice's send didn't hit the mock"
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
    assert received[0].text == "hello bob, from alice"
    assert str(received[0].sender) == alice_aci
