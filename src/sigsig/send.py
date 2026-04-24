"""Message send pipeline.

1. Resolve the caller's recipient to a :class:`ServiceId`.
2. If the libsignal session for ``(service_id, device_id)`` isn't cached,
   fetch a PreKeyBundle from ``GET /v2/keys/{serviceId}/*`` and call
   ``SignalStore.process_pre_key_bundle`` (X3DH + PQXDH).
3. ``SignalStore.encrypt`` produces either a SignalMessage (envelope
   type 1 = DOUBLE_RATCHET) or a PreKeySignalMessage (envelope
   type 3 = PREKEY_MESSAGE).
4. ``PUT /v1/messages/{serviceId}`` carrying the per-device envelope list.
"""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass
from typing import Any

from sigsig_libsignal._libsignal import SignalStore  # type: ignore[import-not-found]

from sigsig._proto import SignalService_pb2 as svc_pb
from sigsig.errors import MismatchedDevices, ProtocolError, StaleDevices
from sigsig.transport.http import HttpClient
from sigsig.types import DeviceId, ServiceId

log = logging.getLogger(__name__)


@dataclass(slots=True)
class SendResult:
    timestamp_ms: int
    server_response: dict[str, Any]


# Type byte mapping returned by SignalStore.encrypt → Envelope.Type.
# Whisper(2) → DOUBLE_RATCHET(1); PreKey(3) → PREKEY_MESSAGE(3).
_CIPHER_TYPE_TO_ENVELOPE = {
    2: int(svc_pb.Envelope.DOUBLE_RATCHET),
    3: int(svc_pb.Envelope.PREKEY_MESSAGE),
}


async def send_text_message(
    *,
    http: HttpClient,
    store: SignalStore,
    recipient: ServiceId,
    text: str,
    expire_timer_s: int = 0,
    our_aci: str | None = None,
    our_device_id: int | None = None,
) -> SendResult:
    now_ms = int(time.time() * 1000)

    dm = svc_pb.DataMessage()
    dm.body = text
    dm.timestamp = now_ms
    if expire_timer_s:
        dm.expireTimer = expire_timer_s
    content = svc_pb.Content()
    content.dataMessage.CopyFrom(dm)
    plaintext = _pad(content.SerializeToString())

    service_str = recipient.service_id_string
    bundles = await _fetch_all_bundles(http=http, recipient=recipient)

    skip_device = our_device_id if our_aci and service_str == our_aci else None

    messages: list[dict[str, Any]] = []
    for dev in bundles["devices"]:
        if dev["device_id"] == skip_device:
            continue
        device_id = dev["device_id"]
        try:
            cipher_type, ciphertext = store.encrypt(service_str, device_id, plaintext)
        except RuntimeError as exc:
            if "not found" not in str(exc):
                raise
            _install_bundle(store, recipient, bundles["identity_key"], dev)
            cipher_type, ciphertext = store.encrypt(service_str, device_id, plaintext)
        envelope_type = _CIPHER_TYPE_TO_ENVELOPE.get(cipher_type)
        if envelope_type is None:
            raise ProtocolError(f"unexpected cipher type {cipher_type} from libsignal")

        messages.append(
            {
                "type": envelope_type,
                "destinationDeviceId": device_id,
                "destinationRegistrationId": dev["registration_id"],
                "content": base64.b64encode(ciphertext).decode("ascii"),
            }
        )

    body = {
        "messages": messages,
        "online": False,
        "urgent": True,
        "timestamp": now_ms,
    }

    try:
        resp = await http.put(
            f"/v1/messages/{service_str}",
            json_body=body,
            params={"story": "false"},
        )
    except (MismatchedDevices, StaleDevices):
        raise

    return SendResult(timestamp_ms=now_ms, server_response=resp.json() if resp.content else {})


_PADDING_BLOCK_SIZE = 80


def _pad(body: bytes) -> bytes:
    """Append Signal's 0x80 + zero-fill padding (PushTransportDetails.java)."""
    length = len(body) + 1
    blocks = (length + _PADDING_BLOCK_SIZE - 1) // _PADDING_BLOCK_SIZE
    return body + b"\x80" + b"\x00" * (blocks * _PADDING_BLOCK_SIZE - length - 1)


async def _fetch_all_bundles(*, http: HttpClient, recipient: ServiceId) -> dict[str, Any]:
    resp = await http.get(f"/v2/keys/{recipient.service_id_string}/*")
    return _parse_prekey_bundle(resp.json())


def _install_bundle(
    store: SignalStore,
    recipient: ServiceId,
    identity_key: bytes,
    dev: dict[str, Any],
) -> None:
    store.process_pre_key_bundle(
        recipient.service_id_string,
        dev["device_id"],
        dev["registration_id"],
        identity_key,
        dev["signed_pre_key_id"],
        dev["signed_pre_key_public"],
        dev["signed_pre_key_signature"],
        dev["kyber_pre_key_id"],
        dev["kyber_pre_key_public"],
        dev["kyber_pre_key_signature"],
        (dev["one_time_pre_key_id"], dev["one_time_pre_key_public"])
        if dev["one_time_pre_key_public"] is not None
        else None,
    )


def _parse_prekey_bundle(data: dict[str, Any]) -> dict[str, Any]:
    def b64(s: str) -> bytes:
        # Signal omits base64 padding; restore before decoding.
        return base64.b64decode(s + "=" * (-len(s) % 4))

    identity_key = b64(data["identityKey"])
    devices: list[dict[str, Any]] = []
    for d in data.get("devices", []):
        spk = d["signedPreKey"]
        pqk = d.get("pqPreKey") or d.get("kyberPreKey")
        if pqk is None:
            raise ProtocolError("PreKeyBundle has no Kyber prekey — server is misconfigured")
        otp = d.get("preKey") or None
        devices.append(
            {
                "device_id": int(d["deviceId"]),
                "registration_id": int(d["registrationId"]),
                "signed_pre_key_id": int(spk["keyId"]),
                "signed_pre_key_public": b64(spk["publicKey"]),
                "signed_pre_key_signature": b64(spk["signature"]),
                "kyber_pre_key_id": int(pqk["keyId"]),
                "kyber_pre_key_public": b64(pqk["publicKey"]),
                "kyber_pre_key_signature": b64(pqk["signature"]),
                "one_time_pre_key_id": int(otp["keyId"]) if otp else None,
                "one_time_pre_key_public": b64(otp["publicKey"]) if otp else None,
            }
        )
    return {"identity_key": identity_key, "devices": devices}
