"""Message send pipeline.

1. Resolve the recipient (``ServiceId`` or :class:`sigsig.groups.Group`).
2. Fetch the recipient's PreKeyBundle via ``GET /v2/keys/{serviceId}/*``
   and install sessions for any devices we don't yet have.
3. Encrypt the padded ``Content`` via ``SignalStore.encrypt`` — produces
   either a SignalMessage (type 1 = DOUBLE_RATCHET) or a PreKeySignalMessage
   (type 3 = PREKEY_MESSAGE) per device.
4. ``PUT /v1/messages/{serviceId}`` with the per-device list.

Groups: ``DataMessage.groupV2`` is populated with ``{masterKey, revision}``
and the same envelope is fanned out to every member's ACI one by one.
"""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass
from typing import Any

from sigsig_libsignal._libsignal import SignalStore  # type: ignore[import-not-found]

from sigsig._proto import SignalService_pb2 as svc_pb
from sigsig.attachments import Attachment
from sigsig.attachments_api import upload_attachment
from sigsig.errors import ProtocolError
from sigsig.groups import Group
from sigsig.transport.http import HttpClient
from sigsig.types import DeviceId, ServiceId

log = logging.getLogger(__name__)


@dataclass(slots=True)
class SendResult:
    timestamp_ms: int
    server_response: dict[str, Any]


# Whisper(2) → DOUBLE_RATCHET(1); PreKey(3) → PREKEY_MESSAGE(3).
_CIPHER_TYPE_TO_ENVELOPE = {
    2: int(svc_pb.Envelope.DOUBLE_RATCHET),
    3: int(svc_pb.Envelope.PREKEY_MESSAGE),
}

_PADDING_BLOCK_SIZE = 80


def _pad(body: bytes) -> bytes:
    length = len(body) + 1
    blocks = (length + _PADDING_BLOCK_SIZE - 1) // _PADDING_BLOCK_SIZE
    return body + b"\x80" + b"\x00" * (blocks * _PADDING_BLOCK_SIZE - length - 1)


async def _build_text_content(
    *,
    text: str,
    expire_timer_s: int,
    group: Group | None,
    attachments: list[Attachment],
    http: HttpClient,
) -> tuple[bytes, int]:
    now_ms = int(time.time() * 1000)
    dm = svc_pb.DataMessage()
    dm.body = text
    dm.timestamp = now_ms
    if expire_timer_s:
        dm.expireTimer = expire_timer_s
    if group is not None:
        dm.groupV2.masterKey = group.master_key
        dm.groupV2.revision = group.revision
    for att in attachments:
        pointer = await upload_attachment(http=http, attachment=att)
        dm.attachments.append(pointer)
    content = svc_pb.Content()
    content.dataMessage.CopyFrom(dm)
    return _pad(content.SerializeToString()), now_ms


async def send_text_message(
    *,
    http: HttpClient,
    store: SignalStore,
    recipient: ServiceId,
    text: str,
    expire_timer_s: int = 0,
    our_aci: str | None = None,
    our_device_id: int | None = None,
    attachments: list[Attachment] | None = None,
) -> SendResult:
    plaintext, now_ms = await _build_text_content(
        text=text,
        expire_timer_s=expire_timer_s,
        group=None,
        attachments=attachments or [],
        http=http,
    )
    await _deliver_to_one(
        http=http,
        store=store,
        recipient=recipient,
        plaintext=plaintext,
        timestamp_ms=now_ms,
        our_aci=our_aci,
        our_device_id=our_device_id,
    )
    return SendResult(timestamp_ms=now_ms, server_response={})


async def send_group_text_message(
    *,
    http: HttpClient,
    store: SignalStore,
    group: Group,
    text: str,
    expire_timer_s: int = 0,
    our_aci: str | None = None,
    our_device_id: int | None = None,
    attachments: list[Attachment] | None = None,
) -> SendResult:
    plaintext, now_ms = await _build_text_content(
        text=text,
        expire_timer_s=expire_timer_s,
        group=group,
        attachments=attachments or [],
        http=http,
    )
    for member in group.members:
        if our_aci and member.service_id_string == our_aci:
            continue
        try:
            await _deliver_to_one(
                http=http,
                store=store,
                recipient=member,
                plaintext=plaintext,
                timestamp_ms=now_ms,
                our_aci=our_aci,
                our_device_id=our_device_id,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("group send to %s failed: %s", member, exc)
    return SendResult(timestamp_ms=now_ms, server_response={})


async def _deliver_to_one(
    *,
    http: HttpClient,
    store: SignalStore,
    recipient: ServiceId,
    plaintext: bytes,
    timestamp_ms: int,
    our_aci: str | None,
    our_device_id: int | None,
) -> None:
    service_str = recipient.service_id_string
    bundles = await _fetch_all_bundles(http=http, recipient=recipient)
    skip_device = our_device_id if our_aci and service_str == our_aci else None

    messages: list[dict[str, Any]] = []
    for dev in bundles["devices"]:
        device_id: DeviceId = dev["device_id"]
        if device_id == skip_device:
            continue
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

    await http.put(
        f"/v1/messages/{service_str}",
        json_body={
            "messages": messages,
            "online": False,
            "urgent": True,
            "timestamp": timestamp_ms,
        },
        params={"story": "false"},
    )


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
