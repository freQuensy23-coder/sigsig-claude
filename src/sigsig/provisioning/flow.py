"""QR linked-device flow.

1. Open the unauthenticated provisioning WebSocket.
2. Receive a ``ProvisioningAddress`` and emit a ``sgnl://linkdevice?...``
   URL via a user callback.
3. Receive an encrypted ``ProvisionEnvelope`` when the primary scans.
4. DH-decrypt it with :mod:`sigsig.crypto.provisioning_cipher`.
5. Generate prekeys via libsignal (real XEd25519 + Kyber1024 signatures).
6. ``PUT /v1/devices/link``.
7. Return a :class:`SigsigStore` reflecting the new linked device.

Signal's provisioning WS has a hard ~90 s session lifetime (closes with
``CLOSE 1000 Timeout`` regardless of keepalives), so :func:`link_device`
transparently reconnects and re-emits a fresh QR each time, keeping the
same temporary keypair so the primary sees a consistent public key
across reconnects.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from sigsig_libsignal._libsignal import (  # type: ignore[import-not-found]
    SignalStore,
    generate_registration_id,
    identity_key_pair_from_raw,
)

from sigsig._proto import Provisioning_pb2 as prov_pb
from sigsig.config import (
    DEFAULT_CAPABILITIES,
    LIVE,
    PREKEY_BATCH_SIZE,
    PRIMARY_DEVICE_ID,
    Environment,
)
from sigsig.crypto import provisioning_cipher
from sigsig.crypto.curve25519 import KeyPair, PublicKey
from sigsig.crypto.uak import derive_access_key
from sigsig.errors import ProvisioningError
from sigsig.keys.generate import generate_password
from sigsig.keys.upload import build_account_attributes, build_link_device_request
from sigsig.provisioning.qr import build_link_url
from sigsig.session.store import SigsigStore
from sigsig.transport.http import HttpClient, HttpCredentials
from sigsig.transport.ws import ProvisioningWebSocket

log = logging.getLogger(__name__)

UrlCallback = Callable[[str], Awaitable[None] | None]

PROVISIONING_TIMEOUT = 5 * 60
WS_ATTEMPT_TIMEOUT = 120


@dataclass(slots=True)
class LinkDeviceResult:
    store: SigsigStore
    provisioning_url: str


async def link_device(
    *,
    device_name: str = "sigsig",
    environment: Environment = LIVE,
    on_url: UrlCallback | None = None,
    timeout: float = PROVISIONING_TIMEOUT,
    one_time_prekey_count: int = PREKEY_BATCH_SIZE,
) -> LinkDeviceResult:
    temp_keypair = KeyPair.generate()
    provisioning_password = generate_password()
    deadline = asyncio.get_running_loop().time() + timeout

    session_uuid, envelope = await _wait_for_envelope(
        temp_keypair=temp_keypair,
        on_url=on_url,
        environment=environment,
        deadline=deadline,
        timeout=timeout,
    )

    plaintext = provisioning_cipher.decrypt(
        envelope.body,
        their_public=PublicKey.deserialize(envelope.publicKey),
        our_private=temp_keypair.private,
    )
    provision = prov_pb.ProvisionMessage()
    provision.ParseFromString(plaintext)

    return await _finish_link_device(
        provision=provision,
        environment=environment,
        provisioning_password=provisioning_password,
        device_name=device_name,
        one_time_prekey_count=one_time_prekey_count,
        session_uuid=session_uuid,
    )


class _WebSocketExpired(Exception):
    """Raised internally when the provisioning WS closes before an envelope arrives."""


async def _wait_for_envelope(
    *,
    temp_keypair: KeyPair,
    on_url: UrlCallback | None,
    environment: Environment,
    deadline: float,
    timeout: float,
) -> tuple[str, prov_pb.ProvisionEnvelope]:
    attempt = 0
    while True:
        attempt += 1
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise ProvisioningError(f"timed out waiting for primary to scan ({timeout:.0f}s)")
        log.info("opening provisioning WS (attempt %d, %.0fs budget left)", attempt, remaining)

        ws = await ProvisioningWebSocket.connect(environment=environment)
        try:
            return await asyncio.wait_for(
                _read_provision_envelope(ws, temp_keypair, on_url),
                timeout=min(remaining, WS_ATTEMPT_TIMEOUT),
            )
        except _WebSocketExpired:
            log.info("provisioning WS expired; reconnecting")
        except asyncio.TimeoutError:
            pass
        finally:
            await ws.close()


async def _read_provision_envelope(
    ws: ProvisioningWebSocket,
    temp_keypair: KeyPair,
    on_url: UrlCallback | None,
) -> tuple[str, prov_pb.ProvisionEnvelope]:
    session_uuid: str | None = None
    async for req in ws.requests():
        log.info("provisioning push: verb=%s path=%s body_len=%d", req.verb, req.path, len(req.body))
        await req.ack(200)

        if session_uuid is None:
            addr = prov_pb.ProvisioningAddress()
            addr.ParseFromString(req.body)
            session_uuid = addr.address
            url = build_link_url(session_uuid=session_uuid, public_key=temp_keypair.public)
            if on_url is not None:
                await _maybe_await(on_url(url))
            continue

        envelope = prov_pb.ProvisionEnvelope()
        envelope.ParseFromString(req.body)
        return session_uuid, envelope

    raise _WebSocketExpired


async def _maybe_await(value: Awaitable[None] | None) -> None:
    if value is not None:
        await value


async def _finish_link_device(
    *,
    provision: prov_pb.ProvisionMessage,
    environment: Environment,
    provisioning_password: str,
    device_name: str,
    one_time_prekey_count: int,
    session_uuid: str,
) -> LinkDeviceResult:
    if not provision.aciIdentityKeyPublic or not provision.aciIdentityKeyPrivate:
        raise ProvisioningError("ProvisionMessage missing ACI identity keypair")
    if not provision.pniIdentityKeyPublic or not provision.pniIdentityKeyPrivate:
        raise ProvisioningError("ProvisionMessage missing PNI identity keypair")
    if not provision.aci or not provision.pni:
        raise ProvisioningError("ProvisionMessage missing aci/pni")

    # Turn the raw (public, private) bytes into libsignal's IdentityKeyPair
    # serialization, then feed each to its own SignalStore.
    aci_identity_bytes = identity_key_pair_from_raw(
        provision.aciIdentityKeyPublic, provision.aciIdentityKeyPrivate
    )
    pni_identity_bytes = identity_key_pair_from_raw(
        provision.pniIdentityKeyPublic, provision.pniIdentityKeyPrivate
    )

    aci_registration_id = generate_registration_id()
    pni_registration_id = generate_registration_id()

    aci_store = SignalStore.from_identity(aci_identity_bytes, aci_registration_id)

    # Generate the ACI prekeys we'll upload. These are libsignal-signed,
    # stored inside the ACI store so that the matching private keys are
    # available when a peer sends a PreKeySignalMessage.
    aci_spk_id, aci_spk_pub, aci_spk_sig = aci_store.generate_signed_pre_key(1)
    aci_kyber_id, aci_kyber_pub, aci_kyber_sig = aci_store.generate_kyber_pre_key(1)
    _ = aci_store.generate_pre_keys(1, one_time_prekey_count)

    # PNI prekeys must also be uploaded at link time. We don't keep a
    # persistent PNI session store (we never use it to send or receive
    # 1:1 messages), so build a throw-away SignalStore solely to produce
    # and sign the prekeys.
    pni_store = SignalStore.from_identity(pni_identity_bytes, pni_registration_id)
    pni_spk_id, pni_spk_pub, pni_spk_sig = pni_store.generate_signed_pre_key(1)
    pni_kyber_id, pni_kyber_pub, pni_kyber_sig = pni_store.generate_kyber_pre_key(1)

    profile_key = bytes(provision.profileKey) or None
    uak = derive_access_key(profile_key) if profile_key else None

    attrs = build_account_attributes(
        signaling_key=None,
        registration_id=aci_registration_id,
        pni_registration_id=pni_registration_id,
        name=None,
        capabilities=DEFAULT_CAPABILITIES,
        unidentified_access_key=uak,
    )
    link_body = build_link_device_request(
        verification_code=provision.provisioningCode,
        account_attributes=attrs,
        aci_signed_pre_key_id=aci_spk_id,
        aci_signed_pre_key_public=aci_spk_pub,
        aci_signed_pre_key_signature=aci_spk_sig,
        pni_signed_pre_key_id=pni_spk_id,
        pni_signed_pre_key_public=pni_spk_pub,
        pni_signed_pre_key_signature=pni_spk_sig,
        aci_pq_last_resort_id=aci_kyber_id,
        aci_pq_last_resort_public=aci_kyber_pub,
        aci_pq_last_resort_signature=aci_kyber_sig,
        pni_pq_last_resort_id=pni_kyber_id,
        pni_pq_last_resort_public=pni_kyber_pub,
        pni_pq_last_resort_signature=pni_kyber_sig,
    )

    async with HttpClient(
        credentials=HttpCredentials(username=provision.number, password=provisioning_password),
        environment=environment,
    ) as http:
        resp = await http.put("/v1/devices/link", json_body=link_body)

    device_id = int(resp.json().get("deviceId", PRIMARY_DEVICE_ID))

    store = SigsigStore.fresh(
        number=provision.number,
        aci=provision.aci,
        pni=provision.pni,
        device_id=device_id,
        password=provisioning_password,
        aci_identity_bytes=aci_identity_bytes,
        aci_registration_id=aci_registration_id,
        pni_identity_bytes=pni_identity_bytes,
        profile_key=profile_key,
        account_entropy_pool=provision.accountEntropyPool or None,
        media_root_backup_key=bytes(provision.mediaRootBackupKey) or None,
    )
    # The ACI store we just generated prekeys into becomes the canonical
    # store; overwrite the fresh empty one that ``SigsigStore.fresh`` built.
    store.aci_store = aci_store
    store.file.signal_store_blob = aci_store.serialize()

    # Public identity key for the returned URL display.
    aci_public_key = PublicKey.deserialize(provision.aciIdentityKeyPublic)
    return LinkDeviceResult(
        store=store,
        provisioning_url=build_link_url(
            session_uuid=session_uuid, public_key=aci_public_key
        ),
    )


# The link-request body grew more fields than a positional kwargs call
# comfortably handles; keep it here as a local shim that forwards to the
# builder in sigsig.keys.upload.
__all__ = ["LinkDeviceResult", "link_device"]
