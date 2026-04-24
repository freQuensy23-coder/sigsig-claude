"""Build the upload payloads expected by PUT /v2/keys and /v1/devices/link.

Wire shape follows libsignal-service-java's ``LinkDeviceRequest``,
``AccountAttributes`` and ``SignedPreKeyEntity`` / ``KyberPreKeyEntity``
(see the Turasa fork mirror). Base64 values are **unpadded** — the
Jackson serializers use ``Base64.encodeWithoutPadding``.
"""

from __future__ import annotations

import base64
from typing import Any


def _b64(data: bytes) -> str:
    """Standard base64, unpadded — matches libsignal-service-java."""
    return base64.b64encode(data).decode("ascii").rstrip("=")


def signed_pre_key_entity(
    key_id: int, public: bytes, signature: bytes
) -> dict[str, Any]:
    """JSON shape of ``SignedPreKeyEntity``."""
    return {
        "keyId": key_id,
        "publicKey": _b64(public),
        "signature": _b64(signature),
    }


def kyber_pre_key_entity(
    key_id: int, public: bytes, signature: bytes
) -> dict[str, Any]:
    """JSON shape of ``KyberPreKeyEntity``."""
    return {
        "keyId": key_id,
        "publicKey": _b64(public),
        "signature": _b64(signature),
    }


def build_account_attributes(
    *,
    signaling_key: bytes | None,
    registration_id: int,
    pni_registration_id: int,
    name: str | None,
    capabilities: dict[str, bool],
    unrestricted_unidentified_access: bool = False,
    unidentified_access_key: bytes | None = None,
    fetches_messages: bool = True,
    discoverable_by_phone_number: bool = False,
    registration_lock: str | None = None,
    recovery_password: str | None = None,
) -> dict[str, Any]:
    """JSON shape of the ``AccountAttributes`` posted to /v1/devices/link.

    Fields line up with ``AccountAttributes.kt`` in libsignal-service-java.
    """
    return {
        "signalingKey": _b64(signaling_key) if signaling_key is not None else None,
        "registrationId": registration_id,
        "voice": True,
        "video": True,
        "fetchesMessages": fetches_messages,
        "registrationLock": registration_lock,
        "unidentifiedAccessKey": (
            _b64(unidentified_access_key) if unidentified_access_key is not None else None
        ),
        "unrestrictedUnidentifiedAccess": unrestricted_unidentified_access,
        "discoverableByPhoneNumber": discoverable_by_phone_number,
        "capabilities": capabilities,
        "name": name,
        "pniRegistrationId": pni_registration_id,
        "recoveryPassword": recovery_password,
    }


def build_link_device_request(
    *,
    verification_code: str,
    account_attributes: dict[str, Any],
    aci_signed_pre_key_id: int,
    aci_signed_pre_key_public: bytes,
    aci_signed_pre_key_signature: bytes,
    pni_signed_pre_key_id: int,
    pni_signed_pre_key_public: bytes,
    pni_signed_pre_key_signature: bytes,
    aci_pq_last_resort_id: int,
    aci_pq_last_resort_public: bytes,
    aci_pq_last_resort_signature: bytes,
    pni_pq_last_resort_id: int,
    pni_pq_last_resort_public: bytes,
    pni_pq_last_resort_signature: bytes,
) -> dict[str, Any]:
    """Shape of ``LinkDeviceRequest`` for ``PUT /v1/devices/link``."""
    return {
        "verificationCode": verification_code,
        "accountAttributes": account_attributes,
        "aciSignedPreKey": signed_pre_key_entity(
            aci_signed_pre_key_id,
            aci_signed_pre_key_public,
            aci_signed_pre_key_signature,
        ),
        "pniSignedPreKey": signed_pre_key_entity(
            pni_signed_pre_key_id,
            pni_signed_pre_key_public,
            pni_signed_pre_key_signature,
        ),
        "aciPqLastResortPreKey": kyber_pre_key_entity(
            aci_pq_last_resort_id,
            aci_pq_last_resort_public,
            aci_pq_last_resort_signature,
        ),
        "pniPqLastResortPreKey": kyber_pre_key_entity(
            pni_pq_last_resort_id,
            pni_pq_last_resort_public,
            pni_pq_last_resort_signature,
        ),
    }
