"""Fetch Groups V2 state from Signal's server.

Flow (see signal-cli ``GroupsV2Api.java`` / libsignal ``zkgroup``):

1. ``GET /v1/certificate/auth/group`` on chat.signal.org with our regular
   Basic auth — returns 7 days of ``AuthCredentialWithPniResponse`` blobs
   (one per day, redemption-day-aligned).
2. Pick today's credential; verify it against ``ZKGROUP_SERVER_PUBLIC_PARAMS``
   and bind to our ACI + PNI + redemption timestamp.
3. Derive ``GroupSecretParams`` from the group's master_key.
4. Build a zero-knowledge ``AuthCredentialPresentation`` over
   (server_public_params, group_secret_params, credential).
5. ``GET /v2/groups/`` on storage.signal.org with Basic auth
   ``hex(group_public_params):hex(presentation)``. Returns ``GroupResponse``
   protobuf; the inner ``Group`` has encrypted members.
6. Decrypt each ``Member.userId`` with ``GroupSecretParams`` to get the ACI.
"""

from __future__ import annotations

import base64
import secrets
import uuid
from dataclasses import dataclass
from typing import Any

from sigsig_libsignal._libsignal import (  # type: ignore[import-not-found]
    zkgroup_auth_presentation,
    zkgroup_decrypt_uuid_ciphertext,
    zkgroup_group_public_params,
    zkgroup_group_secret_params,
    zkgroup_receive_auth_credential,
)

from sigsig._proto import Groups_pb2 as groups_pb
from sigsig.config import GROUPS_V2_HOST, ZKGROUP_SERVER_PUBLIC_PARAMS
from sigsig.errors import ProtocolError
from sigsig.transport.http import HttpClient, HttpCredentials
from sigsig.types import ServiceId


SECONDS_PER_DAY = 86400


@dataclass(slots=True, frozen=True)
class AuthCredential:
    redemption_time_seconds: int
    credential_bytes: bytes   # raw AuthCredentialWithPniResponse bytes


async def fetch_auth_credentials(
    http: HttpClient, *, today_seconds: int
) -> list[AuthCredential]:
    start = (today_seconds // SECONDS_PER_DAY) * SECONDS_PER_DAY
    end = start + 7 * SECONDS_PER_DAY
    resp = await http.get(
        "/v1/certificate/auth/group",
        params={"redemptionStartSeconds": start, "redemptionEndSeconds": end},
    )
    body = resp.json()
    out: list[AuthCredential] = []
    for c in body.get("credentials", []):
        out.append(
            AuthCredential(
                redemption_time_seconds=int(c["redemptionTime"]),
                credential_bytes=base64.b64decode(c["credential"]),
            )
        )
    return out


def _aci_uuid_bytes(aci: str) -> bytes:
    return uuid.UUID(aci.removeprefix("aci:")).bytes


def _pni_uuid_bytes(pni: str) -> bytes:
    return uuid.UUID(pni.removeprefix("PNI:")).bytes


def build_auth_header(
    *,
    master_key: bytes,
    aci: str,
    pni: str,
    credential: AuthCredential,
) -> tuple[str, bytes]:
    """Return ``(Authorization header value, group_secret_params)``."""
    gsp = zkgroup_group_secret_params(master_key)
    auth_cred = zkgroup_receive_auth_credential(
        ZKGROUP_SERVER_PUBLIC_PARAMS,
        credential.credential_bytes,
        _aci_uuid_bytes(aci),
        _pni_uuid_bytes(pni),
        credential.redemption_time_seconds,
    )
    randomness = secrets.token_bytes(32)
    presentation = zkgroup_auth_presentation(
        ZKGROUP_SERVER_PUBLIC_PARAMS, gsp, auth_cred, randomness
    )
    gpp = zkgroup_group_public_params(gsp)
    username = gpp.hex()
    password = presentation.hex()
    token = base64.b64encode(f"{username}:{password}".encode("ascii")).decode("ascii")
    return "Basic " + token, gsp


async def fetch_group_members(
    *,
    master_key: bytes,
    aci: str,
    pni: str,
    chat_http: HttpClient,
    today_seconds: int,
) -> list[ServiceId]:
    """Download + decrypt the group state, return member ACIs."""
    credentials = await fetch_auth_credentials(chat_http, today_seconds=today_seconds)
    today_start = (today_seconds // SECONDS_PER_DAY) * SECONDS_PER_DAY
    today_cred = next(
        (c for c in credentials if c.redemption_time_seconds == today_start), None
    )
    if today_cred is None:
        raise ProtocolError("no auth credential for today in /v1/certificate/auth/group response")

    auth, gsp = build_auth_header(
        master_key=master_key, aci=aci, pni=pni, credential=today_cred
    )

    async with _storage_client() as storage_http:
        resp = await storage_http.request(
            "GET",
            "/v2/groups/",
            headers={"Authorization": auth, "Accept": "application/x-protobuf"},
        )

    group_response = groups_pb.GroupResponse()
    group_response.ParseFromString(resp.content)
    group = group_response.group

    members: list[ServiceId] = []
    for m in group.members:
        aci_str = zkgroup_decrypt_uuid_ciphertext(gsp, m.userId)
        members.append(ServiceId.parse(aci_str))
    return members


def _storage_client() -> HttpClient:
    from sigsig.config import LIVE

    storage_env = type(LIVE)(
        chat_http_url=GROUPS_V2_HOST,
        chat_ws_url=LIVE.chat_ws_url,
        storage_url=LIVE.storage_url,
        cdn_urls=LIVE.cdn_urls,
        cdsi_url=LIVE.cdsi_url,
        unidentified_sender_trust_root=LIVE.unidentified_sender_trust_root,
    )
    return HttpClient(
        credentials=HttpCredentials(username=None, password=None),
        environment=storage_env,
    )
