"""sigsig — async Python client for Signal."""

from sigsig import events
from sigsig.client import Client
from sigsig.groups import Group
from sigsig.errors import (
    AuthenticationFailed,
    MismatchedDevices,
    ProtocolError,
    ProvisioningError,
    ServerError,
    SessionError,
    SigsigError,
    StaleDevices,
    TransportError,
)
from sigsig.types import DeviceId, PreKeyId, RegistrationId, ServiceId, ServiceIdKind

__all__ = [
    "AuthenticationFailed",
    "Client",
    "DeviceId",
    "Group",
    "MismatchedDevices",
    "PreKeyId",
    "ProtocolError",
    "ProvisioningError",
    "RegistrationId",
    "ServerError",
    "ServiceId",
    "ServiceIdKind",
    "SessionError",
    "SigsigError",
    "StaleDevices",
    "TransportError",
    "events",
]
