"""Common typed identifiers used across sigsig."""

from __future__ import annotations

import enum
import re
import uuid
from dataclasses import dataclass
from typing import Self

# Signal device IDs are small positive integers (primary is always 1).
DeviceId = int
# Registration IDs are 14-bit random values (0 .. 16383).
RegistrationId = int
# Signal PreKey / SignedPreKey / KyberPreKey IDs are 32-bit but kept < 2^24 in practice.
PreKeyId = int


class ServiceIdKind(enum.StrEnum):
    """Which identity namespace a ServiceId refers to."""

    ACI = "ACI"   # Account identity — stable, survives phone-number changes.
    PNI = "PNI"   # Phone-number identity — changes on number change.


_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


@dataclass(frozen=True, slots=True)
class ServiceId:
    """Tagged UUID identifying a Signal account or phone-number identity.

    The on-the-wire encoding is:
      - ACI: bare UUID string ``"d8f1a6c2-..."``
      - PNI: ``"PNI:c9e7b1d0-..."``
    """

    kind: ServiceIdKind
    uuid: uuid.UUID

    @classmethod
    def aci(cls, value: str | uuid.UUID) -> Self:
        return cls(ServiceIdKind.ACI, value if isinstance(value, uuid.UUID) else uuid.UUID(value))

    @classmethod
    def pni(cls, value: str | uuid.UUID) -> Self:
        return cls(ServiceIdKind.PNI, value if isinstance(value, uuid.UUID) else uuid.UUID(value))

    @classmethod
    def parse(cls, value: str) -> Self:
        """Parse the canonical wire form."""
        if value.startswith("PNI:"):
            return cls.pni(value[4:])
        if value.startswith("aci:"):
            return cls.aci(value[4:])
        if _UUID_RE.match(value):
            return cls.aci(value)
        raise ValueError(f"not a ServiceId: {value!r}")

    @property
    def service_id_string(self) -> str:
        """Wire format used in HTTP paths and protobuf ``service_id`` fields."""
        if self.kind is ServiceIdKind.PNI:
            return f"PNI:{self.uuid}"
        return str(self.uuid)

    def __str__(self) -> str:
        return self.service_id_string


def parse_recipient(value: str | ServiceId) -> ServiceId | str:
    """Accept a user-supplied recipient and return either a ServiceId or a raw E.164.

    - ``ServiceId`` → returned as-is.
    - ``"aci:<uuid>"`` / ``"PNI:<uuid>"`` / bare UUID → parsed as ServiceId.
    - ``"+<digits>"`` → returned as an E.164 string (caller must then resolve via CDSI).
    """
    if isinstance(value, ServiceId):
        return value
    s = value.strip()
    if s.startswith("+") and s[1:].isdigit():
        return s
    return ServiceId.parse(s)
