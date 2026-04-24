import uuid

import pytest

from sigsig.types import ServiceId, ServiceIdKind, parse_recipient


def test_aci_parse_bare_uuid() -> None:
    sid = ServiceId.parse("d8f1a6c2-4f1b-4c0a-9e3a-0123456789ab")
    assert sid.kind is ServiceIdKind.ACI
    assert str(sid) == "d8f1a6c2-4f1b-4c0a-9e3a-0123456789ab"


def test_pni_parse_with_prefix() -> None:
    sid = ServiceId.parse("PNI:d8f1a6c2-4f1b-4c0a-9e3a-0123456789ab")
    assert sid.kind is ServiceIdKind.PNI
    assert sid.service_id_string == "PNI:d8f1a6c2-4f1b-4c0a-9e3a-0123456789ab"


def test_parse_invalid() -> None:
    with pytest.raises(ValueError):
        ServiceId.parse("not-a-uuid")


def test_parse_recipient_e164() -> None:
    assert parse_recipient("+15551234567") == "+15551234567"


def test_parse_recipient_service_id() -> None:
    sid = uuid.uuid4()
    parsed = parse_recipient(f"aci:{sid}")
    assert isinstance(parsed, ServiceId)
    assert parsed.uuid == sid
