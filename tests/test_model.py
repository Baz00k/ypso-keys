import base64
import json

import pytest

from ypso_keys.errors import ToolError
from ypso_keys.model import Session, key_bytes, normalize
from ypso_keys.profiles import profile


def source():
    return {
        "shared_key": bytes(range(32)).hex(),
        "created_at": "1767225600000",
        "reboot_counter": "16",
        "pump_uuid": "00000000-0000-0000-0000-aabbccddeeff",
        "pump_serial": "12345678",
        "app_version": "2.6.1.001",
    }


def test_live_contract_normalizes_identity_date_and_counter():
    value = normalize(source(), profile(), "aa:bb:cc:dd:ee:ff")
    assert value.pump_mac == "AA:BB:CC:DD:EE:FF"
    assert value.created_at.year == 2026
    assert value.reboot_counter == 16
    assert value.shared_key == bytes(range(32))


def test_wrong_expected_pump_is_rejected():
    with pytest.raises(ToolError, match="does not match"):
        normalize(source(), profile(), "11:22:33:44:55:66")


@pytest.mark.parametrize(
    "value",
    [None, "", "00" * 32, "ab" * 31, "ab" * 33, "zz" * 32, "ab " * 32, [1] * 32, "ab" * 32 + "\n"],
)
def test_invalid_keys_are_rejected_without_echo(value):
    with pytest.raises(ToolError) as error:
        key_bytes(value)
    assert "zzzz" not in str(error.value)


def test_base64_requires_explicit_encoding():
    value = base64.b64encode(bytes(range(32))).decode()
    assert key_bytes(value, "base64") == bytes(range(32))
    with pytest.raises(ToolError):
        key_bytes(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("created_at", None),
        ("created_at", "9999999999999"),
        ("created_at", "2026-01-01"),
        ("reboot_counter", "-1"),
        ("reboot_counter", "2147483648"),
        ("reboot_counter", True),
        ("pump_uuid", "garbage"),
        ("pump_serial", "<xml>"),
        ("app_version", "bad\nlog"),
    ],
)
def test_malformed_source_metadata_fails_closed(field, value):
    raw = source()
    raw[field] = value
    with pytest.raises(ToolError):
        normalize(raw, profile())


def test_round_trip_and_redaction(session):
    loaded = Session.load(session.document())
    assert loaded == session
    for text in (repr(session), json.dumps(session.summary())):
        assert session.shared_key.hex() not in text
        assert "write_counter" not in text
    assert session.summary()["pump_validity"] == "unverified"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda v: v.update(schema_version=2),
        lambda v: v.update(schema_version=True),
        lambda v: v.update(write_counter=123),
        lambda v: v.update(reboot_counter=True),
        lambda v: v.update(created_at="2026-01-01T00:00:00"),
        lambda v: v.update(captured_at="2025-01-01T00:00:00Z"),
        lambda v: v["pump"].update(mac="AA:BBCC:DD:EE:FF"),
        lambda v: v["source"].update(private_key="should not be allowed"),
    ],
)
def test_session_schema_rejects_unsafe_documents(session, mutation):
    value = json.loads(session.document())
    mutation(value)
    with pytest.raises(ToolError):
        Session.load(json.dumps(value).encode())


def test_explicit_profile_needs_both_identity_fields():
    config = profile()
    config["identity"] = "explicit"
    with pytest.raises(ToolError, match="requires"):
        normalize(source(), config)
