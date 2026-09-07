from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .errors import ToolError


def mac_address(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", value
    ):
        raise ToolError(
            "invalid_identity", "Pump MAC must have six colon-separated hexadecimal octets."
        )
    return value.upper()


def key_bytes(value: Any, encoding: str = "hex") -> bytes:
    try:
        if not isinstance(value, str):
            raise ValueError
        if encoding == "hex":
            if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
                raise ValueError
            key = bytes.fromhex(value)
        elif encoding == "base64":
            key = base64.b64decode(value, validate=True)
        else:
            raise ValueError
        if len(key) != 32 or key == bytes(32):
            raise ValueError
        return key
    except (ValueError, TypeError):
        raise ToolError(
            "invalid_key",
            "Source must contain one nonzero 32-byte session key in the configured encoding.",
        ) from None


def timestamp(value: Any) -> datetime:
    try:
        if not isinstance(value, str):
            raise ValueError
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError
        if not 2020 <= dt.year <= 2100:
            raise ValueError
        return dt.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise ToolError(
            "invalid_date", "Session timestamps must be timezone-aware ISO 8601 dates."
        ) from None


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class Session:
    shared_key: bytes = field(repr=False)
    pump_mac: str
    pump_serial: str
    created_at: datetime
    captured_at: datetime
    reboot_counter: int | None
    source: dict[str, str]

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.shared_key).hexdigest()[:16]

    def summary(self) -> dict[str, Any]:
        review = self.created_at + timedelta(days=25)
        return {
            "schema_version": 1,
            "pump": {"mac": self.pump_mac, "serial": self.pump_serial},
            "key_fingerprint": self.fingerprint,
            "created_at": iso(self.created_at),
            "captured_at": iso(self.captured_at),
            "review_after": iso(review),
            "review_due": datetime.now(timezone.utc) >= review,
            "pump_validity": "unverified",
            "source": self.source,
        }

    def document(self) -> bytes:
        value = {
            "schema_version": 1,
            "pump": {"mac": self.pump_mac, "serial": self.pump_serial},
            "shared_key": self.shared_key.hex(),
            "created_at": iso(self.created_at),
            "captured_at": iso(self.captured_at),
            "reboot_counter": self.reboot_counter,
            "source": self.source,
        }
        return (json.dumps(value, indent=2) + "\n").encode()

    @classmethod
    def load(cls, data: bytes) -> Session:
        try:
            obj = json.loads(data)
            required = {
                "schema_version",
                "pump",
                "shared_key",
                "created_at",
                "captured_at",
                "reboot_counter",
                "source",
            }
            if (
                not isinstance(obj, dict)
                or set(obj) != required
                or type(obj["schema_version"]) is not int
                or obj["schema_version"] != 1
            ):
                raise ValueError
            if set(obj["pump"]) != {"mac", "serial"}:
                raise ValueError
            key = key_bytes(obj["shared_key"])
            mac = mac_address(obj["pump"]["mac"])
            serial = obj["pump"]["serial"]
            if not isinstance(serial, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", serial):
                raise ValueError
            created, captured = timestamp(obj["created_at"]), timestamp(obj["captured_at"])
            if created > captured + timedelta(minutes=5) or captured > datetime.now(
                timezone.utc
            ) + timedelta(minutes=5):
                raise ValueError
            counter = obj["reboot_counter"]
            if counter is not None and (type(counter) is not int or not 0 <= counter <= 2147483647):
                raise ValueError
            source = obj["source"]
            if not isinstance(source, dict) or set(source) not in (
                {
                    "profile",
                    "package",
                    "app_version",
                    "identity",
                },
                {
                    "profile",
                    "package",
                    "app_version",
                    "identity",
                    "donor",
                },
            ):
                raise ValueError
            if any(
                not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9_.:() -]{1,200}", v)
                for v in source.values()
            ):
                raise ValueError
            source.pop("donor", None)  # Read legacy v1 files without retaining device identifiers.
            return cls(key, mac, serial, created, captured, counter, source)
        except (ValueError, TypeError, KeyError, AttributeError):
            raise ToolError(
                "invalid_session", "Session file does not match schema version 1."
            ) from None


def normalize(
    raw: dict[str, Any],
    config: dict[str, Any],
    expected_mac: str | None = None,
    explicit_serial: str | None = None,
) -> Session:
    key = key_bytes(raw.get("shared_key"), config["encoding"])
    try:
        date = raw["created_at"]
        if not isinstance(date, str) or not re.fullmatch(r"\d{13}", date):
            raise ValueError
        created = datetime.fromtimestamp(int(date) / 1000, timezone.utc)
        counter_raw = raw.get("reboot_counter")
        if counter_raw is not None and (
            not isinstance(counter_raw, str) or not re.fullmatch(r"\d{1,10}", counter_raw)
        ):
            raise ValueError
        counter = int(counter_raw) if counter_raw is not None else None
        if config["identity"] == "mylife-db-v1":
            uuid = raw["pump_uuid"]
            if not isinstance(uuid, str) or not re.fullmatch(
                r"00000000-0000-0000-0000-[a-fA-F0-9]{12}", uuid
            ):
                raise ValueError
            tail = uuid[-12:]
            mac = mac_address(":".join(tail[i : i + 2] for i in range(0, 12, 2)))
            serial = raw["pump_serial"]
            if expected_mac is not None and mac != mac_address(expected_mac):
                raise ToolError(
                    "pump_mismatch", "Stored pump identity does not match --expect-pump."
                )
        else:
            if expected_mac is None or explicit_serial is None:
                raise ToolError(
                    "identity_required", "This profile requires --expect-pump and --pump-serial."
                )
            mac, serial = mac_address(expected_mac), explicit_serial
        session = Session(
            key,
            mac,
            serial,
            created,
            datetime.now(timezone.utc),
            counter,
            {
                "profile": config["id"],
                "package": config["package"],
                "app_version": raw["app_version"],
                "identity": config["identity"],
            },
        )
        return Session.load(session.document())
    except (ValueError, TypeError, KeyError, OverflowError, OSError):
        raise ToolError(
            "invalid_source", "Stored key date, counter or pump identity is missing or malformed."
        ) from None
