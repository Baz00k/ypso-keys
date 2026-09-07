from __future__ import annotations

import re
import shlex
import xml.etree.ElementTree as ET
from pathlib import Path

from .adb import Adb
from .capture import device_lock
from .errors import ToolError
from .model import Session
from .storage import write_private

DEFAULT_PACKAGE = "info.nightscout.androidaps"
DEFAULT_PREFERENCES = "ypso_ble_state"
KEY = "ypso_shared_key"
MAC = "ypso_pump_mac"
REBOOT = "ypso_reboot_counter"
COUNTERS = {"writeCounter", "ypso_write_counter", "readCounter", "ypso_read_counter"}


def merge_preferences(existing: bytes, session: Session) -> bytes:
    try:
        if b"<!DOCTYPE" in existing.upper() or b"<!ENTITY" in existing.upper():
            raise ValueError
        root = ET.fromstring(existing) if existing.strip() else ET.Element("map")
        if root.tag != "map":
            raise ValueError
        names = [child.get("name") for child in root]
        if None in names or len(names) != len(set(names)):
            raise ValueError
        for child in list(root):
            if child.get("name") in COUNTERS | {KEY, MAC, REBOOT}:
                root.remove(child)
        ET.SubElement(root, "string", name=KEY).text = session.shared_key.hex()
        ET.SubElement(root, "string", name=MAC).text = session.pump_mac
        if session.reboot_counter is not None:
            ET.SubElement(root, "int", name=REBOOT, value=str(session.reboot_counter))
        return bytes(ET.tostring(root, encoding="utf-8", xml_declaration=True))
    except (ET.ParseError, ValueError):
        raise ToolError(
            "invalid_preferences", "AAPS preferences are malformed or contain duplicate names."
        ) from None


def debug_access(adb: Adb, package: str = DEFAULT_PACKAGE) -> bool:
    try:
        return b"uid=" in adb.shell(f"run-as {shlex.quote(package)} id")
    except ToolError:
        return False


def import_session(
    adb: Adb,
    session: Session,
    backup: Path,
    package: str = DEFAULT_PACKAGE,
    preferences: str = DEFAULT_PREFERENCES,
) -> None:
    if not re.fullmatch(r"[a-zA-Z]\w*(?:\.[a-zA-Z]\w*)+", package):
        raise ToolError("invalid_package", "AAPS package name is invalid.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", preferences):
        raise ToolError("invalid_preferences_name", "AAPS preferences name is invalid.")
    prefs = f"shared_prefs/{preferences}.xml"
    with device_lock(adb.serial):
        adb.ready()
        if not debug_access(adb, package):
            raise ToolError(
                "aaps_not_debuggable",
                "Installed AAPS does not permit run-as. Use a same-signature debuggable build or add an in-app importer; no preferences were changed.",
            )
        # Import is an explicit status-only operation; leave AAPS force-stopped.
        adb.stop(package)
        read_script = f"if test -e {prefs}; then cat {prefs}; fi"
        existing = adb.shell(f"run-as {package} sh -c {shlex.quote(read_script)}")
        merged = merge_preferences(existing, session)
        write_private(backup, existing or b'<?xml version="1.0"?><map />')
        # Input goes over stdin, never argv or public /sdcard storage.
        script = (
            f"set -eu; umask 077; mkdir -p shared_prefs; "
            f"test ! -L {prefs}; "
            "tmp=$(mktemp shared_prefs/.ypso-keys-XXXXXX); "
            'trap \'rm -f "$tmp"\' EXIT; cat > "$tmp"; '
            f'chmod 600 "$tmp"; mv "$tmp" {prefs}; rm -f {prefs}.bak'
        )
        adb.shell(f"run-as {package} sh -c {shlex.quote(script)}", data=merged)
        actual = adb.shell(f"run-as {package} cat {prefs}")
        if actual != merged:
            raise ToolError(
                "import_verification",
                "AAPS preference read-back differs; app remains stopped and original backup is available.",
            )
        if not re.fullmatch(rb"\s*", adb.shell(f"pidof {package} || true")):
            adb.stop(package)
            raise ToolError(
                "aaps_restarted", "AAPS restarted during import; inspect preferences before use."
            )
