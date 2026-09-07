import xml.etree.ElementTree as ET

import pytest

from ypso_keys.aaps import import_session, merge_preferences
from ypso_keys.errors import ToolError


def test_merge_preserves_unrelated_settings_and_removes_stale_counters(session):
    existing = b"""<map><string name="unrelated">keep &amp; preserve</string>
    <string name="ypso_shared_key">old</string><int name="ypso_reboot_counter" value="9" />
    <long name="ypso_write_counter" value="42"/><long name="writeCounter" value="43"/>
    <long name="readCounter" value="44"/><long name="ypso_read_counter" value="45"/></map>"""
    merged = ET.fromstring(merge_preferences(existing, session))
    values = {v.get("name"): v for v in merged}
    assert values["unrelated"].text == "keep & preserve"
    assert values["ypso_shared_key"].text == session.shared_key.hex()
    assert values["ypso_pump_mac"].text == session.pump_mac
    assert values["ypso_reboot_counter"].get("value") == "16"
    assert (
        not {"writeCounter", "ypso_write_counter", "readCounter", "ypso_read_counter"}
        & values.keys()
    )


@pytest.mark.parametrize(
    "xml",
    [
        b"permission denied",
        b"<wrong/>",
        b'<map><int name="x"/><int name="x"/></map>',
        b'<!DOCTYPE map [<!ENTITY x "secret">]><map/>',
    ],
)
def test_bad_existing_preferences_never_silently_replaced(xml, session):
    with pytest.raises(ToolError):
        merge_preferences(xml, session)


class FakeTarget:
    serial = "target456"

    def __init__(self, debuggable=True, mismatch=False):
        self.debuggable = debuggable
        self.mismatch = mismatch
        self.calls = []
        self.written = None

    def ready(self):
        pass

    def stop(self, package):
        self.calls.append("stop")

    def shell(self, command, *, data=None):
        self.calls.append(command)
        if command.endswith(" id"):
            if not self.debuggable:
                raise ToolError("command_failed", "no debug")
            return b"uid=1234"
        if "if test" in command:
            return b'<map><string name="other">value</string></map>'
        if data is not None:
            self.written = data
            return b""
        if " cat " in command:
            return b"wrong" if self.mismatch else self.written
        if "pidof" in command:
            return b""
        raise AssertionError(command)


def test_release_target_reports_limit_before_mutation(session, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    target = FakeTarget(debuggable=False)
    with pytest.raises(ToolError) as error:
        import_session(target, session, tmp_path / "backup")
    assert error.value.code == "aaps_not_debuggable"
    assert "stop" not in target.calls
    assert target.written is None


def test_import_stdin_backup_readback_and_no_launch(session, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    target = FakeTarget()
    backup = tmp_path / "backup"
    import_session(target, session, backup)
    assert b'"other"' in backup.read_bytes()
    assert backup.stat().st_mode & 0o777 == 0o600
    assert session.shared_key.hex().encode() in target.written
    assert all(session.shared_key.hex() not in call for call in target.calls)
    assert all("am start" not in call for call in target.calls)


def test_readback_mismatch_is_failure_with_backup(session, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    target = FakeTarget(mismatch=True)
    backup = tmp_path / "backup"
    with pytest.raises(ToolError, match="read-back"):
        import_session(target, session, backup)
    assert backup.exists()
