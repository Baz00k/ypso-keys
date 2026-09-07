import json
import subprocess

import pytest

from ypso_keys.capture import (
    app_data_dir,
    capture,
    device_lock,
    journal,
    recover,
    recovery_path,
    stop_server,
    worker_response,
)
from ypso_keys.errors import ToolError
from ypso_keys.profiles import profile
from ypso_keys.storage import write_private

SERVER = "/opt/tools/frida-server"


class FakeDonor:
    serial = "donor123"

    def __init__(self, bluetooth=True):
        self.bt = bluetooth
        self.listening = False
        self.calls = []
        self.fail_stop = False
        self.fail_disable = False

    def ready(self):
        self.calls.append("ready")

    def root(self, command):
        self.calls.append(command)
        if command == "id -u":
            return b"0"
        if "--version" in command:
            return b"17.17.0"
        if "sha256sum" in command:
            return b"a" * 64 + b"  prefs.xml"
        if "ss -ltn" in command:
            return b"LISTEN" if self.listening else b""
        if "echo $!" in command:
            self.listening = True
            return b"123"
        if "/proc/123/cmdline" in command:
            return (
                b"\0".join([SERVER.encode(), b"-l", b"127.0.0.1:27083", b""])
                if self.listening
                else b""
            )
        if command == "kill 123":
            self.listening = False
            return b""
        raise AssertionError(command)

    def shell(self, command):
        self.calls.append(command)
        if command.startswith("dumpsys package"):
            return b"  dataDir=/data/user/0/net.sinovo.mylife.app\n"
        if command.startswith("pm path"):
            return b"package:/data/app/base.apk"
        raise AssertionError(command)

    def bluetooth_on(self):
        return self.bt

    def set_bluetooth(self, enabled):
        self.calls.append(("bluetooth", enabled))
        if self.fail_disable and not enabled:
            raise ToolError("bluetooth_state", "cannot disable")
        self.bt = enabled

    def stop(self, package):
        self.calls.append("stop")
        if self.fail_stop:
            raise ToolError("app_not_stopped", "cannot stop")

    def call(self, *args):
        self.calls.append(args)
        if args == ("forward", "tcp:0", "tcp:27083"):
            return b"4567"
        if args == ("forward", "--remove", "tcp:4567"):
            return b""
        if args == ("forward", "--list"):
            return b"donor123 tcp:4567 tcp:27083\n"
        raise AssertionError(args)


@pytest.fixture(autouse=True)
def private_state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))


def test_explicit_application_state_directory(tmp_path, monkeypatch):
    configured = tmp_path / "custom-state"
    monkeypatch.setenv("YPSO_KEYS_STATE_DIR", str(configured))
    assert recovery_path("source123").parent == configured


def success(*args, **kwargs):
    return subprocess.CompletedProcess(
        args, 0, json.dumps({"ok": True, "data": {"synthetic": True}}).encode()
    )


@pytest.mark.parametrize("initial_bt", [True, False])
def test_capture_order_and_cleanup(initial_bt, monkeypatch):
    donor = FakeDonor(initial_bt)

    def worker(*args, **kwargs):
        assert donor.bt is False
        assert donor.listening
        assert donor.calls.index("stop") < donor.calls.index(("bluetooth", False))
        assert kwargs["timeout"] == 45
        return success(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", worker)
    assert capture(donor, profile(), SERVER) == {"synthetic": True}
    assert donor.bt == initial_bt
    assert not donor.listening
    assert donor.calls.count("stop") == 2
    assert ("forward", "--remove", "tcp:4567") in donor.calls
    assert not recovery_path(donor.serial).exists()


@pytest.mark.parametrize("failure", ["timeout", "worker", "malformed", "interrupt"])
def test_every_worker_failure_cleans_up(failure, monkeypatch):
    donor = FakeDonor()

    def worker(*args, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired("worker", 45, output=b"SECRET")
        if failure == "interrupt":
            raise KeyboardInterrupt
        if failure == "malformed":
            return subprocess.CompletedProcess(args, 0, b"invalid json SECRET")
        return subprocess.CompletedProcess(args, 1, b'{"ok":false,"code":"SECRET"}')

    monkeypatch.setattr(subprocess, "run", worker)
    with pytest.raises((ToolError, KeyboardInterrupt)) as error:
        capture(donor, profile(), SERVER)
    assert "SECRET" not in str(error.value)
    assert not donor.listening
    assert donor.bt
    assert not recovery_path(donor.serial).exists()


@pytest.mark.parametrize(
    "data",
    [
        b"{",
        b"[]",
        b"null",
        b"{}",
        b'{"package":5}',
        b'{"package":"org.example.app","server":"/server","bluetooth_was_on":true,"pid":true}',
    ],
)
def test_malformed_recovery_is_stable_and_never_touches_phone(data):
    donor = FakeDonor()
    path = recovery_path(donor.serial)
    write_private(path, data)
    with pytest.raises(ToolError) as error:
        recover(donor)
    assert error.value.code == "invalid_recovery"
    assert path.read_bytes() == data
    assert not donor.calls


@pytest.mark.parametrize(
    "data",
    [
        b"{",
        b"[]",
        b"null",
        b'{"ok":true}',
        b'{"ok":false}',
        b'{"ok":true,"data":[]}',
        b'{"ok":false,"code":[]}',
        b'{"ok":1,"data":{}}',
    ],
)
def test_malformed_worker_response_has_stable_code(data):
    with pytest.raises(ToolError) as error:
        worker_response(data)
    assert error.value.code == "capture_protocol"


def test_failed_app_stop_never_restores_bluetooth_and_keeps_recovery(monkeypatch):
    donor = FakeDonor()

    def worker(*args, **kwargs):
        donor.fail_stop = True
        return success(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", worker)
    with pytest.raises(ToolError, match="Cleanup incomplete"):
        capture(donor, profile(), SERVER)
    assert donor.bt is False
    assert not donor.listening
    assert recovery_path(donor.serial).exists()
    with pytest.raises(ToolError, match="interrupted"):
        capture(donor, profile(), SERVER)
    donor.fail_stop = False
    assert recover(donor)["recovered"]
    assert donor.bt is True
    assert not recovery_path(donor.serial).exists()


def test_no_spawn_when_bluetooth_cannot_be_disabled(monkeypatch):
    donor = FakeDonor()
    donor.fail_disable = True

    def unexpected(*args, **kwargs):
        raise AssertionError("worker must not start")

    monkeypatch.setattr(subprocess, "run", unexpected)
    with pytest.raises(ToolError, match="cannot disable"):
        capture(donor, profile(), SERVER)
    assert not donor.listening


def test_lock_prevents_concurrent_capture():
    with device_lock("donor123"):
        with pytest.raises(ToolError, match="Another"):
            with device_lock("donor123"):
                pass


def test_app_data_directory_is_resolved_from_package_metadata():
    source = FakeDonor()
    assert app_data_dir(source, "net.sinovo.mylife.app") == "/data/user/0/net.sinovo.mylife.app"


def test_ambiguous_app_data_directory_fails_closed():
    source = FakeDonor()
    source.shell = lambda command: b" dataDir=/data/user/0/app\n dataDir=/data/user/10/app\n"
    with pytest.raises(ToolError) as error:
        app_data_dir(source, "org.example.app")
    assert error.value.code == "app_data_dir"


def test_missing_app_data_directory_fails_closed():
    source = FakeDonor()
    source.shell = lambda command: b"Package metadata without a data directory"
    with pytest.raises(ToolError) as error:
        app_data_dir(source, "org.example.app")
    assert error.value.code == "app_data_dir"


def test_malformed_server_identity_becomes_domain_error():
    source = FakeDonor()
    source.root = lambda command: b"\xff\0-l\0127.0.0.1:27083\0"
    with pytest.raises(ToolError) as error:
        stop_server(source, 123, SERVER)
    assert error.value.code == "server_identity"


@pytest.mark.parametrize("failure", ["stop", "server", "forward", "bluetooth"])
def test_recovery_attempts_independent_cleanup_and_retains_journal(failure):
    class FailingDonor(FakeDonor):
        def root(self, command):
            if failure == "server" and command == "kill 123":
                self.calls.append(command)
                raise ToolError("injected", "failure")
            return super().root(command)

        def call(self, *args):
            if failure == "forward" and args == ("forward", "--remove", "tcp:4567"):
                self.calls.append(args)
                raise ToolError("injected", "failure")
            return super().call(*args)

        def set_bluetooth(self, enabled):
            if failure == "bluetooth":
                self.calls.append(("bluetooth", enabled))
                raise ToolError("injected", "failure")
            super().set_bluetooth(enabled)

    donor = FailingDonor(False)
    donor.listening = True
    donor.fail_stop = failure == "stop"
    path = recovery_path(donor.serial)
    journal(
        path,
        {
            "package": "net.sinovo.mylife.app",
            "server": SERVER,
            "bluetooth_was_on": True,
            "pid": 123,
            "port": 4567,
        },
    )
    with pytest.raises(ToolError, match="Recovery incomplete"):
        recover(donor)
    assert "kill 123" in donor.calls
    assert ("forward", "--remove", "tcp:4567") in donor.calls
    assert path.exists()
    if failure == "stop":
        assert not donor.bt
        assert ("bluetooth", True) not in donor.calls
    else:
        assert ("bluetooth", True) in donor.calls


def test_changed_encrypted_storage_prevents_export(monkeypatch):
    donor = FakeDonor()
    original = donor.root
    count = 0

    def root(command):
        nonlocal count
        if "sha256sum" in command:
            count += 1
            return (b"a" if count == 1 else b"b") * 64 + b" prefs.xml"
        return original(command)

    donor.root = root
    monkeypatch.setattr(subprocess, "run", success)
    with pytest.raises(ToolError) as error:
        capture(donor, profile(), SERVER)
    assert error.value.code == "preferences_changed"
    assert not donor.listening
    assert donor.bt
