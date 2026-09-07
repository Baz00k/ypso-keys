from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import frida

from .adb import Adb
from .errors import ToolError
from .storage import read_private, write_private

PORT = 27083


def app_data_dir(adb: Adb, package: str) -> str:
    output = adb.shell(f"dumpsys package {shlex.quote(package)}").decode()
    matches = re.findall(r"^\s*dataDir=(/[^\s]+)\s*$", output, re.MULTILINE)
    if len(set(matches)) != 1 or not re.fullmatch(r"/[A-Za-z0-9_./-]+", matches[0]):
        raise ToolError(
            "app_data_dir", "Cannot resolve a unique private data directory for the source app."
        )
    return str(matches[0])


def preference_digest(adb: Adb, config: dict[str, Any]) -> bytes:
    file = f"{app_data_dir(adb, config['package'])}/shared_prefs/{config['preferences']}.xml"
    digest = adb.root("sha256sum " + shlex.quote(file)).split()[0]
    if not re.fullmatch(rb"[a-f0-9]{64}", digest):
        raise ToolError("preference_digest", "Cannot fingerprint source encrypted preferences.")
    return digest


def stop_server(adb: Adb, pid: int, server: str) -> None:
    cmdline = adb.root(f"cat /proc/{pid}/cmdline 2>/dev/null || true")
    if not cmdline:
        return
    parts = cmdline.split(b"\0")
    if parts[0].decode() != server or f"127.0.0.1:{PORT}".encode() not in parts:
        raise ToolError(
            "server_identity", "Recorded PID has changed identity; inspect server manually."
        )
    adb.root(f"kill {pid}")
    deadline = time.monotonic() + 5
    while adb.root(f"cat /proc/{pid}/cmdline 2>/dev/null || true").strip(b"\0"):
        if time.monotonic() >= deadline:
            raise ToolError("server_stop", "Owned Frida server did not exit.")
        time.sleep(0.1)


def recovery_path(serial: str) -> Path:
    return state_dir() / (hashlib.sha256(serial.encode()).hexdigest()[:24] + ".recovery.json")


def journal(path: Path, value: dict[str, Any]) -> None:
    # Replace only our private journal. Each version is fully written before rename.
    temporary = path.with_suffix(".next")
    if temporary.exists():
        temporary.unlink()
    write_private(temporary, json.dumps(value).encode())
    os.replace(temporary, path)


def read_journal(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(read_private(path))
        if (
            not isinstance(value, dict)
            or not {"package", "server", "bluetooth_was_on"} <= value.keys()
        ):
            raise ValueError
        if value.keys() - {"package", "server", "bluetooth_was_on", "pid", "port"}:
            raise ValueError
        if (
            not isinstance(value["package"], str)
            or not re.fullmatch(r"[a-zA-Z]\w*(?:\.[a-zA-Z]\w*)+", value["package"])
            or not isinstance(value["server"], str)
            or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value["server"])
            or type(value["bluetooth_was_on"]) is not bool
        ):
            raise ValueError
        pid, port = value.get("pid"), value.get("port")
        if pid is not None and (type(pid) is not int or pid < 2):
            raise ValueError
        if port is not None and (type(port) is not int or not 1 <= port <= 65535):
            raise ValueError
        return value
    except (ValueError, TypeError, KeyError):
        raise ToolError(
            "invalid_recovery", "Recovery journal is malformed; retained for manual inspection."
        ) from None


def worker_response(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data)
        if not isinstance(value, dict) or type(value.get("ok")) is not bool:
            raise ValueError
        if value["ok"]:
            if set(value) != {"ok", "data"} or not isinstance(value["data"], dict):
                raise ValueError
        elif set(value) != {"ok", "code"} or not isinstance(value["code"], str):
            raise ValueError
        return value
    except (ValueError, TypeError):
        raise ToolError("capture_protocol", "Invalid response from extraction worker.") from None


def recover(adb: Adb) -> dict[str, Any]:
    with device_lock(adb.serial):
        path = recovery_path(adb.serial)
        if not path.exists():
            return {"recovered": False, "reason": "no_interrupted_capture"}
        value = read_journal(path)
        package, server = value["package"], value["server"]
        pid = value.get("pid")
        port = value.get("port")
        adb.ready()
        failed, stopped = False, False
        try:
            adb.stop(package)
            stopped = True
        except ToolError:
            failed = True
        if pid is not None:
            try:
                stop_server(adb, pid, server)
            except ToolError:
                failed = True
        if port is not None:
            try:
                forwards = adb.call("forward", "--list").decode().splitlines()
                if f"{adb.serial} tcp:{port} tcp:{PORT}" in forwards:
                    adb.call("forward", "--remove", f"tcp:{port}")
            except ToolError:
                failed = True
        if stopped:
            try:
                adb.set_bluetooth(value["bluetooth_was_on"])
            except ToolError:
                failed = True
        if failed:
            raise ToolError(
                "cleanup_failed",
                "Recovery incomplete; independent cleanup was attempted. Reconnect and run recover again.",
            )
        path.unlink()
        return {
            "recovered": True,
            "source_app_stopped": True,
            "bluetooth_restored": value["bluetooth_was_on"],
        }


def state_dir() -> Path:
    path = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "ypso-keys"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ToolError("state_permissions", "State directory must be owned by you with mode 0700.")
    return path


@contextmanager
def device_lock(serial: str) -> Iterator[None]:
    name = hashlib.sha256(serial.encode()).hexdigest()[:24]
    fd = os.open(state_dir() / (name + ".lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ToolError("device_busy", "Another ypso-keys operation owns this phone.") from None
        yield
    finally:
        os.close(fd)


def capture(adb: Adb, config: dict[str, Any], server: str) -> dict[str, Any]:
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", server):
        raise ToolError(
            "invalid_server", "Frida server must be an absolute Android executable path."
        )
    package = config["package"]
    with device_lock(adb.serial):
        path = recovery_path(adb.serial)
        if path.exists():
            raise ToolError(
                "recovery_required",
                "A prior extraction was interrupted. Run recover --source SERIAL first.",
            )
        adb.ready()
        if adb.root("id -u").strip() != b"0":
            raise ToolError("root_required", "Extraction requires root on the source device.")
        if adb.root(shlex.quote(server) + " --version").decode().strip() != frida.__version__:
            raise ToolError("frida_version", "Host and source Frida versions must match exactly.")
        if not adb.shell(f"pm path --user 0 {shlex.quote(package)}").startswith(b"package:"):
            raise ToolError(
                "app_missing", "Selected source application is not installed for user 0."
            )
        bt_was_on = adb.bluetooth_on()
        pid: int | None = None
        port: int | None = None
        cleanup_failed = False
        original_digest: bytes | None = None
        preferences_changed = False
        record = {"package": package, "server": server, "bluetooth_was_on": bt_was_on}
        journal(path, record)
        try:
            # Force-stop before disabling Bluetooth; no app is spawned until OFF is verified.
            adb.stop(package)
            original_digest = preference_digest(adb, config)
            adb.set_bluetooth(False)
            # Refuse a busy endpoint: we must own the server we later stop.
            if adb.root(f"ss -ltn | grep -E ':{PORT} ' || true").strip():
                raise ToolError("frida_port_busy", "Dedicated Frida port 27083 is already in use.")
            command = f"{shlex.quote(server)} -l 127.0.0.1:{PORT} >/dev/null 2>&1 & echo $!"
            raw_pid = adb.root(command).strip()
            if not raw_pid.isdigit() or int(raw_pid) < 2:
                raise ToolError("frida_start", "Could not determine owned Frida server PID.")
            pid = int(raw_pid)
            record["pid"] = pid
            journal(path, record)
            port_raw = adb.call("forward", "tcp:0", f"tcp:{PORT}").strip()
            if not port_raw.isdigit():
                raise ToolError("adb_forward", "Could not establish a local Frida tunnel.")
            port = int(port_raw)
            record["port"] = port
            journal(path, record)
            deadline = time.monotonic() + 5
            while not adb.root(f"ss -ltn | grep -E ':{PORT} ' || true").strip():
                if time.monotonic() > deadline:
                    raise ToolError("frida_start", "Frida server did not start listening.")
                time.sleep(0.2)
            request = json.dumps({"address": f"127.0.0.1:{port}", "config": config}).encode()
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "ypso_keys.worker"],
                    input=request,
                    capture_output=True,
                    timeout=45,
                )
            except subprocess.TimeoutExpired:
                raise ToolError(
                    "capture_timeout", "Extraction timed out; source cleanup was attempted."
                ) from None
            response = worker_response(result.stdout)
            if bool(result.returncode) == response["ok"]:
                raise ToolError(
                    "capture_protocol", "Worker exit status disagrees with its response."
                )
            if result.returncode:
                known = {
                    "CONTEXT_NOT_READY",
                    "BLUETOOTH_NOT_OFF",
                    "PREFERENCES_MISSING",
                    "KEYSET_MISSING",
                    "MASTER_KEY_MISSING",
                    "PREFERENCE_READ_FAILED",
                    "AMBIGUOUS_KEY_RECORD",
                    "AMBIGUOUS_PUMP_RECORD",
                    "ServerNotRunningError",
                    "ProcessNotFoundError",
                    "NotSupportedError",
                    "TransportError",
                    "PermissionDeniedError",
                    "RPCException",
                    "AttributeError",
                }
                code = response.get("code")
                known.update(
                    "PREFERENCE_READ_FAILED_" + stage
                    for stage in (
                        "context",
                        "bluetooth",
                        "file",
                        "keystore",
                        "classes",
                        "create",
                        "read",
                        "identity",
                    )
                )
                suffix = code if code in known else "unknown"
                raise ToolError(
                    "capture_failed",
                    "Cannot read source preferences ("
                    + suffix
                    + "); check profile, app unlock and Frida compatibility.",
                )
            return dict(response["data"])
        finally:
            # Attempt every cleanup even if one fails. Never restore BT unless app stop succeeds.
            stopped = False
            try:
                adb.stop(package)
                stopped = True
            except ToolError:
                cleanup_failed = True
            if pid is not None:
                try:
                    stop_server(adb, pid, server)
                except ToolError:
                    cleanup_failed = True
            if port is not None:
                try:
                    adb.call("forward", "--remove", f"tcp:{port}")
                except ToolError:
                    cleanup_failed = True
            if stopped and original_digest is not None:
                try:
                    preferences_changed = preference_digest(adb, config) != original_digest
                except ToolError:
                    cleanup_failed = True
            if stopped and bt_was_on:
                try:
                    adb.set_bluetooth(True)
                except ToolError:
                    cleanup_failed = True
            if cleanup_failed:
                raise ToolError(
                    "cleanup_failed",
                    "Cleanup incomplete: force-stop source app and stop the server on port 27083; check source Bluetooth.",
                )
            path.unlink()
            if preferences_changed:
                raise ToolError(
                    "preferences_changed",
                    "Donor encrypted preferences changed during capture; no session was exported. Investigate the source adapter before retrying.",
                )
