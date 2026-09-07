from __future__ import annotations

import re
import shlex
import subprocess
import time
from dataclasses import dataclass

from .errors import ToolError


def run(args: list[str], *, data: bytes | None = None, timeout: float = 15) -> bytes:
    try:
        result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        raise ToolError(
            "dependency_missing", "Required executable was not found on PATH."
        ) from None
    except subprocess.TimeoutExpired:
        raise ToolError(
            "timeout", "External command timed out; inspect device connectivity."
        ) from None
    if result.returncode:
        # ADB/Frida can echo secrets in errors. Never forward stdout/stderr or argv.
        raise ToolError("command_failed", "External command failed; run doctor for diagnostics.")
    return result.stdout


def devices() -> list[dict[str, str]]:
    result = []
    for line in run(["adb", "devices", "-l"]).decode().splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        item = {"serial": parts[0], "state": parts[1]}
        for part in parts[2:]:
            if ":" in part:
                key, value = part.split(":", 1)
                item[key] = value
        result.append(item)
    return result


@dataclass
class Adb:
    serial: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", self.serial) or self.serial.startswith("-"):
            raise ToolError("invalid_serial", "Use an explicit serial from the devices command.")

    def call(self, *args: str, data: bytes | None = None, timeout: float = 15) -> bytes:
        return run(["adb", "-s", self.serial, *args], data=data, timeout=timeout)

    def shell(self, command: str, *, data: bytes | None = None) -> bytes:
        # shell -T propagates the remote exit code, unlike exec-out on some ADB versions.
        return self.call("shell", "-T", command, data=data)

    def root(self, command: str) -> bytes:
        return self.shell("su -c " + shlex.quote(command))

    def ready(self) -> None:
        if self.call("get-state").strip() != b"device":
            raise ToolError("device_unavailable", "Selected phone is not authorized and online.")
        if self.shell("am get-current-user").strip() != b"0":
            raise ToolError("android_user", "Switch the selected phone to Android user 0.")

    def stop(self, package: str) -> None:
        self.shell(f"am force-stop --user 0 {shlex.quote(package)}")
        pids = self.shell(f"pidof {shlex.quote(package)} || true").strip()
        if pids:
            raise ToolError("app_not_stopped", "Donor app could not be force-stopped.")

    def bluetooth_on(self) -> bool:
        status = self.shell("dumpsys bluetooth_manager").decode()
        match = re.search(r"^\s*state: (OFF|ON|TURNING_ON|TURNING_OFF)\s*$", status, re.M)
        if match is None or match[1] not in ("ON", "OFF"):
            raise ToolError("bluetooth_state", "Bluetooth state is unknown or transitional.")
        return match[1] == "ON"

    def set_bluetooth(self, enabled: bool) -> None:
        self.shell("svc bluetooth " + ("enable" if enabled else "disable"))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                if self.bluetooth_on() == enabled:
                    return
            except ToolError:
                pass
            time.sleep(0.2)
        raise ToolError("bluetooth_state", "Could not confirm requested Bluetooth state.")
