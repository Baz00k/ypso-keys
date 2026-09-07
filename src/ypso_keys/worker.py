"""Isolated Frida worker. stdout is a private protocol pipe, never a user log."""

from __future__ import annotations

import json
import sys
import time
from importlib.resources import files
from typing import Any

import frida


def extract(address: str, config: dict[str, Any]) -> dict[str, Any]:
    device = frida.get_device_manager().add_remote_device(address)
    pid = device.spawn([config["package"]])
    session = device.attach(pid)
    try:
        script = session.create_script(files("ypso_keys").joinpath("agent.js").read_text())
        # No application log, Frida console, or exception stack is forwarded.
        script.set_log_handler(lambda *_: None)
        script.load()
        device.resume(pid)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                return dict(script.exports_sync.read(config))
            except frida.core.RPCException as error:
                if "CONTEXT_NOT_READY" in str(error):
                    time.sleep(0.2)
                    continue
                raise
        raise TimeoutError
    finally:
        # Kill while the main thread remains parked, before removing the hook.
        device.kill(pid)
        session.detach()


def main() -> None:
    try:
        request = json.load(sys.stdin)
        response = extract(request["address"], request["config"])
        print(json.dumps({"ok": True, "data": response}))
    except Exception as error:
        code = type(error).__name__
        if isinstance(error, frida.core.RPCException):
            for stage in (
                "context",
                "bluetooth",
                "file",
                "keystore",
                "classes",
                "create",
                "read",
                "identity",
            ):
                if "PREFERENCE_READ_FAILED_" + stage in str(error):
                    code = "PREFERENCE_READ_FAILED_" + stage
            for known in (
                "CONTEXT_NOT_READY",
                "BLUETOOTH_NOT_OFF",
                "PREFERENCES_MISSING",
                "KEYSET_MISSING",
                "MASTER_KEY_MISSING",
                "AMBIGUOUS_KEY_RECORD",
                "AMBIGUOUS_PUMP_RECORD",
            ):
                if known in str(error):
                    code = known
        print(json.dumps({"ok": False, "code": code}))
        sys.exit(1)


if __name__ == "__main__":
    main()
