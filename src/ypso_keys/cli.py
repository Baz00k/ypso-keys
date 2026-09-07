from __future__ import annotations

import argparse
import json
import os
import shlex
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, NoReturn

import frida

from .aaps import (
    DEFAULT_PACKAGE,
    DEFAULT_PREFERENCES,
    debug_access,
    import_session,
    merge_preferences,
)
from .adb import Adb, devices
from .capture import capture, recover, state_dir
from .errors import ToolError
from .model import Session, mac_address, normalize
from .profiles import profile
from .storage import read_private, write_private


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse echoes invalid user arguments; these may accidentally contain a key.
        raise ToolError("usage", "Invalid arguments. Use ypso-keys --help or COMMAND --help.")


def parser() -> argparse.ArgumentParser:
    p = Parser(description="Recover a stored YpsoPump session from a rooted Android source device.")
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit one redacted JSON result (also accepted after command)",
    )
    p.add_argument("--version", action="version", version="ypso-keys 0.2.0")
    commands = p.add_subparsers(dest="command", required=True, parser_class=Parser)
    for name, help_text in (
        ("devices", "List all ADB devices without choosing one"),
        ("doctor", "Read-only source and optional target checks"),
        ("extract", "Recover the existing session; source Bluetooth is temporarily disabled"),
        ("inspect", "Validate a session and show metadata, never its key"),
        ("export-aaps", "Write status-only AAPS preferences to a private local file"),
        ("import-aaps", "Import into a debuggable AAPS build; leave AAPS stopped"),
        ("recover", "Finish cleanup after an interrupted source extraction"),
    ):
        sub = commands.add_parser(name, help=help_text)
        sub.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        if name in ("doctor", "extract", "recover"):
            sub.add_argument(
                "--source", required=True, help="Exact ADB serial of rooted source device"
            )
        if name in ("doctor", "extract"):
            sub.add_argument(
                "--profile", type=Path, help="Explicit source adapter JSON; defaults to mylife MAUI"
            )
            sub.add_argument(
                "--frida-server",
                help="Absolute frida-server path on source; or set YPSO_KEYS_FRIDA_SERVER",
            )
        if name == "doctor":
            sub.add_argument("--target", help="Optional AAPS phone to check for run-as access")
            sub.add_argument("--aaps-package", default=DEFAULT_PACKAGE)
        if name == "extract":
            sub.add_argument(
                "--output",
                type=Path,
                help="New 0600 file; default is under ~/.local/state/ypso-keys/",
            )
            sub.add_argument("--expect-pump", help="Reject a different pump MAC")
            sub.add_argument(
                "--pump-serial", help="Required only for profiles using explicit identity"
            )
        if name in ("inspect", "export-aaps", "import-aaps"):
            sub.add_argument("session", type=Path)
        if name in ("export-aaps", "import-aaps"):
            sub.add_argument(
                "--status-only",
                required=True,
                action="store_true",
                help="Export no write/read counters; does not enforce driver therapy restrictions",
            )
        if name == "export-aaps":
            sub.add_argument("--output", required=True, type=Path)
        if name == "import-aaps":
            sub.add_argument("--target", required=True)
            sub.add_argument("--aaps-package", default=DEFAULT_PACKAGE)
            sub.add_argument("--aaps-preferences", default=DEFAULT_PREFERENCES)
            sub.add_argument(
                "--backup",
                required=True,
                type=Path,
                help="New private file for original preferences",
            )
    return p


def doctor(args: argparse.Namespace) -> dict[str, Any]:
    config = profile(args.profile)
    server = args.frida_server or os.environ.get("YPSO_KEYS_FRIDA_SERVER")
    if not server:
        raise ToolError(
            "frida_server_required", "Pass --frida-server or set YPSO_KEYS_FRIDA_SERVER."
        )
    adb = Adb(args.source)
    adb.ready()
    checks: dict[str, Any] = {"source": args.source, "profile": config["id"]}
    actions: list[tuple[str, Callable[[], bool]]] = [
        ("root", lambda: adb.root("id -u").strip() == b"0"),
        (
            "frida_version_match",
            lambda: (
                adb.root(shlex.quote(server) + " --version").decode().strip() == frida.__version__
            ),
        ),
        (
            "app_installed",
            lambda: adb.shell(f"pm path --user 0 {config['package']}").startswith(b"package:"),
        ),
    ]
    for name, action in actions:
        try:
            checks[name] = action()
        except ToolError:
            checks[name] = False
    checks["bluetooth_on"] = adb.bluetooth_on()
    checks["host_frida"] = frida.__version__
    checks["ready"] = all(checks[name] for name in ("root", "frida_version_match", "app_installed"))
    if args.target:
        target = Adb(args.target)
        target.ready()
        checks["target"] = args.target
        checks["aaps_direct_import_available"] = debug_access(target, args.aaps_package)
    return checks


def dispatch(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "devices":
        return {"devices": devices()}
    if args.command == "doctor":
        return doctor(args)
    if args.command == "recover":
        return recover(Adb(args.source))
    if args.command == "extract":
        config = profile(args.profile)
        expected = mac_address(args.expect_pump) if args.expect_pump else None
        output = args.output or state_dir() / (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + ".session.json"
        )
        if output.exists() or output.is_symlink():
            raise ToolError("output_exists", "Output already exists; choose a new filename.")
        if not output.parent.is_dir():
            raise ToolError(
                "output_directory", "Create the output parent directory before extracting."
            )
        server = args.frida_server or os.environ.get("YPSO_KEYS_FRIDA_SERVER")
        if not server:
            raise ToolError(
                "frida_server_required", "Pass --frida-server or set YPSO_KEYS_FRIDA_SERVER."
            )
        raw = capture(Adb(args.source), config, server)
        session = normalize(raw, config, expected, args.pump_serial)
        write_private(output, session.document())
        return {**session.summary(), "output": str(output), "source_app_stopped": True}
    session = Session.load(read_private(args.session))
    if args.command == "inspect":
        return session.summary()
    if args.command == "export-aaps":
        write_private(args.output, merge_preferences(b"", session))
        return {
            "output": str(args.output),
            "key_fingerprint": session.fingerprint,
            "write_counter_included": False,
            "mode": "status-only",
        }
    if args.command == "import-aaps":
        import_session(
            Adb(args.target), session, args.backup, args.aaps_package, args.aaps_preferences
        )
        return {
            "target": args.target,
            "backup": str(args.backup),
            "aaps_launched": False,
            "read_back_verified": True,
            "write_counter_included": False,
        }
    raise ToolError("usage", "Unknown command.")


def interrupted(signum: int, frame: Any) -> None:
    raise KeyboardInterrupt


def main() -> None:
    json_mode = "--json" in sys.argv
    signal.signal(signal.SIGTERM, interrupted)
    try:
        args = parser().parse_args()
        result = {"ok": True, "command": args.command, **dispatch(args)}
        print(json.dumps(result, indent=None if json_mode else 2))
    except ToolError as error:
        result = {"ok": False, "error": {"code": error.code, "message": str(error)}}
        print(json.dumps(result), file=sys.stdout if json_mode else sys.stderr)
        sys.exit(2 if error.code == "usage" else 1)
    except KeyboardInterrupt:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "interrupted",
                        "message": "Interrupted; run recover with the source serial if cleanup was incomplete.",
                    },
                }
            ),
            file=sys.stdout if json_mode else sys.stderr,
        )
        sys.exit(130)
    except Exception:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "unexpected",
                        "message": "Unexpected failure; sensitive diagnostics suppressed. Run recover, then doctor.",
                    },
                }
            ),
            file=sys.stdout if json_mode else sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
