import json
import os
import subprocess
import sys

from ypso_keys.storage import write_private


def cli(*args):
    return subprocess.run([sys.executable, "-m", "ypso_keys.cli", *args], capture_output=True)


def test_inspect_machine_contract_never_contains_secret(session, tmp_path):
    path = tmp_path / "session"
    write_private(path, session.document())
    result = cli("inspect", str(path), "--json")
    assert result.returncode == 0
    value = json.loads(result.stdout)
    assert value["ok"] is True
    assert value["key_fingerprint"] == session.fingerprint
    assert not result.stderr
    assert session.shared_key.hex().encode() not in result.stdout


def test_invalid_argument_is_not_echoed():
    result = cli("--json", "accidentally-pasted-SECRET")
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"]["code"] == "usage"
    assert b"SECRET" not in result.stdout + result.stderr


def test_external_frida_server_path_is_required():
    result = cli("doctor", "--source", "source123", "--json")
    assert result.returncode == 1
    assert json.loads(result.stdout)["error"]["code"] == "frida_server_required"


def test_export_is_explicit_private_and_counter_free(session, tmp_path):
    path, output = tmp_path / "session", tmp_path / "output"
    write_private(path, session.document())
    refused = cli("export-aaps", str(path), "--output", str(output), "--json")
    assert refused.returncode == 2
    assert not output.exists()
    result = cli("export-aaps", str(path), "--output", str(output), "--status-only", "--json")
    assert result.returncode == 0
    assert os.stat(output).st_mode & 0o777 == 0o600
    assert b"write_counter" not in output.read_bytes()
    assert session.shared_key.hex().encode() not in result.stdout + result.stderr
