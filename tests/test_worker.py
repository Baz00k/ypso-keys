from types import SimpleNamespace

import pytest

from ypso_keys import worker


def test_hook_load_precedes_resume_and_kill_precedes_detach(monkeypatch):
    calls = []

    class Script:
        exports_sync = SimpleNamespace(read=lambda config: {"synthetic": True})

        def set_log_handler(self, handler):
            calls.append("logs_suppressed")

        def load(self):
            calls.append("load")

    class Session:
        def create_script(self, source):
            assert "CountDownLatch" in source
            calls.append("create")
            return Script()

        def detach(self):
            calls.append("detach")

    class Device:
        def spawn(self, args):
            calls.append("spawn")
            return 123

        def attach(self, pid):
            calls.append("attach")
            return Session()

        def resume(self, pid):
            calls.append("resume")

        def kill(self, pid):
            calls.append("kill")

    manager = SimpleNamespace(add_remote_device=lambda address: Device())
    monkeypatch.setattr(worker.frida, "get_device_manager", lambda: manager)
    assert worker.extract("127.0.0.1:1234", {"package": "org.example.app"}) == {"synthetic": True}
    assert calls == [
        "spawn",
        "attach",
        "create",
        "logs_suppressed",
        "load",
        "resume",
        "kill",
        "detach",
    ]


def test_worker_error_is_redacted(monkeypatch, capsys):
    import io

    monkeypatch.setattr(worker.sys, "stdin", io.StringIO('{"address":"local","config":{}}'))

    def failure(*args):
        raise RuntimeError("secret key material must not be printed")

    monkeypatch.setattr(worker, "extract", failure)
    with pytest.raises(SystemExit):
        worker.main()
    output = capsys.readouterr()
    assert "secret" not in output.out + output.err
    assert '"ok": false' in output.out
