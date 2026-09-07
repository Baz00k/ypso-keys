import os

import pytest

from ypso_keys.errors import ToolError
from ypso_keys.storage import read_private, write_private


def test_private_atomic_roundtrip(tmp_path):
    path = tmp_path / "secret"
    write_private(path, b"sensitive")
    assert path.stat().st_mode & 0o777 == 0o600
    assert read_private(path) == b"sensitive"
    assert list(tmp_path.iterdir()) == [path]


def test_existing_output_is_never_overwritten(tmp_path):
    path = tmp_path / "secret"
    write_private(path, b"original")
    with pytest.raises(ToolError, match="already exists"):
        write_private(path, b"replacement")
    assert read_private(path) == b"original"
    assert list(tmp_path.iterdir()) == [path]


def test_no_symlink_following_on_read_or_write(tmp_path):
    target = tmp_path / "target"
    write_private(target, b"original")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ToolError):
        write_private(link, b"replacement")
    with pytest.raises(ToolError):
        read_private(link)
    assert target.read_bytes() == b"original"


def test_public_permissions_and_fifo_rejected(tmp_path):
    path = tmp_path / "secret"
    write_private(path, b"secret")
    path.chmod(0o644)
    with pytest.raises(ToolError, match="0600"):
        read_private(path)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ToolError):
        read_private(fifo)


def test_partial_write_never_published(tmp_path, monkeypatch):
    def fail(_):
        raise OSError("injected disk failure")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(ToolError):
        write_private(tmp_path / "secret", b"secret")
    assert not list(tmp_path.iterdir())
