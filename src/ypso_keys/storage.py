from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from .errors import ToolError

MAX_SIZE = 1024 * 1024


def read_private(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ToolError(
                    "file_permissions",
                    "Secret input must be a regular file owned by you with mode 0600.",
                )
            data = stream.read(MAX_SIZE + 1)
            if len(data) > MAX_SIZE:
                raise ToolError("file_too_large", "Secret input exceeds the 1 MiB limit.")
            return data
    except OSError:
        raise ToolError(
            "file_read", "Cannot read secret file; check path, ownership and permissions."
        ) from None


def write_private(path: Path, data: bytes) -> None:
    """Publish a complete 0600 file atomically, without overwriting even symlinks."""
    temporary: str | None = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".ypso-keys-", dir=path.parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError:
        raise ToolError("output_exists", "Output already exists; choose a new filename.") from None
    except OSError:
        raise ToolError(
            "file_write", "Cannot publish secret output; check destination directory."
        ) from None
    finally:
        if temporary is not None:
            os.unlink(temporary)
