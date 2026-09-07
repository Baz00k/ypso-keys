from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .errors import ToolError

MYLIFE = {
    "id": "mylife-maui-v1",
    "package": "net.sinovo.mylife.app",
    "preferences": "net.sinovo.mylife.app.microsoft.maui.essentials.preferences",
    "alias": "net.sinovo.mylife.app.microsoft.maui.essentials.preferences",
    "identity": "mylife-db-v1",
    "encoding": "hex",
    "fields": {
        "shared_key": "sharedKey",
        "created_at": "sharedKeyDate",
        "reboot_counter": "rebootCounter",
    },
}


def profile(path: Path | None = None) -> dict[str, Any]:
    if path is None:
        return json.loads(json.dumps(MYLIFE))  # type: ignore[no-any-return]
    try:
        value = json.loads(path.read_text())
        if not isinstance(value, dict) or set(value) != set(MYLIFE):
            raise ValueError
        for key in ("id", "package", "preferences", "alias"):
            if not isinstance(value[key], str) or not re.fullmatch(
                r"[A-Za-z0-9_.-]{1,200}", value[key]
            ):
                raise ValueError
        if not re.fullmatch(r"[a-zA-Z]\w*(?:\.[a-zA-Z]\w*)+", value["package"]):
            raise ValueError
        if value["identity"] not in ("mylife-db-v1", "explicit"):
            raise ValueError
        if value["encoding"] not in ("hex", "base64"):
            raise ValueError
        if set(value["fields"]) != set(MYLIFE["fields"]):
            raise ValueError
        for name in value["fields"].values():
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", name):
                raise ValueError
        if len(set(value["fields"].values())) != 3:
            raise ValueError
        return value
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise ToolError(
            "invalid_profile", "Profile must match the documented encrypted-preferences schema."
        ) from None
