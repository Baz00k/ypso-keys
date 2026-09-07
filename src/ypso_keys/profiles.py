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
    "preferences_path": "shared_prefs/net.sinovo.mylife.app.microsoft.maui.essentials.preferences.xml",
    "alias": "net.sinovo.mylife.app.microsoft.maui.essentials.preferences",
    "identity": "mylife-db-v1",
    "identity_config": {
        "database_path": "files/mylifeHealthData.db",
        "query": "SELECT d.SerialNumber, m.UUID FROM \"PATIENT.DEVICE\" d JOIN DEVICE_NAME_MAPPING m ON m.DeviceId=d.DeviceId WHERE d.Active=1 AND m.Name LIKE 'YpsoPump_%'",
    },
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
        if value["identity"] == "mylife-db-v1":
            identity = value["identity_config"]
            if not isinstance(identity, dict) or set(identity) != {"database_path", "query"}:
                raise ValueError
            built_in_identity = MYLIFE["identity_config"]
            if (
                not isinstance(built_in_identity, dict)
                or identity["query"] != built_in_identity["query"]
            ):
                raise ValueError
            paths: tuple[Any, ...] = (value["preferences_path"], identity["database_path"])
        else:
            if value["identity_config"] is not None:
                raise ValueError
            paths = (value["preferences_path"],)
        for relative in paths:
            if (
                not isinstance(relative, str)
                or relative.startswith("/")
                or ".." in relative.split("/")
                or not re.fullmatch(r"[A-Za-z0-9_./-]{1,300}", relative)
            ):
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
