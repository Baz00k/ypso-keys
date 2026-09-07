from datetime import datetime, timezone

import pytest

from ypso_keys.model import Session


@pytest.fixture
def session():
    return Session(
        bytes(range(32)),
        "AA:BB:CC:DD:EE:FF",
        "12345678",
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 2, tzinfo=timezone.utc),
        16,
        {
            "profile": "mylife-maui-v1",
            "package": "net.sinovo.mylife.app",
            "app_version": "2.6.1.001",
            "identity": "mylife-db-v1",
        },
    )
