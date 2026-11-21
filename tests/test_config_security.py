"""FSD security config regressions."""
from __future__ import annotations

from fsd.certificate import REMOTE_CERT_MAX_LEVEL
from fsd.config import DEFAULT_CONFIG, Config


def test_default_db_credentials_are_not_plaintext() -> None:
    db = DEFAULT_CONFIG["database"]
    assert db["user"] == ""
    assert db["password"] == ""


def test_server_link_control_defaults_off() -> None:
    config = Config("does-not-exist.conf")
    config.load()
    assert config.link_control_enabled is False
    assert config.allow_from == []


def test_remote_cert_level_cap_is_not_admin() -> None:
    assert REMOTE_CERT_MAX_LEVEL <= 10
