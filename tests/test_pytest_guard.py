"""FSD pytest 护栏：认证与历史应急后门回归。"""
from __future__ import annotations

import os

from fsd.certificate import Certificate, CertificateStore, hash_password


def _store() -> CertificateStore:
    store = CertificateStore()
    store.add(Certificate("1234", hash_password("correct-password"), 1))
    return store


def test_correct_password_accepted() -> None:
    assert _store().max_level("1234", "correct-password") == (True, 1)


def test_wrong_password_rejected() -> None:
    assert _store().max_level("1234", "wrong-password") == (False, 1)


def test_unknown_cid_rejected() -> None:
    assert _store().max_level("9999", "anything")[0] is False


def test_legacy_emergency_env_has_no_effect() -> None:
    os.environ["FSD_ALLOW_ANY_PASSWORD"] = "1"
    os.environ["FSD_AUTO_ADD_UNKNOWN"] = "1"
    try:
        assert _store().max_level("9999", "anything")[0] is False
        assert _store().max_level("1234", "wrong-password")[0] is False
    finally:
        os.environ.pop("FSD_ALLOW_ANY_PASSWORD", None)
        os.environ.pop("FSD_AUTO_ADD_UNKNOWN", None)


def test_hash_cannot_be_used_as_password() -> None:
    hashed = hash_password("correct-password")
    store = CertificateStore()
    store.add(Certificate("1234", hashed, 1))
    assert store.max_level("1234", hashed)[0] is False
