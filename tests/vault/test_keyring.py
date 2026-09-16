"""Tests for the vault KeyRing and v2 key schedule (FEAT-099, TASK-070)."""
import base64
import logging
import os
import pickle

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from navigator_session.vault.config import VaultConfig, get_naming_key_id
from navigator_session.vault.keyring import (
    ALG_AESGCM,
    ALG_CHACHA20,
    KeyRing,
    lp,
)


def _v1_derive(seed: bytes, context: str) -> bytes:
    """Reproduce the legacy v1 derivation (crypto.derive_key) for comparison."""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=context.encode("utf-8")
    ).derive(seed)


class TestConstruction:
    def test_from_env_loads_ring(self, keyring):
        assert keyring.key_ids == (1, 2)
        assert keyring.active_key_id == 1
        assert keyring.write_alg_id == ALG_AESGCM
        assert keyring.naming_key_id == 1
        assert keyring.has_key(2) and not keyring.has_key(3)

    def test_explicit_constructor(self, master_keys):
        ring = KeyRing(master_keys, 2, cipher_backend="chacha20", naming_key_id=2)
        assert ring.active_key_id == 2
        assert ring.write_alg_id == ALG_CHACHA20
        assert ring.naming_key_id == 2

    @pytest.mark.parametrize("backend", ["CHACHA20", " chacha20 "])
    def test_backend_is_case_insensitive(self, master_key_env, monkeypatch, backend):
        monkeypatch.setenv("VAULT_CIPHER_BACKEND", backend)
        assert KeyRing.from_env().write_alg_id == ALG_CHACHA20

    def test_unknown_backend_fails_fast(self, master_key_env, monkeypatch):
        monkeypatch.setenv("VAULT_CIPHER_BACKEND", "des")
        with pytest.raises(ValueError, match="VAULT_CIPHER_BACKEND"):
            KeyRing.from_env()

    def test_empty_ring(self):
        with pytest.raises(ValueError, match="empty"):
            KeyRing({}, 1)

    def test_wrong_key_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            KeyRing({1: os.urandom(31)}, 1)

    def test_wrong_key_length_from_env(self, clean_vault_env):
        clean_vault_env.setenv(
            "VAULT_MASTER_KEY_v1", base64.b64encode(os.urandom(16)).decode()
        )
        clean_vault_env.setenv("VAULT_ACTIVE_KEY_ID", "1")
        with pytest.raises(ValueError):
            KeyRing.from_env()

    @pytest.mark.parametrize("bad_id", [0, 65536, -1, True])
    def test_key_id_range(self, bad_id):
        with pytest.raises(ValueError, match="Key id"):
            KeyRing({bad_id: os.urandom(32)}, 1)

    def test_active_key_missing(self, master_keys):
        with pytest.raises(ValueError, match="Active key version 9"):
            KeyRing(master_keys, 9)

    def test_active_key_env_missing(self, master_key_env, monkeypatch):
        monkeypatch.delenv("VAULT_ACTIVE_KEY_ID")
        with pytest.raises(RuntimeError):
            KeyRing.from_env()


class TestNamingKey:
    def test_defaults_to_lowest_key_id(self, clean_vault_env):
        for key_id in (3, 5):
            clean_vault_env.setenv(
                f"VAULT_MASTER_KEY_v{key_id}", base64.b64encode(os.urandom(32)).decode()
            )
        clean_vault_env.setenv("VAULT_ACTIVE_KEY_ID", "5")
        assert KeyRing.from_env().naming_key_id == 3

    def test_env_override(self, master_key_env, monkeypatch):
        monkeypatch.setenv("VAULT_NAMING_KEY_ID", "2")
        assert KeyRing.from_env().naming_key_id == 2

    def test_missing_naming_key_fails(self, master_key_env, monkeypatch):
        monkeypatch.setenv("VAULT_NAMING_KEY_ID", "9")
        with pytest.raises(ValueError, match="Naming key version 9"):
            KeyRing.from_env()

    def test_stable_across_active_rotation(self, master_key_env, monkeypatch):
        before = KeyRing.from_env().naming_hmac("session-123")
        monkeypatch.setenv("VAULT_ACTIVE_KEY_ID", "2")
        assert KeyRing.from_env().naming_hmac("session-123") == before

    def test_changes_with_naming_key(self, master_key_env, monkeypatch):
        before = KeyRing.from_env().naming_hmac("session-123")
        monkeypatch.setenv("VAULT_NAMING_KEY_ID", "2")
        assert KeyRing.from_env().naming_hmac("session-123") != before

    def test_hmac_format_and_determinism(self, keyring):
        digest = keyring.naming_hmac("jira:access_token")
        assert len(digest) == 64 and int(digest, 16) >= 0
        assert digest == keyring.naming_hmac("jira:access_token")
        assert digest != keyring.naming_hmac("jira:refresh_token")
        assert "jira" not in digest

    def test_hmac_requires_str(self, keyring):
        with pytest.raises(TypeError):
            keyring.naming_hmac(b"bytes")  # type: ignore[arg-type]


class TestKeySchedule:
    def test_subkeys_pairwise_distinct(self, keyring):
        db = keyring.derive_db_key(1, ALG_AESGCM)
        session = keyring.derive_session_key(1, ALG_AESGCM, "sid")
        naming = keyring._naming_key  # noqa: SLF001 - verifying separation
        assert len({db, session, naming}) == 3
        assert all(len(k) == 32 for k in (db, session, naming))

    def test_differs_from_v1_derivations(self, keyring, master_keys):
        assert keyring.derive_db_key(1, ALG_AESGCM) != _v1_derive(master_keys[1], "vault-db-v1")
        assert keyring.derive_session_key(1, ALG_AESGCM, "sid") != _v1_derive(
            b"sid", "vault-session"
        )

    def test_db_key_depends_on_alg_and_key_id(self, keyring):
        assert keyring.derive_db_key(1, ALG_AESGCM) != keyring.derive_db_key(1, ALG_CHACHA20)
        assert keyring.derive_db_key(1, ALG_AESGCM) != keyring.derive_db_key(2, ALG_AESGCM)
        assert keyring.derive_db_key(1, ALG_AESGCM) == keyring.derive_db_key(1, ALG_AESGCM)

    def test_session_key_requires_master_key(self, master_keys):
        ring_a = KeyRing(master_keys, 1)
        ring_b = KeyRing({1: os.urandom(32)}, 1)
        assert ring_a.derive_session_key(1, ALG_AESGCM, "sid") != ring_b.derive_session_key(
            1, ALG_AESGCM, "sid"
        )

    def test_session_key_bound_to_session_and_deterministic(self, keyring):
        key = keyring.derive_session_key(1, ALG_AESGCM, "telegram-persistent:7")
        assert key == keyring.derive_session_key(1, ALG_AESGCM, "telegram-persistent:7")
        assert key != keyring.derive_session_key(1, ALG_AESGCM, "telegram-persistent:8")
        assert key != keyring.derive_session_key(1, ALG_CHACHA20, "telegram-persistent:7")

    def test_session_uuid_must_be_non_empty(self, keyring):
        with pytest.raises(ValueError):
            keyring.derive_session_key(1, ALG_AESGCM, "")

    def test_unknown_key_id(self, keyring):
        with pytest.raises(KeyError):
            keyring.derive_db_key(9, ALG_AESGCM)
        with pytest.raises(KeyError):
            keyring.derive_session_key(9, ALG_AESGCM, "sid")

    def test_unknown_alg_id(self, keyring):
        with pytest.raises(ValueError, match="algorithm id"):
            keyring.derive_db_key(1, 0x7F)

    def test_length_prefix(self):
        assert lp("ab") == b"\x00\x00\x00\x02ab"
        assert lp(b"") == b"\x00\x00\x00\x00"
        assert lp("ñ") == b"\x00\x00\x00\x02\xc3\xb1"


class TestNoKeyMaterialLeaks:
    def test_repr(self, keyring, master_keys):
        text = repr(keyring)
        for key in master_keys.values():
            assert base64.b64encode(key).decode() not in text
            assert key.hex() not in text
        assert "active_key_id=1" in text

    def test_logs(self, master_key_env, caplog):
        with caplog.at_level(logging.DEBUG, logger="navigator.vault"):
            ring = KeyRing.from_env()
            ring.naming_hmac("sid")
            ring.derive_db_key(1, ALG_AESGCM)
        for key in master_key_env.values():
            assert base64.b64encode(key).decode() not in caplog.text
            assert key.hex() not in caplog.text
        assert "active v1" in caplog.text

    def test_cannot_be_pickled(self, keyring):
        with pytest.raises(TypeError, match="cannot be serialized"):
            pickle.dumps(keyring)

    def test_no_instance_dict(self, keyring):
        assert not hasattr(keyring, "__dict__")


class TestConfig:
    def test_get_naming_key_id(self, clean_vault_env):
        assert get_naming_key_id() is None
        clean_vault_env.setenv("VAULT_NAMING_KEY_ID", " ")
        assert get_naming_key_id() is None
        clean_vault_env.setenv("VAULT_NAMING_KEY_ID", "3")
        assert get_naming_key_id() == 3
        clean_vault_env.setenv("VAULT_NAMING_KEY_ID", "x")
        with pytest.raises(ValueError):
            get_naming_key_id()

    def test_vault_config_naming_default(self, master_key_env):
        cfg = VaultConfig.from_env()
        assert cfg.naming_key_id is None
        assert cfg.effective_naming_key_id == 1

    def test_vault_config_naming_missing(self, master_keys):
        with pytest.raises(ValueError, match="naming_key_id 7"):
            VaultConfig(master_keys=master_keys, active_key_id=1, naming_key_id=7)
