"""Shared fixtures for Session Vault kernel tests."""
import base64
import os

import pytest

from navigator_session.vault.keyring import KeyRing

_VAULT_ENV_PREFIXES = ("VAULT_MASTER_KEY_v",)
_VAULT_ENV_NAMES = ("VAULT_ACTIVE_KEY_ID", "VAULT_CIPHER_BACKEND", "VAULT_NAMING_KEY_ID")


@pytest.fixture
def clean_vault_env(monkeypatch):
    """Remove every vault variable inherited from the developer's environment."""
    for name in list(os.environ):
        if name.startswith(_VAULT_ENV_PREFIXES) or name in _VAULT_ENV_NAMES:
            monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture
def master_keys() -> dict[int, bytes]:
    """Two random 32-byte master keys (versions 1 and 2)."""
    return {1: os.urandom(32), 2: os.urandom(32)}


@pytest.fixture
def master_key_env(clean_vault_env, master_keys):
    """Two-version key ring in the environment, v1 active, default naming key."""
    for key_id, key in master_keys.items():
        clean_vault_env.setenv(
            f"VAULT_MASTER_KEY_v{key_id}", base64.b64encode(key).decode("ascii")
        )
    clean_vault_env.setenv("VAULT_ACTIVE_KEY_ID", "1")
    return master_keys


@pytest.fixture
def keyring(master_key_env) -> KeyRing:
    """KeyRing loaded from ``master_key_env``."""
    return KeyRing.from_env()
