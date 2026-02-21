"""
Vault Configuration — Master key loading and validated settings.

Reads master keys from environment variables in the format:
    VAULT_MASTER_KEY_v{N} = <base64-encoded 32-byte key>
    VAULT_ACTIVE_KEY_ID = <integer>

Security Note:
    Never log key material. Only log key IDs and version numbers.
"""
import os
import re
import base64
import secrets
import logging

from pydantic import BaseModel, Field, field_validator, model_validator

logger = logging.getLogger("navigator.vault")

_KEY_ENV_PATTERN = re.compile(r"^VAULT_MASTER_KEY_v(\d+)$")


def load_master_keys() -> dict[int, bytes]:
    """Load master keys from VAULT_MASTER_KEY_v{N} environment variables.

    Each env var value must be base64-encoded and decode to exactly 32 bytes.

    Returns:
        Mapping of key version (int) to raw 32-byte key.

    Raises:
        RuntimeError: If no master keys are found in the environment.
        ValueError: If a key does not decode to exactly 32 bytes.
    """
    keys: dict[int, bytes] = {}
    for name, value in os.environ.items():
        match = _KEY_ENV_PATTERN.match(name)
        if match:
            version = int(match.group(1))
            key_bytes = base64.b64decode(value)
            if len(key_bytes) != 32:
                raise ValueError(
                    f"{name} must decode to exactly 32 bytes, "
                    f"got {len(key_bytes)}"
                )
            keys[version] = key_bytes
    if not keys:
        raise RuntimeError(
            "No vault master keys found in environment. "
            "Set VAULT_MASTER_KEY_v1=<base64-encoded-32-byte-key>"
        )
    logger.debug("Loaded %d master key version(s): %s", len(keys), sorted(keys.keys()))
    return keys


def get_active_key_id() -> int:
    """Read the active master key version from VAULT_ACTIVE_KEY_ID env var.

    Returns:
        Active key version as integer.

    Raises:
        RuntimeError: If VAULT_ACTIVE_KEY_ID is not set.
        ValueError: If the value is not a valid integer.
    """
    raw = os.environ.get("VAULT_ACTIVE_KEY_ID")
    if raw is None:
        raise RuntimeError(
            "VAULT_ACTIVE_KEY_ID environment variable is not set"
        )
    return int(raw)


def get_active_master_key(master_keys: dict[int, bytes]) -> tuple[int, bytes]:
    """Return the active (key_id, key_bytes) tuple.

    Args:
        master_keys: Mapping of key version to raw key bytes.

    Returns:
        Tuple of (active_key_id, active_key_bytes).

    Raises:
        KeyError: If active_key_id is not present in master_keys.
    """
    active_id = get_active_key_id()
    if active_id not in master_keys:
        raise KeyError(
            f"Active key version {active_id} not found in provided master keys"
        )
    return active_id, master_keys[active_id]


def generate_master_key() -> str:
    """Generate a random 32-byte master key and return as base64 string.

    This is a utility for operators to generate new keys.

    Returns:
        Base64-encoded 32-byte key string.
    """
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


class VaultConfig(BaseModel):
    """Validated vault configuration."""

    master_keys: dict[int, bytes]
    active_key_id: int
    cipher_backend: str = Field(default="aesgcm")
    max_keys_per_user: int = Field(default=50, ge=1, le=1000)
    session_ttl: int = Field(default=3600, ge=60)

    model_config = {"arbitrary_types_allowed": True}

    @field_validator("cipher_backend")
    @classmethod
    def validate_cipher(cls, v: str) -> str:
        """Validate cipher backend is supported."""
        if v not in ("aesgcm", "chacha20"):
            raise ValueError(f"Unsupported cipher backend: {v}")
        return v

    @model_validator(mode="after")
    def validate_active_key_exists(self) -> "VaultConfig":
        """Ensure active_key_id is present in master_keys."""
        if self.active_key_id not in self.master_keys:
            raise ValueError(
                f"active_key_id {self.active_key_id} not found in "
                f"master_keys (available: {sorted(self.master_keys.keys())})"
            )
        return self

    @classmethod
    def from_env(cls) -> "VaultConfig":
        """Create VaultConfig by loading values from environment.

        Returns:
            Populated VaultConfig instance.
        """
        master_keys = load_master_keys()
        active_key_id = get_active_key_id()
        cipher_backend = os.environ.get("VAULT_CIPHER_BACKEND", "aesgcm")
        return cls(
            master_keys=master_keys,
            active_key_id=active_key_id,
            cipher_backend=cipher_backend,
        )
