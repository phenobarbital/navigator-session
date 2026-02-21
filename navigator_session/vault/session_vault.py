"""
SessionVault — Encrypted key-value storage bound to a user session.

Provides the public API for the Session Vault system:
- ``set(key, value)`` — encrypt and persist a secret
- ``get(key, default)`` — decrypt and return a secret (cache → Redis → default)
- ``delete(key)`` — soft-delete a secret
- ``keys()`` / ``exists(key)`` — enumerate and check cached secrets
- ``load_for_session()`` — factory that loads all user secrets from DB

Security Note:
    Never log plaintext or ciphertext values. Only log key names, operations,
    and user IDs. Decrypted values exist in process memory during use —
    this is an accepted limitation (see threat model in ``__init__.py``).
"""
import logging
from typing import Any

from .crypto import (
    encrypt_for_session,
    decrypt_for_session,
    encrypt_for_db,
    decrypt_for_db,
    serialize_value,
    deserialize_value,
)
from .config import load_master_keys, get_active_key_id

logger = logging.getLogger("navigator.vault")

# Default maximum secrets per user (spec §7 resolution: 50)
_DEFAULT_MAX_KEYS_PER_USER = 50

# ---------------------------------------------------------------------------
# SQL statements
# ---------------------------------------------------------------------------

_UPSERT_SECRET = """
INSERT INTO auth.user_vault_secrets (user_id, key, ciphertext_db, key_version)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id, key) WHERE deleted_at IS NULL
DO UPDATE SET ciphertext_db = EXCLUDED.ciphertext_db,
             key_version = EXCLUDED.key_version,
             updated_at = NOW()
"""

_SOFT_DELETE_SECRET = """
UPDATE auth.user_vault_secrets
SET deleted_at = NOW()
WHERE user_id = $1 AND key = $2 AND deleted_at IS NULL
"""

_SELECT_ALL_ACTIVE = """
SELECT key, ciphertext_db, key_version
FROM auth.user_vault_secrets
WHERE user_id = $1 AND deleted_at IS NULL
"""

_INSERT_AUDIT = """
INSERT INTO auth.user_vault_audit (user_id, key, operation, key_version, session_id)
VALUES ($1, $2, $3, $4, $5)
"""


class SessionVault:
    """Encrypted vault bound to a user session.

    Secrets are encrypted with two layers:
    - **Session layer**: AES-GCM with key derived from session_uuid (RAM/Redis)
    - **Database layer**: AES-GCM with key derived from master key (PostgreSQL)

    Lookup order for ``get()``: in-memory cache → Redis → default.
    All user secrets are loaded from DB into cache at session start via
    ``load_for_session()``.
    """

    def __init__(
        self,
        session_uuid: str,
        user_id: int,
        db_pool: Any,
        redis: Any = None,
        session_ttl: int = 3600,
    ):
        self._session_uuid = session_uuid
        self._user_id = user_id
        self._db = db_pool
        self._redis = redis
        self._ttl = session_ttl
        self._cache: dict[str, bytes] = {}  # key -> ciphertext_mem
        self._master_keys = load_master_keys()
        self._active_key_id = get_active_key_id()
        self._max_keys_per_user = _DEFAULT_MAX_KEYS_PER_USER

    # ------------------------------------------------------------------
    # Key validation
    # ------------------------------------------------------------------

    def _validate_key(self, key: str) -> None:
        """Validate a vault key name.

        Raises:
            ValueError: If key is empty, too long, or contains ':'.
        """
        if not key:
            raise ValueError("Vault key cannot be empty")
        if len(key) > 255:
            raise ValueError("Vault key cannot exceed 255 characters")
        if ":" in key:
            raise ValueError("Vault key cannot contain ':'")

    # ------------------------------------------------------------------
    # Redis helpers
    # ------------------------------------------------------------------

    def _redis_key(self, key: str) -> str:
        """Build Redis cache key."""
        return f"vault:{self._session_uuid}:{key}"

    async def _redis_set(self, key: str, ciphertext_mem: bytes) -> None:
        """Write ciphertext_mem to Redis with TTL. No-op if Redis is None."""
        if self._redis is not None:
            await self._redis.setex(
                self._redis_key(key), self._ttl, ciphertext_mem,
            )

    async def _redis_get(self, key: str) -> bytes | None:
        """Read ciphertext_mem from Redis. Returns None if not found or no Redis."""
        if self._redis is not None:
            return await self._redis.get(self._redis_key(key))
        return None

    async def _redis_delete(self, key: str) -> None:
        """Remove key from Redis cache. No-op if Redis is None."""
        if self._redis is not None:
            await self._redis.delete(self._redis_key(key))

    # ------------------------------------------------------------------
    # Audit helper
    # ------------------------------------------------------------------

    async def _audit(self, conn: Any, key: str, operation: str) -> None:
        """Insert an audit log entry."""
        await conn.execute(
            _INSERT_AUDIT,
            self._user_id, key, operation,
            self._active_key_id, self._session_uuid,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def set(self, key: str, value: Any) -> None:
        """Encrypt and persist a secret.

        Supported types: str, int, float, dict, list, bytes, bool, None.

        Args:
            key: Secret name (max 255 chars, no ':').
            value: Secret value to encrypt and store.

        Raises:
            ValueError: If key is invalid or max_keys_per_user exceeded.
        """
        self._validate_key(key)

        # Enforce max keys limit (overwrite doesn't count)
        if key not in self._cache and len(self._cache) >= self._max_keys_per_user:
            raise ValueError(
                f"Max secrets per user ({self._max_keys_per_user}) exceeded"
            )

        # Serialize and encrypt
        plaintext_bytes = serialize_value(value)
        ciphertext_mem = encrypt_for_session(plaintext_bytes, self._session_uuid)
        master_key = self._master_keys[self._active_key_id]
        ciphertext_db = encrypt_for_db(
            plaintext_bytes, self._active_key_id, master_key,
        )

        # Persist to cache
        self._cache[key] = ciphertext_mem

        # Persist to Redis
        await self._redis_set(key, ciphertext_mem)

        # Persist to DB + audit
        async with self._db.acquire() as conn:
            await conn.execute(
                _UPSERT_SECRET,
                self._user_id, key, ciphertext_db, self._active_key_id,
            )
            await self._audit(conn, key, "set")

        logger.debug("Vault set: user=%s key=%s", self._user_id, key)

    async def get(self, key: str, default: Any = None) -> Any:
        """Decrypt and return a secret.

        Lookup order: in-memory cache → Redis → default.

        Args:
            key: Secret name.
            default: Value returned if key not found.

        Returns:
            Decrypted value, or default if not found.
        """
        self._validate_key(key)

        # 1. Check in-memory cache
        ct_mem = self._cache.get(key)
        if ct_mem is not None:
            plaintext_bytes = decrypt_for_session(ct_mem, self._session_uuid)
            return deserialize_value(plaintext_bytes)

        # 2. Check Redis
        ct_mem = await self._redis_get(key)
        if ct_mem is not None:
            # Populate in-memory cache from Redis hit
            self._cache[key] = ct_mem
            plaintext_bytes = decrypt_for_session(ct_mem, self._session_uuid)
            return deserialize_value(plaintext_bytes)

        # 3. Not found
        return default

    async def delete(self, key: str) -> None:
        """Soft-delete a secret from vault.

        Removes from in-memory cache, Redis, and marks deleted_at in DB.

        Args:
            key: Secret name to delete.
        """
        self._validate_key(key)

        # Remove from cache
        self._cache.pop(key, None)

        # Remove from Redis
        await self._redis_delete(key)

        # Soft-delete in DB + audit
        async with self._db.acquire() as conn:
            await conn.execute(
                _SOFT_DELETE_SECRET, self._user_id, key,
            )
            await self._audit(conn, key, "delete")

        logger.debug("Vault delete: user=%s key=%s", self._user_id, key)

    async def keys(self) -> list[str]:
        """List active key names in the vault.

        Returns:
            List of key names currently in cache.
        """
        return list(self._cache.keys())

    async def exists(self, key: str) -> bool:
        """Check if a key exists in the vault cache.

        Args:
            key: Secret name to check.

        Returns:
            True if key is in cache, False otherwise.
        """
        return key in self._cache

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    async def load_for_session(
        cls,
        session_uuid: str,
        user_id: int,
        db_pool: Any,
        redis: Any = None,
        session_ttl: int = 3600,
    ) -> "SessionVault":
        """Load all user secrets from DB, re-encrypt for session, populate cache.

        This is the primary constructor used during the login flow.

        Args:
            session_uuid: Session identifier for key derivation.
            user_id: User whose secrets to load.
            db_pool: asyncpg-compatible connection pool.
            redis: Optional Redis client for session caching.
            session_ttl: TTL for Redis cache entries (seconds).

        Returns:
            Populated SessionVault instance.
        """
        vault = cls(
            session_uuid=session_uuid,
            user_id=user_id,
            db_pool=db_pool,
            redis=redis,
            session_ttl=session_ttl,
        )

        # Load all active secrets from DB
        async with db_pool.acquire() as conn:
            rows = await conn.fetch(_SELECT_ALL_ACTIVE, user_id)

        for row in rows:
            key = row["key"]
            ciphertext_db = row["ciphertext_db"]

            try:
                # Decrypt from DB layer
                plaintext_bytes = decrypt_for_db(ciphertext_db, vault._master_keys)
                # Re-encrypt for session layer
                ciphertext_mem = encrypt_for_session(plaintext_bytes, session_uuid)
                # Populate cache
                vault._cache[key] = ciphertext_mem
                # Populate Redis
                await vault._redis_set(key, ciphertext_mem)
            except Exception as err:
                logger.error(
                    "Failed to load vault secret key=%s for user=%s: %s",
                    key, user_id, err,
                )

        logger.info(
            "Vault loaded for user=%s: %d secret(s)", user_id, len(vault._cache),
        )
        return vault
