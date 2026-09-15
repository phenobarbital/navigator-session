"""
SessionVault — Encrypted key-value storage bound to a user session.

Provides the public API for the Session Vault system:
- ``set(key, value)`` — encrypt and persist a secret
- ``get(key, default)`` — decrypt and return a secret (cache → Redis → default)
- ``delete(key)`` — soft-delete a secret
- ``keys()`` / ``exists(key)`` / ``list_metadata()`` — enumerate cached secrets
- ``load_for_session()`` — factory that loads all user secrets from DB

Both layers use envelope v2 with context binding:

- Database layer: ``VaultContext("user-vault", "db", (user_id, key))``
- Session layer:  ``VaultContext("user-vault", "session", (sid_hmac, user_id, key))``
  sealed with a key derived from a master key *and* the session id.

Redis keys are ``vault:v2:{hmac(session_uuid)}:{hmac(key)}`` and audit rows
store ``hmac(session_uuid)``, so neither exposes session ids nor secret names.

Security Note:
    Never log plaintext or ciphertext values. Only log key names, operations,
    user IDs and error classes. Decrypted values exist in process memory during
    use — an accepted limitation (see threat model in ``__init__.py``).
"""
import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional

from .context import VaultContext
from .crypto import deserialize_value, serialize_value
from .envelope import (
    UnknownKeyVersionError,
    UnsupportedFormatError,
    VaultIntegrityError,
    open_sealed,
    seal,
)
from .keyring import KeyRing
from .models import VaultSecretMetadata
from .targets.postgres import acquire_connection, fetch_rows

logger = logging.getLogger("navigator.vault")

# Default maximum secrets per user (spec §7 resolution: 50)
_DEFAULT_MAX_KEYS_PER_USER = 50
_MAX_KEY_LENGTH = 255
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

PURPOSE = "user-vault"
REDIS_PREFIX = "vault:v2"

#: Errors meaning "this stored secret cannot be trusted/opened".
INTEGRITY_ERRORS = (VaultIntegrityError, UnknownKeyVersionError, UnsupportedFormatError)

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
SELECT key, ciphertext_db, key_version, updated_at
FROM auth.user_vault_secrets
WHERE user_id = $1 AND deleted_at IS NULL
"""

_INSERT_AUDIT = """
INSERT INTO auth.user_vault_audit (user_id, key, operation, key_version, session_id)
VALUES ($1, $2, $3, $4, $5)
"""


class _SessionKeyCache:
    """KeyRing view that caches the session keys of one session.

    Delegates everything to the wrapped :class:`KeyRing`; only
    ``derive_session_key`` for this vault's own session id is memoized
    (per key version and algorithm).
    """

    __slots__ = ("_ring", "_session_uuid", "_keys")

    def __init__(self, ring: KeyRing, session_uuid: str) -> None:
        self._ring = ring
        self._session_uuid = session_uuid
        self._keys: dict[tuple[int, int], bytes] = {}

    @property
    def active_key_id(self) -> int:
        return self._ring.active_key_id

    @property
    def write_alg_id(self) -> int:
        return self._ring.write_alg_id

    def has_key(self, key_id: int) -> bool:
        return self._ring.has_key(key_id)

    def derive_db_key(self, key_id: int, alg_id: int) -> bytes:
        return self._ring.derive_db_key(key_id, alg_id)

    def derive_session_key(self, key_id: int, alg_id: int, session_uuid: str) -> bytes:
        if session_uuid != self._session_uuid:
            return self._ring.derive_session_key(key_id, alg_id, session_uuid)
        cached = self._keys.get((key_id, alg_id))
        if cached is None:
            cached = self._ring.derive_session_key(key_id, alg_id, session_uuid)
            self._keys[(key_id, alg_id)] = cached
        return cached

    def __repr__(self) -> str:
        return f"_SessionKeyCache({self._ring!r})"

    def __reduce__(self):
        raise TypeError("session key cache holds key material and cannot be serialized")


class SessionVault:
    """Encrypted vault bound to a user session.

    Secrets are sealed twice with envelope v2:

    - **Session layer** (memory/Redis): key derived from a master key and the
      session id, context ``(hmac(session_uuid), user_id, key)``.
    - **Database layer** (PostgreSQL): key derived from the master key,
      context ``(user_id, key)``.

    Lookup order for ``get()``: in-memory cache → Redis → default. All user
    secrets are loaded from DB into the cache at session start via
    ``load_for_session()``.

    Args:
        session_uuid: Session identifier (cookie value or deterministic id).
        user_id: Owner of the secrets (integer primary key).
        db_pool: asyncpg-compatible pool.
        redis: Optional Redis client for the session cache.
        session_ttl: TTL of Redis cache entries in seconds.
        keyring: Key ring; defaults to ``KeyRing.from_env()``.

    Raises:
        ValueError: If ``session_uuid`` is empty or ``user_id`` is not an integer.
    """

    def __init__(
        self,
        session_uuid: str,
        user_id: int,
        db_pool: Any,
        redis: Any = None,
        session_ttl: int = 3600,
        *,
        keyring: Optional[KeyRing] = None,
    ):
        if not isinstance(session_uuid, str) or not session_uuid:
            raise ValueError("session_uuid must be a non-empty string")
        if isinstance(user_id, bool):
            raise ValueError("user_id must be an integer")
        self._session_uuid = session_uuid
        self._user_id = int(user_id)
        self._db = db_pool
        self._redis = redis
        self._ttl = session_ttl
        ring = keyring if keyring is not None else KeyRing.from_env()
        self._keyring = _SessionKeyCache(ring, session_uuid)
        self._sid_hmac = ring.naming_hmac(session_uuid)
        self._naming = ring.naming_hmac
        self._cache: dict[str, bytes] = {}  # key -> ciphertext_mem
        self._metadata: dict[str, VaultSecretMetadata] = {}
        self._max_keys_per_user = _DEFAULT_MAX_KEYS_PER_USER

    # ------------------------------------------------------------------
    # Validation & contexts
    # ------------------------------------------------------------------

    def _validate_key(self, key: str) -> None:
        """Validate a vault key name.

        ``:`` is allowed (Redis names are HMAC'd), e.g. ``jira:access_token``.

        Raises:
            ValueError: If key is empty, too long, or contains control characters.
        """
        if not isinstance(key, str) or not key:
            raise ValueError("Vault key cannot be empty")
        if len(key) > _MAX_KEY_LENGTH:
            raise ValueError(f"Vault key cannot exceed {_MAX_KEY_LENGTH} characters")
        if _CONTROL_CHARS.search(key):
            raise ValueError("Vault key cannot contain control characters")

    def _db_context(self, key: str) -> VaultContext:
        return VaultContext(
            purpose=PURPOSE, layer="db", fields=(("user_id", self._user_id), ("key", key))
        )

    def _session_context(self, key: str) -> VaultContext:
        return VaultContext(
            purpose=PURPOSE,
            layer="session",
            fields=(("sid_hmac", self._sid_hmac), ("user_id", self._user_id), ("key", key)),
        )

    def _seal_session(self, plaintext: bytes, key: str) -> bytes:
        return seal(
            plaintext, self._session_context(key), self._keyring,  # type: ignore[arg-type]
            session_uuid=self._session_uuid,
        )

    def _open_session(self, ciphertext_mem: bytes, key: str) -> Any:
        plaintext = open_sealed(
            ciphertext_mem, self._session_context(key), self._keyring,  # type: ignore[arg-type]
            session_uuid=self._session_uuid,
        )
        return deserialize_value(plaintext)

    # ------------------------------------------------------------------
    # Redis helpers
    # ------------------------------------------------------------------

    def _redis_key(self, key: str) -> str:
        """Build the Redis cache key (no raw session id or secret name)."""
        return f"{REDIS_PREFIX}:{self._sid_hmac}:{self._naming(key)}"

    async def _redis_set(self, key: str, ciphertext_mem: bytes) -> None:
        """Write ciphertext_mem to Redis with TTL. No-op if Redis is None."""
        if self._redis is not None:
            await self._redis.setex(self._redis_key(key), self._ttl, ciphertext_mem)

    async def _redis_get(self, key: str) -> Optional[bytes]:
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

    async def _audit(
        self, conn: Any, key: str, operation: str, key_version: Optional[int] = None
    ) -> None:
        """Insert an audit log entry (session id stored as HMAC)."""
        await conn.execute(
            _INSERT_AUDIT,
            self._user_id,
            key,
            operation,
            self._keyring.active_key_id if key_version is None else key_version,
            self._sid_hmac,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def set(self, key: str, value: Any) -> VaultSecretMetadata:
        """Encrypt and persist a secret.

        Supported types: str, int, float, dict, list, bytes, bool, None.
        The database write happens first; cache and Redis are updated only
        after it succeeds.

        Args:
            key: Secret name (max 255 chars, no control characters).
            value: Secret value to encrypt and store.

        Returns:
            Metadata of the stored secret (no value).

        Raises:
            ValueError: If key is invalid or max_keys_per_user exceeded.
        """
        self._validate_key(key)

        # Enforce max keys limit (overwrite doesn't count)
        if key not in self._cache and len(self._cache) >= self._max_keys_per_user:
            raise ValueError(
                f"Max secrets per user ({self._max_keys_per_user}) exceeded"
            )

        plaintext = serialize_value(value)
        key_version = self._keyring.active_key_id
        ciphertext_db = seal(plaintext, self._db_context(key), self._keyring)  # type: ignore[arg-type]
        ciphertext_mem = self._seal_session(plaintext, key)

        async with acquire_connection(self._db) as conn:
            await conn.execute(_UPSERT_SECRET, self._user_id, key, ciphertext_db, key_version)
            await self._audit(conn, key, "set", key_version)

        self._cache[key] = ciphertext_mem
        await self._redis_set(key, ciphertext_mem)
        metadata = VaultSecretMetadata(
            key=key, updated_at=datetime.now(timezone.utc), key_version=key_version
        )
        self._metadata[key] = metadata

        logger.debug("Vault set: user=%s key=%s", self._user_id, key)
        return metadata

    async def get(self, key: str, default: Any = None) -> Any:
        """Decrypt and return a secret.

        Lookup order: in-memory cache → Redis → default.

        Args:
            key: Secret name.
            default: Value returned if key not found.

        Returns:
            Decrypted value, or default if not found.

        Raises:
            VaultIntegrityError: If the cached ciphertext fails authentication
                (the entry is evicted from the in-memory cache).
        """
        self._validate_key(key)

        ct_mem = self._cache.get(key)
        source = "cache"
        if ct_mem is None:
            ct_mem = await self._redis_get(key)
            source = "redis"
        if ct_mem is None:
            return default

        try:
            value = self._open_session(bytes(ct_mem), key)
        except INTEGRITY_ERRORS as err:
            self._cache.pop(key, None)
            logger.error(
                "Vault get integrity failure: user=%s key=%s source=%s error=%s",
                self._user_id, key, source, type(err).__name__,
            )
            raise
        if source == "redis":
            self._cache[key] = bytes(ct_mem)
        return value

    async def delete(self, key: str) -> None:
        """Soft-delete a secret from vault.

        Removes from in-memory cache, Redis, and marks deleted_at in DB.

        Args:
            key: Secret name to delete.
        """
        self._validate_key(key)

        self._cache.pop(key, None)
        self._metadata.pop(key, None)
        await self._redis_delete(key)

        async with acquire_connection(self._db) as conn:
            await conn.execute(_SOFT_DELETE_SECRET, self._user_id, key)
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

    async def list_metadata(self) -> list[VaultSecretMetadata]:
        """List metadata of the cached secrets, sorted by key (no values).

        Returns:
            Metadata for every secret known to this vault instance.
        """
        return [self._metadata[k] for k in sorted(self._metadata) if k in self._cache]

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
        *,
        keyring: Optional[KeyRing] = None,
    ) -> "SessionVault":
        """Load all user secrets from DB, re-seal for the session, populate cache.

        Secrets whose database ciphertext fails to open (tampered, moved from
        another user/key, unknown key version, legacy format) are skipped,
        logged by key name and error class, and audited as ``integrity_fail``.
        Loading never fails because of a single bad secret.

        Args:
            session_uuid: Session identifier for key derivation.
            user_id: User whose secrets to load.
            db_pool: asyncpg-compatible connection pool.
            redis: Optional Redis client for session caching.
            session_ttl: TTL for Redis cache entries (seconds).
            keyring: Key ring; defaults to ``KeyRing.from_env()``.

        Returns:
            Populated SessionVault instance.
        """
        vault = cls(
            session_uuid=session_uuid,
            user_id=user_id,
            db_pool=db_pool,
            redis=redis,
            session_ttl=session_ttl,
            keyring=keyring,
        )

        async with acquire_connection(db_pool) as conn:
            rows = await fetch_rows(conn, _SELECT_ALL_ACTIVE, vault._user_id)

        failures: list[tuple[str, Optional[int]]] = []
        for row in rows:
            key = row["key"]
            try:
                plaintext = open_sealed(
                    bytes(row["ciphertext_db"]), vault._db_context(key), vault._keyring  # type: ignore[arg-type]
                )
            except INTEGRITY_ERRORS as err:
                logger.error(
                    "Vault secret failed integrity check: user=%s key=%s error=%s",
                    vault._user_id, key, type(err).__name__,
                )
                failures.append((key, row["key_version"]))
                continue
            try:
                ciphertext_mem = vault._seal_session(plaintext, key)
                vault._cache[key] = ciphertext_mem
                await vault._redis_set(key, ciphertext_mem)
                vault._metadata[key] = VaultSecretMetadata(
                    key=key,
                    updated_at=row["updated_at"] or datetime.now(timezone.utc),
                    key_version=row["key_version"],
                )
            except Exception as err:  # noqa: BLE001 - one secret must not break login
                vault._cache.pop(key, None)
                logger.error(
                    "Failed to load vault secret key=%s for user=%s: %s",
                    key, vault._user_id, type(err).__name__,
                )

        if failures:
            try:
                async with acquire_connection(db_pool) as conn:
                    for key, key_version in failures:
                        await vault._audit(conn, key, "integrity_fail", key_version)
            except Exception as err:  # noqa: BLE001 - auditing must not break login
                logger.error(
                    "Failed to audit vault integrity failures for user=%s: %s",
                    vault._user_id, type(err).__name__,
                )

        logger.info(
            "Vault loaded for user=%s: %d secret(s), %d integrity failure(s)",
            vault._user_id, len(vault._cache), len(failures),
        )
        return vault
