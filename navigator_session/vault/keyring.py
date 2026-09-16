"""
Vault KeyRing — Master key ring and v2 key schedule.

The ``KeyRing`` owns every piece of vault key material:

- the master key ring (``VAULT_MASTER_KEY_v{N}``) and the active key id
  (``VAULT_ACTIVE_KEY_ID``);
- the AEAD algorithm used for new writes (``VAULT_CIPHER_BACKEND``);
- the naming key used to HMAC session ids and secret names
  (``VAULT_NAMING_KEY_ID``, defaulting to the lowest key id in the ring);
- all HKDF-SHA256 sub-key derivations with v2-only, domain-separated labels.

Raw master keys never leave this object. The derivation methods are
kernel-internal: they exist for the envelope layer and must not be used to
export key material.

Key schedule (all outputs are 32 bytes)::

    db key       HKDF(master_key[key_id], "navigator-vault/v2/db" ‖ alg_id)
    session key  HKDF(master_key[key_id], "navigator-vault/v2/session" ‖ alg_id ‖ lp(session_uuid))
    naming key   HKDF(master_key[naming_key_id], "navigator-vault/v2/naming")

``lp(x)`` is a 4-byte big-endian length prefix followed by the UTF-8 bytes.

Security Note:
    Never log key material. Only log key ids and algorithm names.
"""
import hashlib
import hmac
import logging
import os
import struct
from typing import Mapping, Optional, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import get_active_key_id, get_naming_key_id, load_master_keys

logger = logging.getLogger("navigator.vault")

KEY_LENGTH = 32
MIN_KEY_ID = 1
MAX_KEY_ID = 0xFFFF

ALG_AESGCM = 0x01
ALG_CHACHA20 = 0x02

#: ``VAULT_CIPHER_BACKEND`` value → algorithm id recorded in envelopes.
CIPHER_BACKENDS: dict[str, int] = {
    "aesgcm": ALG_AESGCM,
    "chacha20": ALG_CHACHA20,
}
ALG_NAMES: dict[int, str] = {alg_id: name for name, alg_id in CIPHER_BACKENDS.items()}

_DB_LABEL = b"navigator-vault/v2/db"
_SESSION_LABEL = b"navigator-vault/v2/session"
_NAMING_LABEL = b"navigator-vault/v2/naming"


def lp(data: Union[str, bytes]) -> bytes:
    """Length-prefix a value for unambiguous concatenation.

    Args:
        data: Text (encoded as UTF-8) or raw bytes.

    Returns:
        4-byte big-endian length followed by the bytes.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    return struct.pack("!I", len(raw)) + raw


def _hkdf(master_key: bytes, info: bytes) -> bytes:
    """Derive a 32-byte sub-key with HKDF-SHA256.

    Args:
        master_key: Input key material (a 32-byte master key).
        info: Domain-separation label.

    Returns:
        32-byte derived key.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=None,  # master keys are uniformly random; info provides separation
        info=info,
    ).derive(master_key)


def resolve_cipher_backend(backend: str) -> int:
    """Map a ``VAULT_CIPHER_BACKEND`` value to its algorithm id.

    Args:
        backend: Backend name (case-insensitive), e.g. ``"aesgcm"``.

    Returns:
        Algorithm id recorded in envelope headers.

    Raises:
        ValueError: If the backend is not supported.
    """
    try:
        return CIPHER_BACKENDS[backend.strip().lower()]
    except KeyError:
        raise ValueError(
            f"Unsupported VAULT_CIPHER_BACKEND {backend!r}; "
            f"expected one of {sorted(CIPHER_BACKENDS)}"
        ) from None


class KeyRing:
    """Master key ring, write algorithm, naming key and v2 key schedule.

    Args:
        master_keys: Mapping of key id to raw 32-byte master key.
        active_key_id: Key id used for new writes.
        cipher_backend: AEAD used for new writes (``"aesgcm"`` or ``"chacha20"``).
        naming_key_id: Key id used to derive the naming key. Defaults to the
            lowest key id in the ring, which stays stable across rotations.

    Raises:
        ValueError: If the ring is empty, a key id is out of range, a key is
            not 32 bytes, or the active/naming key id is not in the ring.
    """

    __slots__ = (
        "_keys",
        "_active_key_id",
        "_write_alg_id",
        "_naming_key_id",
        "_naming_key",
        "_db_keys",
    )

    def __init__(
        self,
        master_keys: Mapping[int, bytes],
        active_key_id: int,
        *,
        cipher_backend: str = "aesgcm",
        naming_key_id: Optional[int] = None,
    ) -> None:
        if not master_keys:
            raise ValueError("Vault key ring is empty")
        keys: dict[int, bytes] = {}
        for key_id, key in master_keys.items():
            self._check_key_id(key_id)
            if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_LENGTH:
                raise ValueError(
                    f"Master key v{key_id} must be exactly {KEY_LENGTH} bytes"
                )
            keys[key_id] = bytes(key)
        self._check_key_id(active_key_id)
        if active_key_id not in keys:
            raise ValueError(
                f"Active key version {active_key_id} not found in key ring "
                f"(available: {sorted(keys)})"
            )
        if naming_key_id is None:
            naming_key_id = min(keys)
        self._check_key_id(naming_key_id)
        if naming_key_id not in keys:
            raise ValueError(
                f"Naming key version {naming_key_id} not found in key ring "
                f"(available: {sorted(keys)}); removing it orphans Redis vault "
                "caches — set VAULT_NAMING_KEY_ID to a key that stays in the ring"
            )
        self._keys = keys
        self._active_key_id = active_key_id
        self._write_alg_id = resolve_cipher_backend(cipher_backend)
        self._naming_key_id = naming_key_id
        self._naming_key = _hkdf(keys[naming_key_id], _NAMING_LABEL)
        self._db_keys: dict[tuple[int, int], bytes] = {}

    @classmethod
    def from_env(cls) -> "KeyRing":
        """Build a KeyRing from the vault environment variables.

        Reads ``VAULT_MASTER_KEY_v{N}``, ``VAULT_ACTIVE_KEY_ID``,
        ``VAULT_CIPHER_BACKEND`` (default ``aesgcm``) and the optional
        ``VAULT_NAMING_KEY_ID``.

        Returns:
            Configured KeyRing.

        Raises:
            RuntimeError: If no master keys or no active key id are configured.
            ValueError: If any value is invalid.
        """
        ring = cls(
            load_master_keys(),
            get_active_key_id(),
            cipher_backend=os.environ.get("VAULT_CIPHER_BACKEND", "aesgcm"),
            naming_key_id=get_naming_key_id(),
        )
        logger.debug(
            "Vault KeyRing loaded: key ids %s, active v%d, write alg %s, naming v%d",
            list(ring.key_ids),
            ring.active_key_id,
            ALG_NAMES[ring.write_alg_id],
            ring.naming_key_id,
        )
        return ring

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def active_key_id(self) -> int:
        """Key id used for new writes."""
        return self._active_key_id

    @property
    def write_alg_id(self) -> int:
        """Algorithm id used for new writes."""
        return self._write_alg_id

    @property
    def naming_key_id(self) -> int:
        """Key id the naming key is derived from."""
        return self._naming_key_id

    @property
    def key_ids(self) -> tuple[int, ...]:
        """Sorted key ids present in the ring."""
        return tuple(sorted(self._keys))

    def has_key(self, key_id: int) -> bool:
        """Return whether ``key_id`` is present in the ring.

        Args:
            key_id: Master key version.

        Returns:
            True if the ring holds that version.
        """
        return key_id in self._keys

    def naming_hmac(self, value: str) -> str:
        """HMAC a name with the naming key (Redis key names, audit session ids).

        Args:
            value: Session id or secret name.

        Returns:
            Lowercase hex HMAC-SHA256 digest (64 characters).

        Raises:
            TypeError: If ``value`` is not a string.
        """
        if not isinstance(value, str):
            raise TypeError("naming_hmac expects a str")
        return hmac.new(
            self._naming_key, value.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    # ------------------------------------------------------------------
    # Kernel-internal derivations (used by the envelope layer)
    # ------------------------------------------------------------------

    def derive_db_key(self, key_id: int, alg_id: int) -> bytes:
        """Derive the database-layer key for a key version and algorithm.

        Kernel-internal: callers outside ``navigator_session.vault`` must use
        the envelope API instead.

        Args:
            key_id: Master key version.
            alg_id: Algorithm id from the envelope header.

        Returns:
            32-byte AEAD key.

        Raises:
            KeyError: If ``key_id`` is not in the ring.
            ValueError: If ``alg_id`` is unknown.
        """
        cache_key = (key_id, alg_id)
        cached = self._db_keys.get(cache_key)
        if cached is None:
            master_key = self._master_key(key_id)
            cached = _hkdf(master_key, _DB_LABEL + bytes([self._check_alg_id(alg_id)]))
            self._db_keys[cache_key] = cached
        return cached

    def derive_session_key(self, key_id: int, alg_id: int, session_uuid: str) -> bytes:
        """Derive the session-layer key bound to a session id.

        Kernel-internal. The result is not cached here (unbounded input);
        ``SessionVault`` caches its own session key per instance.

        Args:
            key_id: Master key version.
            alg_id: Algorithm id from the envelope header.
            session_uuid: Session identifier (cookie value or deterministic id).

        Returns:
            32-byte AEAD key.

        Raises:
            KeyError: If ``key_id`` is not in the ring.
            ValueError: If ``alg_id`` is unknown or ``session_uuid`` is empty.
        """
        if not isinstance(session_uuid, str) or not session_uuid:
            raise ValueError("session_uuid must be a non-empty string")
        master_key = self._master_key(key_id)
        info = _SESSION_LABEL + bytes([self._check_alg_id(alg_id)]) + lp(session_uuid)
        return _hkdf(master_key, info)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _master_key(self, key_id: int) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError:
            raise KeyError(
                f"Master key version {key_id} not found in key ring"
            ) from None

    @staticmethod
    def _check_key_id(key_id: int) -> None:
        if (
            isinstance(key_id, bool)
            or not isinstance(key_id, int)
            or not MIN_KEY_ID <= key_id <= MAX_KEY_ID
        ):
            raise ValueError(
                f"Key id must be an integer in [{MIN_KEY_ID}, {MAX_KEY_ID}], "
                f"got {key_id!r}"
            )

    @staticmethod
    def _check_alg_id(alg_id: int) -> int:
        if alg_id not in ALG_NAMES:
            raise ValueError(f"Unknown vault algorithm id {alg_id!r}")
        return alg_id

    def __repr__(self) -> str:
        return (
            f"KeyRing(key_ids={list(self.key_ids)}, "
            f"active_key_id={self._active_key_id}, "
            f"write_alg={ALG_NAMES[self._write_alg_id]!r}, "
            f"naming_key_id={self._naming_key_id})"
        )

    def __reduce__(self):
        # Key material must never be pickled/serialized by accident
        # (e.g. by a session store serializing attached objects).
        raise TypeError("KeyRing holds key material and cannot be serialized")
