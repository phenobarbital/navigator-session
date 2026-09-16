"""
Legacy v1 vault reader — used ONLY by the offline migrator.

Reproduces the pre-1.0 database-layer decryption (navigator-session 0.10.x
``decrypt_for_db``)::

    blob = key_id (uint16 BE) ‖ nonce (12B) ‖ ciphertext ‖ tag (16B)
    key  = HKDF-SHA256(master_key[key_id], info="vault-db-v{key_id}")
    AEAD = AES-256-GCM or ChaCha20-Poly1305, no associated data

v1 did not record the algorithm; it used ``VAULT_CIPHER_BACKEND`` at import time
(anything other than ``chacha20`` meant AES-GCM). The reader tries the configured
algorithm first and then the other one: AEAD authentication makes a wrong guess
fail safely, and data written under a historical backend change still migrates.

This module is not exported from ``navigator_session.vault`` nor from
``navigator_session.vault.migrate`` and must not be used by runtime code.

Security Note:
    Never log plaintext, ciphertext or key material.
"""
import os
import struct
from typing import Mapping, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..config import load_master_keys
from ..envelope import UnknownKeyVersionError

_KEY_ID_SIZE = 2
_NONCE_SIZE = 12
_TAG_SIZE = 16
MIN_V1_BLOB_SIZE = _KEY_ID_SIZE + _NONCE_SIZE + _TAG_SIZE


class LegacyV1Error(Exception):
    """A blob could not be decrypted as a v1 database-layer ciphertext."""


class LegacyV1Reader:
    """Decrypts v1 database-layer blobs with the legacy key schedule.

    Args:
        master_keys: Mapping of key id to raw 32-byte master key.
        cipher_backend: v1 ``VAULT_CIPHER_BACKEND`` value (tried first).
    """

    __slots__ = ("_keys", "_algorithms")

    def __init__(self, master_keys: Mapping[int, bytes], cipher_backend: str = "aesgcm") -> None:
        self._keys = {int(k): bytes(v) for k, v in master_keys.items()}
        preferred = ChaCha20Poly1305 if cipher_backend.strip().lower() == "chacha20" else AESGCM
        other = AESGCM if preferred is ChaCha20Poly1305 else ChaCha20Poly1305
        self._algorithms = (preferred, other)

    @classmethod
    def from_env(cls) -> "LegacyV1Reader":
        """Build the reader from ``VAULT_MASTER_KEY_v{N}`` and ``VAULT_CIPHER_BACKEND``."""
        return cls(load_master_keys(), os.environ.get("VAULT_CIPHER_BACKEND", "aesgcm"))

    def key_id_of(self, blob: bytes) -> Optional[int]:
        """Return the v1 key id prefix of a blob, or ``None`` if too short."""
        if len(blob) < MIN_V1_BLOB_SIZE:
            return None
        return struct.unpack("!H", blob[:_KEY_ID_SIZE])[0]

    def decrypt(self, blob: bytes) -> bytes:
        """Decrypt a v1 database-layer blob.

        Args:
            blob: Stored v1 ciphertext.

        Returns:
            Plaintext bytes (v1 ``serialize_value`` output).

        Raises:
            UnknownKeyVersionError: If the key id is not in the ring.
            LegacyV1Error: If the blob is malformed or fails authentication.
        """
        data = bytes(blob)
        key_id = self.key_id_of(data)
        if key_id is None:
            raise LegacyV1Error(f"blob too short for v1 format ({len(data)} bytes)")
        master_key = self._keys.get(key_id)
        if master_key is None:
            raise UnknownKeyVersionError(f"master key version {key_id} not found in key ring")
        key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=f"vault-db-v{key_id}".encode("utf-8"),
        ).derive(master_key)
        nonce = data[_KEY_ID_SIZE:_KEY_ID_SIZE + _NONCE_SIZE]
        ciphertext = data[_KEY_ID_SIZE + _NONCE_SIZE:]
        for algorithm in self._algorithms:
            try:
                return algorithm(key).decrypt(nonce, ciphertext, None)
            except InvalidTag:
                continue
        raise LegacyV1Error("v1 authentication failed")

    def __repr__(self) -> str:
        return f"LegacyV1Reader(key_ids={sorted(self._keys)})"

    def __reduce__(self):
        raise TypeError("LegacyV1Reader holds key material and cannot be serialized")
