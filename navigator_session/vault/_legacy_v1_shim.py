"""
TEMPORARY legacy v1 crypto shim — FEAT-099 (TASK-071).

Holds the pre-1.0 Session Vault primitives (``encrypt_for_session``,
``decrypt_for_session``, ``encrypt_for_db``, ``decrypt_for_db``) that were
removed from the public ``navigator_session.vault.crypto`` module, so that
``session_vault.py`` and ``key_rotation.py`` stay importable until they are
rewritten on top of the v2 envelope.

DELETE this module in TASK-073 (SessionVault v2) / TASK-074 (key rotation).
Do not import it from anywhere else. The migrator keeps its own isolated
v1 reader (TASK-075).

v1 formats (no AAD, algorithm not recorded):
- Session layer: HKDF(session_uuid, "vault-session") → AEAD → [nonce|payload+tag]
- Database layer: HKDF(MASTER_KEY_vN, "vault-db-vN") → AEAD → [key_id|nonce|payload+tag]
"""
import os
import struct
import logging

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

logger = logging.getLogger("navigator.vault")

NONCE_SIZE = 12  # 96-bit nonce
KEY_ID_SIZE = 2  # uint16 big-endian
KEY_LENGTH = 32  # AES-256


def _get_cipher_cls() -> type:
    """Return the AEAD cipher class based on VAULT_CIPHER_BACKEND env var."""
    backend = os.environ.get("VAULT_CIPHER_BACKEND", "aesgcm").lower()
    if backend == "chacha20":
        return ChaCha20Poly1305
    return AESGCM


# Resolve cipher once at module load to prevent encrypt/decrypt mismatch
# if the env var changes mid-process.
CIPHER_CLS = _get_cipher_cls()


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_key(seed: bytes, context: str) -> bytes:
    """Derive a 32-byte encryption key using HKDF-SHA256.

    Args:
        seed: Input key material (master key bytes or session UUID bytes).
        context: Context string for domain separation (e.g. "vault-session").

    Returns:
        32-byte derived key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=None,  # Intentional: deterministic derivation for vault keys
        info=context.encode("utf-8"),
    )
    return hkdf.derive(seed)


# ---------------------------------------------------------------------------
# Session-layer encryption (ephemeral, RAM/Redis)
# ---------------------------------------------------------------------------

def encrypt_for_session(plaintext: bytes, session_uuid: str) -> bytes:
    """Encrypt plaintext for session-scoped storage.

    Format: [nonce 12B][encrypted_payload + GCM_tag 16B]

    Args:
        plaintext: Data to encrypt.
        session_uuid: Session identifier used for key derivation.

    Returns:
        ciphertext_mem bytes.
    """
    key = derive_key(session_uuid.encode("utf-8"), "vault-session")
    cipher = CIPHER_CLS(key)
    nonce = os.urandom(NONCE_SIZE)
    ct = cipher.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_for_session(ciphertext_mem: bytes, session_uuid: str) -> bytes:
    """Decrypt session-scoped ciphertext.

    Args:
        ciphertext_mem: Ciphertext in format [nonce 12B][payload+tag].
        session_uuid: Session identifier used for key derivation.

    Returns:
        Decrypted plaintext bytes.
    """
    _min = NONCE_SIZE + 16  # nonce + GCM tag
    if len(ciphertext_mem) < _min:
        raise ValueError(
            f"ciphertext_mem too short: {len(ciphertext_mem)} bytes "
            f"(minimum {_min})"
        )
    key = derive_key(session_uuid.encode("utf-8"), "vault-session")
    cipher = CIPHER_CLS(key)
    nonce = ciphertext_mem[:NONCE_SIZE]
    ct = ciphertext_mem[NONCE_SIZE:]
    return cipher.decrypt(nonce, ct, None)


# ---------------------------------------------------------------------------
# Database-layer encryption (persistent, PostgreSQL)
# ---------------------------------------------------------------------------

def encrypt_for_db(plaintext: bytes, key_id: int, master_key: bytes) -> bytes:
    """Encrypt plaintext for database storage with embedded key version.

    Format: [key_id 2B uint16 BE][nonce 12B][encrypted_payload + tag]

    Args:
        plaintext: Data to encrypt.
        key_id: Master key version identifier.
        master_key: Raw 32-byte master key for this version.

    Returns:
        ciphertext_db bytes with key_id prefix.
    """
    context = f"vault-db-v{key_id}"
    derived = derive_key(master_key, context)
    cipher = CIPHER_CLS(derived)
    nonce = os.urandom(NONCE_SIZE)
    ct = cipher.encrypt(nonce, plaintext, None)
    key_id_bytes = struct.pack("!H", key_id)
    return key_id_bytes + nonce + ct


def decrypt_for_db(ciphertext_db: bytes, master_keys: dict[int, bytes]) -> bytes:
    """Decrypt database-stored ciphertext using embedded key version.

    Args:
        ciphertext_db: Ciphertext in format [key_id 2B][nonce 12B][payload+tag].
        master_keys: Mapping of key_id → raw 32-byte master key.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        KeyError: If the key_id extracted from ciphertext is not in master_keys.
    """
    _min = KEY_ID_SIZE + NONCE_SIZE + 16  # key_id + nonce + GCM tag
    if len(ciphertext_db) < _min:
        raise ValueError(
            f"ciphertext_db too short: {len(ciphertext_db)} bytes "
            f"(minimum {_min})"
        )
    key_id = struct.unpack("!H", ciphertext_db[:KEY_ID_SIZE])[0]
    if key_id not in master_keys:
        raise KeyError(
            f"Master key version {key_id} not found in provided keys"
        )
    master_key = master_keys[key_id]
    context = f"vault-db-v{key_id}"
    derived = derive_key(master_key, context)
    cipher = CIPHER_CLS(derived)
    nonce = ciphertext_db[KEY_ID_SIZE:KEY_ID_SIZE + NONCE_SIZE]
    ct = ciphertext_db[KEY_ID_SIZE + NONCE_SIZE:]
    return cipher.decrypt(nonce, ct, None)
