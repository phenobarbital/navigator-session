"""Session Vault — Encrypted secret storage bound to user sessions.

Crypto kernel (envelope v2):
    - ``KeyRing`` owns the master key ring (``VAULT_MASTER_KEY_v{N}``), the
      write algorithm and all HKDF-SHA256 sub-key derivations.
    - ``seal`` / ``open_sealed`` produce and open versioned envelopes
      (format, algorithm id, key id, nonce) whose associated data binds the
      ciphertext to a ``VaultContext`` (purpose, layer, row and field).

Security Note (Threat Model):
    - Session-layer keys are derived from a master key *and* the session id,
      so Redis contents plus a session cookie are not enough to decrypt.
    - A ciphertext copied to another user, row or field fails authentication
      (``VaultIntegrityError``) instead of decrypting silently.
    - Anyone holding the master keys can decrypt everything; protect them.
    - Secrets are decrypted in process memory while in use; a memory dump of
      the application process can expose plaintext. Mitigation requires
      HSM/secure-enclave integration and is out of scope.

    Transitional: ``SessionVault`` and ``rotate_master_key`` still use the
    legacy v1 primitives until they are rebuilt on the v2 envelope.
"""

from .session_vault import SessionVault
from .key_rotation import rotate_master_key
from .config import VaultConfig, load_master_keys, generate_master_key
from .context import ContextValue, VaultContext
from .envelope import (
    EnvelopeHeader,
    UnknownKeyVersionError,
    UnsupportedFormatError,
    VaultCryptoError,
    VaultIntegrityError,
    open_sealed,
    open_value,
    read_header,
    seal,
    seal_value,
)
from .keyring import KeyRing

__all__ = [
    "SessionVault",
    "rotate_master_key",
    "VaultConfig",
    "load_master_keys",
    "generate_master_key",
    "KeyRing",
    "ContextValue",
    "VaultContext",
    "EnvelopeHeader",
    "seal",
    "open_sealed",
    "seal_value",
    "open_value",
    "read_header",
    "VaultCryptoError",
    "VaultIntegrityError",
    "UnknownKeyVersionError",
    "UnsupportedFormatError",
]
