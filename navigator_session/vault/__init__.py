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

    - Redis key names and audit rows carry HMACs, never raw session ids or
      secret names.

    Master key rotation (``rotate_master_key``) re-seals every registered
    protected target; legacy v1 data is only readable by the offline migrator.
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
from .models import VaultSecretMetadata

__all__ = [
    "VaultSecretMetadata",
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
