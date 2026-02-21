"""Session Vault — Encrypted secret storage bound to user sessions.

Security Note (Threat Model):
    Secrets are decrypted in process memory during session lifetime.
    A memory dump of the application process could expose session_uuid
    and ciphertext_mem, from which plaintext can be recovered.
    This is an accepted limitation — mitigation requires HSM/secure
    enclave integration which is out of scope.
"""

from .session_vault import SessionVault
from .key_rotation import rotate_master_key
from .config import VaultConfig, load_master_keys, generate_master_key

__all__ = [
    "SessionVault",
    "rotate_master_key",
    "VaultConfig",
    "load_master_keys",
    "generate_master_key",
]
