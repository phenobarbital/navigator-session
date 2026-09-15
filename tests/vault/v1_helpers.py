"""Test-only v1 database-layer encryption (mirrors navigator-session 0.10.x encrypt_for_db)."""
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def encrypt_v1_db(plaintext: bytes, key_id: int, master_key: bytes, backend: str = "aesgcm") -> bytes:
    key = HKDF(hashes.SHA256(), 32, None, f"vault-db-v{key_id}".encode()).derive(master_key)
    cipher = ChaCha20Poly1305 if backend == "chacha20" else AESGCM
    nonce = os.urandom(12)
    return struct.pack("!H", key_id) + nonce + cipher(key).encrypt(nonce, plaintext, None)
