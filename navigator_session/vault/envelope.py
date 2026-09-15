"""
Vault Envelope v2 — versioned, context-bound AEAD sealing.

Every vault ciphertext (database and session layers) uses this format::

    offset  size  field
    0       1     format_version   0xA2
    1       1     alg_id           0x01 AES-256-GCM · 0x02 ChaCha20-Poly1305
    2       2     key_id           uint16 big-endian
    4       12    nonce            random
    16      n     ciphertext
    16+n    16    tag

Associated data = ``"NAVVAULT-AAD" ‖ header(16B) ‖ context.canonical_bytes()``.
The header is authenticated, the algorithm is read from the header (not from
the environment), and a blob only opens with the exact :class:`VaultContext`
it was sealed with.

Security Note:
    Never log plaintext, ciphertext or key material.
"""
import os
import struct
from typing import Any, Literal, Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .context import VaultContext
from .crypto import deserialize_value, serialize_value
from .keyring import ALG_AESGCM, ALG_CHACHA20, KeyRing

FORMAT_VERSION = 0xA2
NONCE_SIZE = 12
TAG_SIZE = 16
HEADER_SIZE = 16
MIN_BLOB_SIZE = HEADER_SIZE + TAG_SIZE
AAD_MAGIC = b"NAVVAULT-AAD"

_HEADER_STRUCT = struct.Struct("!BBH12s")
_AEAD_CLASSES: dict[int, type] = {
    ALG_AESGCM: AESGCM,
    ALG_CHACHA20: ChaCha20Poly1305,
}

BytesLike = Union[bytes, bytearray, memoryview]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class VaultCryptoError(Exception):
    """Base class for vault envelope errors."""


class VaultIntegrityError(VaultCryptoError):
    """Authentication failed: tampered ciphertext/header or wrong context."""


class UnknownKeyVersionError(VaultCryptoError, KeyError):
    """The envelope references a master key version not present in the ring."""

    def __str__(self) -> str:  # KeyError would repr()-quote the message
        return str(self.args[0]) if self.args else ""


class UnsupportedFormatError(VaultCryptoError):
    """The blob is not a valid v2 envelope (legacy v1, truncated, unknown algorithm)."""


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

class EnvelopeHeader(BaseModel):
    """Parsed 16-byte envelope header.

    Attributes:
        format_version: Always ``0xA2`` for envelope v2.
        alg_id: AEAD algorithm id.
        key_id: Master key version used to derive the key.
        nonce: 12-byte AEAD nonce.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    format_version: Literal[0xA2] = FORMAT_VERSION
    alg_id: Literal[1, 2]
    key_id: int = Field(ge=1, le=0xFFFF)
    nonce: bytes

    @field_validator("nonce")
    @classmethod
    def _validate_nonce(cls, value: bytes) -> bytes:
        if len(value) != NONCE_SIZE:
            raise ValueError(f"nonce must be {NONCE_SIZE} bytes")
        return value

    def to_bytes(self) -> bytes:
        """Serialize the header to its 16-byte wire form."""
        return _HEADER_STRUCT.pack(
            self.format_version, self.alg_id, self.key_id, self.nonce
        )

    @classmethod
    def from_bytes(cls, data: BytesLike) -> "EnvelopeHeader":
        """Parse a header from the first 16 bytes of a blob.

        Args:
            data: Blob or header bytes (at least 16 bytes).

        Returns:
            Parsed header.

        Raises:
            UnsupportedFormatError: If the bytes are not a valid v2 header.
        """
        raw = bytes(data[:HEADER_SIZE])
        if len(raw) < HEADER_SIZE:
            raise UnsupportedFormatError("blob too short for a v2 envelope header")
        version, alg_id, key_id, nonce = _HEADER_STRUCT.unpack(raw)
        if version != FORMAT_VERSION:
            raise UnsupportedFormatError(
                f"unsupported vault envelope format 0x{version:02x} "
                f"(expected 0x{FORMAT_VERSION:02x})"
            )
        if alg_id not in _AEAD_CLASSES:
            raise UnsupportedFormatError(f"unknown vault algorithm id {alg_id}")
        try:
            return cls(alg_id=alg_id, key_id=key_id, nonce=nonce)
        except ValidationError:
            raise UnsupportedFormatError("invalid vault envelope header") from None


def read_header(blob: BytesLike) -> EnvelopeHeader:
    """Parse the header of a sealed blob without decrypting it.

    Useful for rotation/migration to inspect ``key_id`` and ``alg_id``.

    Args:
        blob: Sealed envelope.

    Returns:
        Parsed header.

    Raises:
        UnsupportedFormatError: If the blob is not a v2 envelope.
    """
    if len(blob) < MIN_BLOB_SIZE:
        raise UnsupportedFormatError(
            f"blob too short: {len(blob)} bytes (minimum {MIN_BLOB_SIZE})"
        )
    return EnvelopeHeader.from_bytes(blob)


def build_aad(header: bytes, context: VaultContext) -> bytes:
    """Build the associated data for a header and context.

    Args:
        header: 16-byte serialized header.
        context: Context the ciphertext is bound to.

    Returns:
        ``"NAVVAULT-AAD" ‖ header ‖ context.canonical_bytes()``.
    """
    return AAD_MAGIC + header + context.canonical_bytes()


# ---------------------------------------------------------------------------
# Seal / open
# ---------------------------------------------------------------------------

def _random_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)


def _check_inputs(context: VaultContext, session_uuid: Optional[str]) -> None:
    if not isinstance(context, VaultContext):
        raise TypeError("context must be a VaultContext")
    if context.layer == "session" and session_uuid is None:
        raise ValueError("session_uuid is required for session-layer contexts")
    if context.layer == "db" and session_uuid is not None:
        raise ValueError("session_uuid must not be given for db-layer contexts")


def _aead(
    keyring: KeyRing,
    alg_id: int,
    key_id: int,
    context: VaultContext,
    session_uuid: Optional[str],
) -> Any:
    if not keyring.has_key(key_id):
        raise UnknownKeyVersionError(
            f"master key version {key_id} not found in key ring"
        )
    if context.layer == "session":
        key = keyring.derive_session_key(key_id, alg_id, session_uuid)  # type: ignore[arg-type]
    else:
        key = keyring.derive_db_key(key_id, alg_id)
    return _AEAD_CLASSES[alg_id](key)


def seal(
    plaintext: BytesLike,
    context: VaultContext,
    keyring: KeyRing,
    *,
    session_uuid: Optional[str] = None,
    key_id: Optional[int] = None,
) -> bytes:
    """Encrypt bytes into a v2 envelope bound to ``context``.

    Args:
        plaintext: Bytes to encrypt.
        context: Context the ciphertext is bound to.
        keyring: Key ring providing keys and the write algorithm.
        session_uuid: Required for ``layer="session"``, forbidden for ``"db"``.
        key_id: Master key version to use; defaults to the active key.

    Returns:
        Sealed envelope bytes.

    Raises:
        TypeError: If ``plaintext`` is not bytes-like or ``context`` is invalid.
        ValueError: If ``session_uuid`` does not match the context layer.
        UnknownKeyVersionError: If ``key_id`` is not in the ring.
    """
    _check_inputs(context, session_uuid)
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    kid = keyring.active_key_id if key_id is None else key_id
    alg_id = keyring.write_alg_id
    # Key ids in a KeyRing are validated to the u16 range, so has_key() also
    # guarantees the value fits the header field.
    aead = _aead(keyring, alg_id, kid, context, session_uuid)
    nonce = _random_nonce()
    header_bytes = _HEADER_STRUCT.pack(FORMAT_VERSION, alg_id, kid, nonce)
    ciphertext = aead.encrypt(nonce, bytes(plaintext), build_aad(header_bytes, context))
    return header_bytes + ciphertext


def open_sealed(
    blob: BytesLike,
    context: VaultContext,
    keyring: KeyRing,
    *,
    session_uuid: Optional[str] = None,
) -> bytes:
    """Decrypt a v2 envelope, requiring the expected ``context``.

    Args:
        blob: Sealed envelope.
        context: Context the caller expects the ciphertext to be bound to.
        keyring: Key ring holding the referenced key version.
        session_uuid: Required for ``layer="session"``, forbidden for ``"db"``.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        TypeError: If ``blob`` is not bytes-like or ``context`` is invalid.
        ValueError: If ``session_uuid`` does not match the context layer.
        UnsupportedFormatError: If the blob is not a valid v2 envelope.
        UnknownKeyVersionError: If the key version is not in the ring.
        VaultIntegrityError: If authentication fails (tampering or wrong context).
    """
    _check_inputs(context, session_uuid)
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise TypeError("blob must be bytes-like")
    data = bytes(blob)
    header = read_header(data)
    aead = _aead(keyring, header.alg_id, header.key_id, context, session_uuid)
    try:
        return aead.decrypt(
            header.nonce, data[HEADER_SIZE:], build_aad(data[:HEADER_SIZE], context)
        )
    except InvalidTag:
        raise VaultIntegrityError(
            "vault envelope authentication failed (tampered data or wrong context)"
        ) from None


def seal_value(
    value: Any,
    context: VaultContext,
    keyring: KeyRing,
    *,
    session_uuid: Optional[str] = None,
    key_id: Optional[int] = None,
) -> bytes:
    """Serialize a Python value and seal it.

    Args:
        value: JSON-representable value or bytes.
        context: Context the ciphertext is bound to.
        keyring: Key ring.
        session_uuid: Required for session-layer contexts.
        key_id: Master key version; defaults to the active key.

    Returns:
        Sealed envelope bytes.
    """
    return seal(
        serialize_value(value), context, keyring, session_uuid=session_uuid, key_id=key_id
    )


def open_value(
    blob: BytesLike,
    context: VaultContext,
    keyring: KeyRing,
    *,
    session_uuid: Optional[str] = None,
) -> Any:
    """Open a sealed envelope and deserialize the value.

    Args:
        blob: Sealed envelope.
        context: Expected context.
        keyring: Key ring.
        session_uuid: Required for session-layer contexts.

    Returns:
        The original Python value.
    """
    return deserialize_value(open_sealed(blob, context, keyring, session_uuid=session_uuid))
