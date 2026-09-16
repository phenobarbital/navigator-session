"""
Vault Context — the identity a ciphertext is bound to.

A :class:`VaultContext` describes *where* a secret lives: its purpose
(e.g. ``"user-vault"``, ``"identity"``), its layer (``"db"`` or
``"session"``) and an ordered tuple of identity fields (e.g. ``user_id``,
``key``). Its canonical encoding becomes part of the AEAD associated data,
so a ciphertext only opens with the exact context it was sealed with.

Canonical encoding (after the ``"NAVVAULT-AAD" ‖ header`` prefix added by
the envelope)::

    lp(purpose) ‖ lp(layer) ‖ u16(field_count)
    ‖ for each (name, value): lp(name) ‖ type_tag(1B) ‖ lp(encoded_value)

    type_tag: 0x00 NULL (empty value) · 0x01 str (UTF-8)
              0x02 int (decimal ASCII) · 0x03 UUID (canonical lowercase)

Values are typed: ``1`` (int), ``"1"`` (str) and a ``UUID`` versus its string
form all encode differently. Callers must use the same Python type on seal
and open.
"""
import re
import struct
from typing import Any, Literal, Optional, Union
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator

from .keyring import lp

ContextValue = Union[str, int, UUID, None]

TAG_NULL = 0x00
TAG_STR = 0x01
TAG_INT = 0x02
TAG_UUID = 0x03

MAX_FIELDS = 0xFFFF

_PURPOSE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_FIELD_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _encode_value(value: ContextValue) -> tuple[int, bytes]:
    """Return the type tag and canonical bytes for a context value."""
    if value is None:
        return TAG_NULL, b""
    if isinstance(value, bool):  # bool is an int subclass; reject explicitly
        raise ValueError("bool is not a valid context value")
    if isinstance(value, int):
        return TAG_INT, str(value).encode("ascii")
    if isinstance(value, str):
        return TAG_STR, value.encode("utf-8")
    if isinstance(value, UUID):
        return TAG_UUID, str(value).encode("ascii")
    raise ValueError(
        f"Unsupported context value type {type(value).__name__}; "
        "expected str, int, UUID or None"
    )


class VaultContext(BaseModel):
    """Identity a vault ciphertext is bound to (AEAD associated data).

    Attributes:
        purpose: Store/purpose name, e.g. ``"user-vault"`` or ``"identity"``.
            Lowercase letters, digits, ``.``, ``_`` and ``-``; max 64 chars.
        layer: ``"db"`` for persistent storage, ``"session"`` for the
            session cache layer.
        fields: Ordered ``(name, value)`` pairs identifying the row and field.
            Order is significant and fixed per protected target.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    purpose: str
    layer: Literal["db", "session"]
    fields: tuple[tuple[str, Any], ...]

    @field_validator("purpose")
    @classmethod
    def _validate_purpose(cls, value: str) -> str:
        if not _PURPOSE_PATTERN.match(value):
            raise ValueError(
                "purpose must match [a-z0-9][a-z0-9._-]{0,63}"
            )
        return value

    @field_validator("fields", mode="before")
    @classmethod
    def _validate_fields(cls, value: Any) -> tuple[tuple[str, ContextValue], ...]:
        if not isinstance(value, (tuple, list)):
            raise ValueError("fields must be a tuple of (name, value) pairs")
        if len(value) > MAX_FIELDS:
            raise ValueError(f"at most {MAX_FIELDS} context fields are allowed")
        normalized: list[tuple[str, ContextValue]] = []
        seen: set[str] = set()
        for pair in value:
            if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                raise ValueError("each context field must be a (name, value) pair")
            name, item = pair
            if not isinstance(name, str) or not _FIELD_NAME_PATTERN.match(name):
                raise ValueError(f"invalid context field name {name!r}")
            if name in seen:
                raise ValueError(f"duplicate context field name {name!r}")
            seen.add(name)
            _encode_value(item)  # type check
            normalized.append((name, item))
        return tuple(normalized)

    def get(self, name: str, default: Optional[ContextValue] = None) -> ContextValue:
        """Return the value of a context field.

        Args:
            name: Field name.
            default: Value returned when the field is absent.

        Returns:
            The field value, or ``default``.
        """
        for field_name, value in self.fields:
            if field_name == name:
                return value
        return default

    def canonical_bytes(self) -> bytes:
        """Encode the context canonically for use as AEAD associated data.

        Returns:
            Length-prefixed, typed encoding of purpose, layer and fields.
        """
        parts = [lp(self.purpose), lp(self.layer), struct.pack("!H", len(self.fields))]
        for name, value in self.fields:
            tag, encoded = _encode_value(value)
            parts.append(lp(name) + bytes([tag]) + lp(encoded))
        return b"".join(parts)
