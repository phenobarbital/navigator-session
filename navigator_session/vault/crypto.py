"""
Vault value serialization.

Converts Python values to bytes before sealing and back after opening.
Encryption lives in :mod:`navigator_session.vault.envelope` (envelope v2);
the pre-1.0 ``encrypt_for_*`` / ``decrypt_for_*`` functions were removed
in FEAT-099.

Security Note:
    Never log plaintext values.
"""
import base64
from typing import Any

import orjson

_BYTES_WRAPPER_KEY = "__vault_bytes_b64__"


def serialize_value(value: Any) -> bytes:
    """Serialize a Python value to bytes for encryption.

    Supports: str, int, float, dict, list, bytes, bool, None.
    bytes values are wrapped as {"__vault_bytes_b64__": "<base64>"} for a safe
    JSON round-trip.

    Args:
        value: Python value to serialize.

    Returns:
        orjson-encoded bytes.
    """
    if isinstance(value, bytes):
        wrapped = {_BYTES_WRAPPER_KEY: base64.b64encode(value).decode("ascii")}
        return orjson.dumps(wrapped)
    return orjson.dumps(value)


def deserialize_value(data: bytes) -> Any:
    """Deserialize bytes back to a Python value.

    Args:
        data: orjson-encoded bytes from serialize_value.

    Returns:
        Original Python value.
    """
    parsed = orjson.loads(data)
    if isinstance(parsed, dict) and _BYTES_WRAPPER_KEY in parsed and len(parsed) == 1:
        return base64.b64decode(parsed[_BYTES_WRAPPER_KEY])
    return parsed
