"""
Vault Key Rotation — Re-seal every protected target under a new master key.

Rotation walks each :class:`~navigator_session.vault.registry.ProtectedTarget`
(user vault, identity credentials, ai-parrot stores, ...) in keyset-paginated
batches. For every row that has at least one field sealed with ``old_key_id``,
all non-NULL fields not already on ``new_key_id`` are opened with the target's
context and re-sealed under ``new_key_id``; the row is written once. Each batch
runs in its own transaction.

The operation is idempotent: rows without fields on ``old_key_id`` are counted as
``skipped``. Rows that cannot be opened (tampered, wrong context, legacy v1,
missing key version) are left untouched, counted as ``errors`` and reported by
reference so operators can investigate or quarantine them.

Security Note:
    Plaintext exists in memory only while a row is re-sealed.
    Never log plaintext or ciphertext values.
"""
import logging
from typing import Any, Optional

from .envelope import (
    UnknownKeyVersionError,
    VaultCryptoError,
    open_sealed,
    read_header,
    seal,
)
from .keyring import KeyRing
from .registry import ProtectedTarget

logger = logging.getLogger("navigator.vault")


def _new_stats() -> dict[str, Any]:
    return {"total": 0, "rotated": 0, "skipped": 0, "errors": 0, "failed_refs": []}


async def rotate_master_key(
    targets: list[ProtectedTarget],
    old_key_id: int,
    new_key_id: int,
    keyring: KeyRing,
    batch_size: int = 100,
) -> dict[str, dict[str, Any]]:
    """Re-seal all target rows from ``old_key_id`` to ``new_key_id``.

    Args:
        targets: Protected targets to rotate (see ``discover_targets``).
        old_key_id: Master key version being retired.
        new_key_id: Master key version to re-seal with.
        keyring: Key ring holding both versions (and any other version still
            present in rows being rotated).
        batch_size: Rows per batch/transaction.

    Returns:
        Mapping of target name to stats: ``total``, ``rotated``, ``skipped``,
        ``errors`` and ``failed_refs`` (secret-free row references).

    Raises:
        UnknownKeyVersionError: If either key version is not in the ring
            (raised before any data is read).
        ValueError: If both versions are equal or ``batch_size`` < 1.
    """
    for key_id in (old_key_id, new_key_id):
        if not keyring.has_key(key_id):
            raise UnknownKeyVersionError(
                f"master key version {key_id} not found in key ring"
            )
    if old_key_id == new_key_id:
        raise ValueError("old_key_id and new_key_id must differ")
    if batch_size < 1:
        raise ValueError("batch_size must be >= 1")

    logger.info(
        "Starting key rotation from v%d to v%d over %d target(s) (batch_size=%d)",
        old_key_id, new_key_id, len(targets), batch_size,
    )
    results: dict[str, dict[str, Any]] = {}
    for target in targets:
        stats = _new_stats()
        results[target.name] = stats
        batch_num = 0
        async for batch in target.iter_batches(batch_size):
            batch_num += 1
            async with target.transaction():
                for row in batch:
                    stats["total"] += 1
                    await _rotate_row(target, row, old_key_id, new_key_id, keyring, stats)
            logger.debug(
                "Key rotation %s: batch %d processed (%d rows)",
                target.name, batch_num, len(batch),
            )
        logger.info(
            "Key rotation %s complete: total=%d rotated=%d skipped=%d errors=%d",
            target.name, stats["total"], stats["rotated"], stats["skipped"], stats["errors"],
        )
    return results


async def _rotate_row(
    target: ProtectedTarget,
    row: Any,
    old_key_id: int,
    new_key_id: int,
    keyring: KeyRing,
    stats: dict[str, Any],
) -> None:
    """Rotate one row, updating ``stats`` in place."""
    present = {f: blob for f, blob in row.values.items() if blob is not None}
    try:
        headers = {f: read_header(blob) for f, blob in present.items()}
    except VaultCryptoError as err:
        _record_error(target, row, err, stats)
        return
    if not any(h.key_id == old_key_id for h in headers.values()):
        stats["skipped"] += 1
        return

    new_blobs: dict[str, Optional[bytes]] = {}
    try:
        for field, blob in present.items():
            if headers[field].key_id == new_key_id:
                continue
            context = target.context_for(row, field)
            plaintext = open_sealed(blob, context, keyring)
            new_blobs[field] = seal(plaintext, context, keyring, key_id=new_key_id)
    except VaultCryptoError as err:
        _record_error(target, row, err, stats)
        return

    try:
        await target.write(row, new_blobs, new_key_id)
    except LookupError as err:  # row vanished between read and write
        _record_error(target, row, err, stats)
        return
    record_rotation = getattr(target, "record_rotation", None)
    if record_rotation is not None:
        await record_rotation(row, new_key_id)
    stats["rotated"] += 1


def _record_error(
    target: ProtectedTarget, row: Any, err: Exception, stats: dict[str, Any]
) -> None:
    stats["errors"] += 1
    stats["failed_refs"].append(row.ref)
    logger.error(
        "Key rotation %s: cannot rotate %s: %s", target.name, row.ref, type(err).__name__
    )
