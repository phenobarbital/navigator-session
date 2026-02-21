"""
Vault Key Rotation — Batch re-encryption of secrets when rotating master keys.

Re-encrypts all vault secrets from one key version to another in configurable
batches. Each batch runs in its own transaction for resumability. The operation
is idempotent: secrets already at the target key version are skipped by the
query filter.

Security Note:
    Plaintext exists in memory only during re-encryption of each row.
    Never log plaintext or ciphertext values.
"""
import logging
from typing import Any

from .crypto import decrypt_for_db, encrypt_for_db

logger = logging.getLogger("navigator.vault")

# SQL statements
_SELECT_BATCH = """
SELECT id, user_id, key, ciphertext_db, key_version
FROM auth.user_vault_secrets
WHERE key_version = $1 AND deleted_at IS NULL
ORDER BY id
LIMIT $2
OFFSET $3
"""

_UPDATE_SECRET = """
UPDATE auth.user_vault_secrets
SET ciphertext_db = $1, key_version = $2, updated_at = NOW()
WHERE id = $3
"""

_INSERT_AUDIT = """
INSERT INTO auth.user_vault_audit (user_id, key, operation, key_version, session_id)
VALUES ($1, $2, $3, $4, $5)
"""


async def rotate_master_key(
    db_pool: Any,
    old_key_id: int,
    new_key_id: int,
    master_keys: dict[int, bytes],
    batch_size: int = 100,
) -> dict:
    """Re-encrypt all secrets from old_key_id to new_key_id in batches.

    Args:
        db_pool: asyncpg-compatible connection pool.
        old_key_id: Source key version to rotate from.
        new_key_id: Target key version to rotate to.
        master_keys: Mapping of all key versions to raw 32-byte keys.
        batch_size: Number of rows to process per batch/transaction.

    Returns:
        Stats dict with keys: total, rotated, errors, skipped.

    Raises:
        KeyError: If old_key_id or new_key_id is not in master_keys.
    """
    if old_key_id not in master_keys:
        raise KeyError(
            f"Old key version {old_key_id} not found in master_keys"
        )
    if new_key_id not in master_keys:
        raise KeyError(
            f"New key version {new_key_id} not found in master_keys"
        )

    new_master_key = master_keys[new_key_id]
    stats = {"total": 0, "rotated": 0, "errors": 0, "skipped": 0}
    offset = 0

    logger.info(
        "Starting key rotation from v%d to v%d (batch_size=%d)",
        old_key_id, new_key_id, batch_size,
    )

    while True:
        async with db_pool.acquire() as conn:
            rows = await conn.fetch(
                _SELECT_BATCH, old_key_id, batch_size, offset,
            )

        if not rows:
            break

        batch_num = (offset // batch_size) + 1
        logger.info(
            "Processing batch %d (%d rows)", batch_num, len(rows),
        )

        async with db_pool.acquire() as conn:
            tx = conn.transaction()
            await tx.start()
            try:
                for row in rows:
                    stats["total"] += 1
                    row_id = row["id"]
                    user_id = row["user_id"]
                    key_name = row["key"]
                    ciphertext_db = row["ciphertext_db"]

                    try:
                        plaintext = decrypt_for_db(ciphertext_db, master_keys)
                        new_ct = encrypt_for_db(
                            plaintext, new_key_id, new_master_key,
                        )

                        await conn.execute(
                            _UPDATE_SECRET, new_ct, new_key_id, row_id,
                        )
                        await conn.execute(
                            _INSERT_AUDIT,
                            user_id, key_name, "rotate", new_key_id, None,
                        )
                        stats["rotated"] += 1
                    except Exception as err:
                        logger.error(
                            "Error rotating secret id=%s key=%s: %s",
                            row_id, key_name, err,
                        )
                        stats["errors"] += 1

                await tx.commit()
            except Exception:
                await tx.rollback()
                raise

        offset += len(rows)

    logger.info(
        "Key rotation complete: %s", stats,
    )
    return stats
