"""
Protected target for ``auth.user_vault_secrets`` (Session Vault database layer).

Context: ``purpose="user-vault"``, ``layer="db"``, fields ``(user_id, key)``.
Soft-deleted rows are included in iteration so no v1 data stays at rest.

Quarantine keeps the blob untouched, soft-deletes the row (preserving an
existing ``deleted_at``) and writes an ``operation='quarantine'`` audit row whose
``session_id`` column carries ``run:<run_id>``.
"""
import re
from datetime import datetime
from typing import Any, Mapping, Optional
from uuid import UUID

from ..context import ContextValue
from ..registry import VaultRow
from .postgres import PostgresTarget

_RUN_ID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

_INSERT_QUARANTINE_AUDIT = """
INSERT INTO auth.user_vault_audit (user_id, key, operation, key_version, session_id)
VALUES ($1, $2, 'quarantine', $3, $4)
"""


class UserVaultTarget(PostgresTarget):
    """``auth.user_vault_secrets`` rows sealed by ``SessionVault``."""

    name = "auth.user_vault_secrets"
    table = "auth.user_vault_secrets"
    purpose = "user-vault"
    pk_column = "id"
    identity_columns = ("user_id", "key")
    encrypted_fields = ("ciphertext_db",)
    include_field_in_context = False
    key_version_column = "key_version"
    touch_column = "updated_at"
    state_columns = ("deleted_at", "updated_at")
    quarantine_assignments = "deleted_at = COALESCE(deleted_at, NOW())"

    def context_value(self, column: str, value: Any) -> ContextValue:
        """``user_id`` is INTEGER, ``key`` is VARCHAR."""
        if column == "user_id":
            return int(value)
        return str(value)

    def pk_from_json(self, value: Any) -> Any:
        """Primary key is a UUID."""
        return value if isinstance(value, UUID) else UUID(str(value))

    def state_from_json(self, column: str, value: Any) -> Any:
        """Lifecycle columns are TIMESTAMPTZ."""
        if value is None or isinstance(value, datetime):
            return value
        return datetime.fromisoformat(value)

    async def audit_quarantine(
        self, conn: Any, row: VaultRow, reason: str, run_id: str
    ) -> None:
        """Record the quarantine in ``auth.user_vault_audit``.

        Raises:
            ValueError: If ``run_id`` is not 1-32 characters of ``[A-Za-z0-9_-]``.
        """
        if not _RUN_ID.match(run_id):
            raise ValueError("run_id must be 1-32 characters of [A-Za-z0-9_-]")
        await conn.execute(
            _INSERT_QUARANTINE_AUDIT,
            int(row.identity["user_id"]),
            str(row.identity["key"]),
            row.key_version,
            f"run:{run_id}",
        )


def factory(resources: Mapping[str, Any]) -> Optional[UserVaultTarget]:
    """Entry-point factory: requires ``db_pool`` (navigator-auth ``authdb``).

    Args:
        resources: Shared handles; ``db_pool`` must be an asyncpg-compatible pool.

    Returns:
        Target, or ``None`` when no database pool is configured.
    """
    pool = resources.get("db_pool")
    if pool is None:
        return None
    return UserVaultTarget(pool)
