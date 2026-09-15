"""
PostgreSQL protected target base.

Subclasses declare the table layout (primary key, identity columns, encrypted
columns, lifecycle columns) and get, for free:

- keyset pagination over the primary key (``WHERE pk > $1 ORDER BY pk LIMIT $2``),
  never ``OFFSET``;
- context building for rotation/migration;
- transactional writes and quarantine (soft state change + audit hook);
- raw export/restore of stored bytes for backups and rollback.

Pools may expose ``acquire()`` either as an async context manager (asyncpg) or
as an awaitable (asyncdb-style); both are supported, mirroring ``SessionVault``.

Security Note:
    Never log blobs. Row refs contain only the primary key.
"""
import base64
import logging
import re
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Any, AsyncIterator, ClassVar, Mapping, Optional

from ..context import ContextValue, VaultContext
from ..registry import BackupSink, BackupSource, TargetRow, VaultRow

logger = logging.getLogger("navigator.vault")

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def quote_ident(name: str) -> str:
    """Quote a (possibly schema-qualified) SQL identifier.

    Args:
        name: Identifier such as ``"auth.user_vault_secrets"`` or ``"key"``.

    Returns:
        Double-quoted identifier, e.g. ``"auth"."user_vault_secrets"``.

    Raises:
        ValueError: If any part is not a plain identifier.
    """
    parts = name.split(".")
    for part in parts:
        if not _IDENTIFIER.match(part):
            raise ValueError(f"Invalid SQL identifier {name!r}")
    return ".".join(f'"{part}"' for part in parts)


@asynccontextmanager
async def acquire_connection(pool: Any) -> AsyncIterator[Any]:
    """Acquire a connection from asyncpg- or asyncdb-style pools.

    Args:
        pool: Pool whose ``acquire()`` is an async context manager or awaitable.

    Yields:
        A connection exposing ``fetch``/``fetch_all``, ``execute`` and ``transaction``.
    """
    ctx = pool.acquire()
    if hasattr(ctx, "__aenter__"):
        async with ctx as conn:
            yield conn
        return
    conn = await ctx
    try:
        yield conn
    finally:
        if hasattr(pool, "release"):
            await pool.release(conn)
        elif hasattr(conn, "release"):
            await conn.release()
        else:
            await conn.close()


async def fetch_rows(conn: Any, sql: str, *args: Any) -> list[Any]:
    """Run a query and return its rows for asyncpg- or asyncdb-style connections."""
    if hasattr(conn, "fetch_all"):
        rows = await conn.fetch_all(sql, *args)
    else:
        rows = await conn.fetch(sql, *args)
    return list(rows) if rows else []


class PostgresTarget:
    """Base class for vault targets stored in PostgreSQL tables.

    Subclasses must set ``name``, ``table``, ``purpose``, ``identity_columns``
    and ``encrypted_fields`` and may override the ``*_value`` hooks to coerce
    types for contexts and backups.

    Args:
        db_pool: asyncpg-compatible pool.
    """

    name: ClassVar[str]
    table: ClassVar[str]
    purpose: ClassVar[str]
    pk_column: ClassVar[str] = "id"
    identity_columns: ClassVar[tuple[str, ...]] = ()
    encrypted_fields: ClassVar[tuple[str, ...]] = ()
    #: Append ``("field", <encrypted column>)`` to the context (multi-field stores).
    include_field_in_context: ClassVar[bool] = False
    key_version_column: ClassVar[Optional[str]] = "key_version"
    #: Column set to ``NOW()`` on every write (``None`` to disable).
    touch_column: ClassVar[Optional[str]] = "updated_at"
    #: Lifecycle columns exported and restored verbatim.
    state_columns: ClassVar[tuple[str, ...]] = ()
    #: SQL assignment fragment applied by :meth:`quarantine` (no parameters).
    quarantine_assignments: ClassVar[str] = ""

    def __init__(self, db_pool: Any) -> None:
        if not self.identity_columns or not self.encrypted_fields:
            raise ValueError(f"{type(self).__name__} must declare identity and encrypted columns")
        if not self.quarantine_assignments:
            raise ValueError(f"{type(self).__name__} must declare quarantine_assignments")
        columns = (
            self.pk_column, *self.identity_columns, *self.encrypted_fields,
            *self.state_columns,
            *((self.key_version_column,) if self.key_version_column else ()),
            *((self.touch_column,) if self.touch_column else ()),
        )
        for column in columns:
            quote_ident(column)
        self._table_sql = quote_ident(self.table)
        self._pool = db_pool
        self._conn: ContextVar[Optional[Any]] = ContextVar(
            f"vault_target_conn_{self.name}", default=None
        )
        select_columns = [self.pk_column, *self.identity_columns, *self.encrypted_fields]
        if self.key_version_column:
            select_columns.append(self.key_version_column)
        select_columns.extend(self.state_columns)
        self._select_sql = ", ".join(quote_ident(c) for c in select_columns)
        pk = quote_ident(self.pk_column)
        self._first_batch_sql = (
            f"SELECT {self._select_sql} FROM {self._table_sql} ORDER BY {pk} LIMIT $1"
        )
        self._next_batch_sql = (
            f"SELECT {self._select_sql} FROM {self._table_sql} "
            f"WHERE {pk} > $1 ORDER BY {pk} LIMIT $2"
        )

    # ------------------------------------------------------------------
    # Hooks
    # ------------------------------------------------------------------

    def context_value(self, column: str, value: Any) -> ContextValue:
        """Coerce an identity column value for the context (override per table)."""
        return value

    def pk_from_json(self, value: Any) -> Any:
        """Convert a backup primary key back to its database type."""
        return value

    def state_from_json(self, column: str, value: Any) -> Any:
        """Convert a backup lifecycle value back to its database type."""
        return value

    async def audit_quarantine(
        self, conn: Any, row: VaultRow, reason: str, run_id: str
    ) -> None:
        """Write an audit record for a quarantined row (no-op by default)."""

    # ------------------------------------------------------------------
    # ProtectedTarget API
    # ------------------------------------------------------------------

    def ref_for(self, pk: Any) -> str:
        """Printable, secret-free row reference."""
        return f"{self.name}:{self.pk_column}={pk}"

    def context_for(self, row: TargetRow, field: str) -> VaultContext:
        """Build the db-layer context for ``field`` of ``row``.

        Raises:
            ValueError: If ``field`` is not an encrypted field of this target.
        """
        if field not in self.encrypted_fields:
            raise ValueError(f"{field!r} is not an encrypted field of {self.name}")
        identity = row.identity  # type: ignore[attr-defined]
        fields: list[tuple[str, ContextValue]] = [
            (column, self.context_value(column, identity[column]))
            for column in self.identity_columns
        ]
        if self.include_field_in_context:
            fields.append(("field", field))
        return VaultContext(purpose=self.purpose, layer="db", fields=tuple(fields))

    async def iter_batches(self, batch_size: int) -> AsyncIterator[list[TargetRow]]:
        """Iterate every row (soft-deleted included) ordered by primary key.

        The connection is released before each batch is yielded, so callers may
        write while iterating even with a single-connection pool.
        """
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        last_pk: Any = None
        while True:
            async with self._connection() as conn:
                if last_pk is None:
                    records = await fetch_rows(conn, self._first_batch_sql, batch_size)
                else:
                    records = await fetch_rows(conn, self._next_batch_sql, last_pk, batch_size)
            if not records:
                return
            rows = [self._row_from_record(record) for record in records]
            yield rows
            if len(rows) < batch_size:
                return
            last_pk = rows[-1].pk

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[Any]:
        """Run writes/quarantines on one connection inside a transaction.

        Nested calls reuse the outer transaction.
        """
        current = self._conn.get()
        if current is not None:
            yield current
            return
        async with acquire_connection(self._pool) as conn:
            tx = conn.transaction()
            await tx.start()
            token = self._conn.set(conn)
            try:
                yield conn
            except BaseException:
                await tx.rollback()
                raise
            else:
                await tx.commit()
            finally:
                self._conn.reset(token)

    async def write(
        self, row: TargetRow, blobs: Mapping[str, Optional[bytes]], key_version: int
    ) -> None:
        """Replace stored blobs and the key version of ``row``.

        Raises:
            ValueError: If ``blobs`` is empty or names unknown fields.
            LookupError: If the row no longer exists.
        """
        if not blobs:
            raise ValueError("blobs must not be empty")
        unknown = set(blobs) - set(self.encrypted_fields)
        if unknown:
            raise ValueError(f"unknown encrypted fields for {self.name}: {sorted(unknown)}")
        assignments: list[str] = []
        args: list[Any] = []
        for column, blob in blobs.items():
            args.append(None if blob is None else bytes(blob))
            assignments.append(f"{quote_ident(column)} = ${len(args)}")
        if self.key_version_column:
            args.append(key_version)
            assignments.append(f"{quote_ident(self.key_version_column)} = ${len(args)}")
        if self.touch_column:
            assignments.append(f"{quote_ident(self.touch_column)} = NOW()")
        args.append(row.pk)  # type: ignore[attr-defined]
        sql = (
            f"UPDATE {self._table_sql} SET {', '.join(assignments)} "
            f"WHERE {quote_ident(self.pk_column)} = ${len(args)}"
        )
        async with self._connection() as conn:
            self._check_updated(await conn.execute(sql, *args), row.ref)

    async def quarantine(self, row: TargetRow, reason: str, run_id: str) -> None:
        """Apply ``quarantine_assignments`` and audit, without touching blobs.

        Args:
            row: Row to quarantine.
            reason: Secret-free reason (e.g. an error class name).
            run_id: Migration run identifier.
        """
        sql = (
            f"UPDATE {self._table_sql} SET {self.quarantine_assignments} "
            f"WHERE {quote_ident(self.pk_column)} = $1"
        )
        async with self.transaction() as conn:
            self._check_updated(await conn.execute(sql, row.pk), row.ref)  # type: ignore[attr-defined]
            await self.audit_quarantine(conn, row, reason, run_id)  # type: ignore[arg-type]
        logger.warning(
            "Vault target %s quarantined %s (run %s): %s", self.name, row.ref, run_id, reason
        )

    async def export_raw(self, sink: BackupSink) -> int:
        """Export every row as stored (blobs base64, lifecycle columns verbatim)."""
        count = 0
        async for batch in self.iter_batches(500):
            for row in batch:
                await sink.write(self.name, self.to_backup_record(row))  # type: ignore[arg-type]
                count += 1
        return count

    async def restore_raw(self, source: BackupSource) -> int:
        """Restore stored bytes, key version and lifecycle columns in one transaction.

        Raises:
            LookupError: If a backed-up row no longer exists.
        """
        count = 0
        async with self.transaction() as conn:
            async for record in source.read(self.name):
                assignments: list[str] = []
                args: list[Any] = []
                values = record["values"]
                for column in self.encrypted_fields:
                    encoded = values.get(column)
                    args.append(None if encoded is None else base64.b64decode(encoded))
                    assignments.append(f"{quote_ident(column)} = ${len(args)}")
                if self.key_version_column:
                    args.append(record.get("key_version"))
                    assignments.append(f"{quote_ident(self.key_version_column)} = ${len(args)}")
                state = record.get("state", {})
                for column in self.state_columns:
                    args.append(self.state_from_json(column, state.get(column)))
                    assignments.append(f"{quote_ident(column)} = ${len(args)}")
                pk = self.pk_from_json(record["pk"])
                args.append(pk)
                sql = (
                    f"UPDATE {self._table_sql} SET {', '.join(assignments)} "
                    f"WHERE {quote_ident(self.pk_column)} = ${len(args)}"
                )
                self._check_updated(await conn.execute(sql, *args), self.ref_for(pk))
                count += 1
        return count

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def to_backup_record(self, row: VaultRow) -> dict[str, Any]:
        """Serialize a row for backup (JSON-safe, no plaintext)."""
        return {
            "ref": row.ref,
            "pk": _jsonable(row.pk),
            "identity": {k: _jsonable(v) for k, v in row.identity.items()},
            "values": {
                k: None if v is None else base64.b64encode(v).decode("ascii")
                for k, v in row.values.items()
            },
            "key_version": row.key_version,
            "state": {k: _jsonable(v) for k, v in row.state.items()},
        }

    def _row_from_record(self, record: Any) -> VaultRow:
        pk = record[self.pk_column]
        values: dict[str, Optional[bytes]] = {}
        for column in self.encrypted_fields:
            blob = record[column]
            values[column] = None if blob is None else bytes(blob)
        return VaultRow(
            ref=self.ref_for(pk),
            pk=pk,
            identity={column: record[column] for column in self.identity_columns},
            values=values,
            key_version=record[self.key_version_column] if self.key_version_column else None,
            state={column: record[column] for column in self.state_columns},
        )

    @asynccontextmanager
    async def _connection(self) -> AsyncIterator[Any]:
        current = self._conn.get()
        if current is not None:
            yield current
            return
        async with acquire_connection(self._pool) as conn:
            yield conn

    @staticmethod
    def _check_updated(status: Any, ref: str) -> None:
        # asyncpg returns a command tag such as "UPDATE 1"; other drivers may not.
        if isinstance(status, str) and status.split()[-1:] == ["0"]:
            raise LookupError(f"{ref} not found")


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)
