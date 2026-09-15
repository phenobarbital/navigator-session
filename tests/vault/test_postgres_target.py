"""Tests for the PostgreSQL target base and UserVaultTarget (FEAT-099, TASK-072)."""
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from navigator_session.vault import VaultIntegrityError, open_sealed, seal
from navigator_session.vault.registry import VaultRow
from navigator_session.vault.targets.postgres import PostgresTarget, quote_ident
from navigator_session.vault.targets.user_vault import UserVaultTarget

from .fake_pg import AwaitablePool, FakeDatabase, FakePool

TABLE = "auth.user_vault_secrets"
AUDIT = "auth.user_vault_audit"
BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def seed(db: FakeDatabase, count: int, deleted_every: int = 0) -> list[dict[str, Any]]:
    rows = []
    for i in range(count):
        rows.append({
            "id": uuid.uuid4(),
            "user_id": 1 + i % 7,
            "key": f"key-{i}",
            "ciphertext_db": os.urandom(40),
            "key_version": 1,
            "created_at": BASE_TIME,
            "updated_at": BASE_TIME + timedelta(seconds=i),
            "deleted_at": BASE_TIME if deleted_every and i % deleted_every == 0 else None,
        })
    db.table(TABLE).extend(rows)
    return rows


class MemorySink:
    def __init__(self):
        self.records: dict[str, list[dict[str, Any]]] = {}

    async def write(self, target, record):
        json.dumps(record)  # must be JSON-serializable
        self.records.setdefault(target, []).append(record)

    async def read(self, target):
        for record in self.records.get(target, []):
            yield record


@pytest.fixture
def db():
    return FakeDatabase()


@pytest.fixture
def target(db):
    return UserVaultTarget(FakePool(db, max_size=1))


async def collect(target, batch_size):
    return [batch async for batch in target.iter_batches(batch_size)]


class TestConfiguration:
    def test_quote_ident(self):
        assert quote_ident("auth.user_vault_secrets") == '"auth"."user_vault_secrets"'
        for bad in ("auth.users; DROP", 'a"b', "", "1col", "a..b"):
            with pytest.raises(ValueError):
                quote_ident(bad)

    def test_invalid_subclass_rejected(self, db):
        class NoColumns(PostgresTarget):
            name = table = "x.y"
            purpose = "p"
            quarantine_assignments = "enabled = false"

        class BadColumn(UserVaultTarget):
            identity_columns = ("user_id; --",)

        with pytest.raises(ValueError):
            NoColumns(FakePool(db))
        with pytest.raises(ValueError):
            BadColumn(FakePool(db))

    def test_context_for(self, target):
        row = VaultRow(ref="r", pk=uuid.uuid4(), identity={"user_id": "42", "key": 7}, values={})
        ctx = target.context_for(row, "ciphertext_db")
        assert ctx.purpose == "user-vault" and ctx.layer == "db"
        assert ctx.fields == (("user_id", 42), ("key", "7"))
        with pytest.raises(ValueError):
            target.context_for(row, "other")


@pytest.mark.asyncio
class TestIteration:
    async def test_visits_every_row_once_including_soft_deleted(self, db, target):
        rows = seed(db, 250, deleted_every=10)
        batches = await collect(target, 100)
        assert [len(b) for b in batches] == [100, 100, 50]
        refs = [r.ref for b in batches for r in b]
        assert len(refs) == len(set(refs)) == 250
        assert sum(1 for b in batches for r in b if r.state["deleted_at"]) == 25
        assert {r.pk for b in batches for r in b} == {r["id"] for r in rows}

    async def test_uses_keyset_pagination(self, db, target):
        seed(db, 5)
        await collect(target, 2)
        selects = [s for s in db.statements if s.startswith("SELECT")]
        assert "OFFSET" not in " ".join(selects)
        assert "WHERE id > $1" in selects[1]

    async def test_exact_multiple_and_empty(self, db, target):
        assert await collect(target, 10) == []
        seed(db, 4)
        assert [len(b) for b in await collect(target, 2)] == [2, 2]

    async def test_row_shape_has_no_secret_in_ref(self, db, target):
        rows = seed(db, 1)
        [[row]] = await collect(target, 10)
        assert row.values["ciphertext_db"] == rows[0]["ciphertext_db"]
        assert row.ref == f"{TABLE}:id={rows[0]['id']}"
        assert rows[0]["ciphertext_db"].hex() not in row.ref
        assert row.key_version == 1 and row.identity == {"user_id": 1, "key": "key-0"}

    async def test_can_write_while_iterating_single_connection_pool(self, db, target):
        seed(db, 5)
        async for batch in target.iter_batches(2):
            for row in batch:
                await target.write(row, {"ciphertext_db": b"new"}, 2)
        assert all(r["ciphertext_db"] == b"new" and r["key_version"] == 2 for r in db.table(TABLE))

    async def test_batch_size_validation(self, target):
        with pytest.raises(ValueError):
            await collect(target, 0)


@pytest.mark.asyncio
class TestWrites:
    async def test_write_updates_blob_version_and_touch(self, db, target):
        seed(db, 1)  # updated_at == BASE_TIME
        [[row]] = await collect(target, 10)
        await target.write(row, {"ciphertext_db": bytearray(b"v2-blob")}, 3)
        stored = db.table(TABLE)[0]
        assert stored["ciphertext_db"] == b"v2-blob" and stored["key_version"] == 3
        assert stored["updated_at"] > BASE_TIME

    async def test_write_validation(self, db, target):
        seed(db, 1)
        [[row]] = await collect(target, 10)
        with pytest.raises(ValueError):
            await target.write(row, {}, 1)
        with pytest.raises(ValueError):
            await target.write(row, {"key": b"x"}, 1)

    async def test_write_missing_row(self, target):
        ghost = VaultRow(ref="ghost", pk=uuid.uuid4(), identity={}, values={})
        with pytest.raises(LookupError, match="ghost not found"):
            await target.write(ghost, {"ciphertext_db": b"x"}, 1)

    async def test_transaction_commit(self, db, target):
        seed(db, 3)
        [rows] = await collect(target, 10)
        async with target.transaction():
            for row in rows:
                await target.write(row, {"ciphertext_db": b"committed"}, 2)
        assert all(r["ciphertext_db"] == b"committed" for r in db.table(TABLE))

    async def test_transaction_rollback(self, db, target):
        original = [r["ciphertext_db"] for r in seed(db, 3)]
        [rows] = await collect(target, 10)
        with pytest.raises(RuntimeError):
            async with target.transaction():
                await target.write(rows[0], {"ciphertext_db": b"lost"}, 2)
                async with target.transaction():  # nested reuses outer
                    await target.write(rows[1], {"ciphertext_db": b"lost"}, 2)
                raise RuntimeError("abort batch")
        assert [r["ciphertext_db"] for r in db.table(TABLE)] == original

    async def test_awaitable_pool(self, db):
        seed(db, 3)
        pool = AwaitablePool(db)
        target = UserVaultTarget(pool)
        [rows] = await collect(target, 10)
        await target.write(rows[0], {"ciphertext_db": b"x"}, 2)
        async with target.transaction():
            await target.write(rows[1], {"ciphertext_db": b"y"}, 2)
        assert pool.released == 3

    async def test_sealed_blob_roundtrip_with_target_context(self, db, target, keyring):
        seed(db, 2)
        [rows] = await collect(target, 10)
        for row in rows:
            blob = seal(b"secret", target.context_for(row, "ciphertext_db"), keyring)
            await target.write(row, {"ciphertext_db": blob}, keyring.active_key_id)
        [reread] = await collect(target, 10)
        assert open_sealed(
            reread[0].values["ciphertext_db"], target.context_for(reread[0], "ciphertext_db"), keyring
        ) == b"secret"
        # Swapping blobs between two users' rows is detected.
        with pytest.raises(VaultIntegrityError):
            open_sealed(
                reread[1].values["ciphertext_db"], target.context_for(reread[0], "ciphertext_db"), keyring
            )


@pytest.mark.asyncio
class TestQuarantine:
    async def test_soft_deletes_audits_and_keeps_blob(self, db, target):
        rows = seed(db, 2)
        [batch] = await collect(target, 10)
        await target.quarantine(batch[0], "VaultIntegrityError", run_id="run-2026")
        stored = next(r for r in db.table(TABLE) if r["id"] == batch[0].pk)
        assert stored["deleted_at"] is not None
        assert stored["ciphertext_db"] == next(r for r in rows if r["id"] == batch[0].pk)["ciphertext_db"]
        [audit] = db.table(AUDIT)
        assert audit == {
            "user_id": batch[0].identity["user_id"], "key": batch[0].identity["key"],
            "operation": "quarantine", "key_version": 1, "session_id": "run:run-2026",
        }

    async def test_preserves_existing_deleted_at(self, db, target):
        seed(db, 1, deleted_every=1)
        [[row]] = await collect(target, 10)
        await target.quarantine(row, "UnsupportedFormatError", run_id="r1")
        assert db.table(TABLE)[0]["deleted_at"] == BASE_TIME

    @pytest.mark.parametrize("run_id", ["", "x" * 33, "run id", "run;drop"])
    async def test_invalid_run_id_rolls_back(self, db, target, run_id):
        seed(db, 1)
        [[row]] = await collect(target, 10)
        with pytest.raises(ValueError):
            await target.quarantine(row, "reason", run_id=run_id)
        assert db.table(TABLE)[0]["deleted_at"] is None
        assert db.table(AUDIT) == []

    async def test_missing_row(self, target):
        ghost = VaultRow(ref="ghost", pk=uuid.uuid4(), identity={"user_id": 1, "key": "k"}, values={})
        with pytest.raises(LookupError):
            await target.quarantine(ghost, "reason", run_id="r1")


@pytest.mark.asyncio
class TestExportRestore:
    async def test_roundtrip_is_byte_identical(self, db, target):
        seed(db, 120, deleted_every=9)
        before = json.loads(json.dumps(db.table(TABLE), default=str))
        sink = MemorySink()
        assert await target.export_raw(sink) == 120

        # Simulate a migration: rewrite every blob and quarantine a row.
        async for batch in target.iter_batches(50):
            for row in batch:
                await target.write(row, {"ciphertext_db": b"\xa2migrated"}, 2)
        [[first]] = [b[:1] for b in await collect(target, 1)][:1]
        await target.quarantine(first, "VaultIntegrityError", run_id="r1")

        assert await target.restore_raw(sink) == 120
        after = json.loads(json.dumps(db.table(TABLE), default=str))
        assert after == before
        restored = db.table(TABLE)[0]
        assert isinstance(restored["id"], uuid.UUID) and isinstance(restored["updated_at"], datetime)

    async def test_backup_records_have_no_plaintext_shape(self, db, target):
        rows = seed(db, 1)
        sink = MemorySink()
        await target.export_raw(sink)
        [record] = sink.records[TABLE]
        assert set(record) == {"ref", "pk", "identity", "values", "key_version", "state"}
        assert record["pk"] == str(rows[0]["id"])
        assert record["state"]["updated_at"] == rows[0]["updated_at"].isoformat()

    async def test_restore_missing_row_rolls_back(self, db, target):
        seed(db, 2)
        sink = MemorySink()
        await target.export_raw(sink)
        sink.records[TABLE][1]["pk"] = str(uuid.uuid4())
        async for batch in target.iter_batches(10):
            for row in batch:
                await target.write(row, {"ciphertext_db": b"migrated"}, 2)
        with pytest.raises(LookupError):
            await target.restore_raw(sink)
        assert all(r["ciphertext_db"] == b"migrated" for r in db.table(TABLE))
