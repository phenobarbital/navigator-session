"""Vault writes on asyncdb pools use the native asyncpg connection.

asyncdb's ``pg`` driver starts a transaction when ``transaction()`` is awaited and its
``execute()`` never raises. Driving vault writes through it crashed ``PostgresTarget``
(``'coroutine' object has no attribute 'start'``) and let failed writes report success.
"""
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from navigator_session.vault import SessionVault
from navigator_session.vault.registry import VaultRow
from navigator_session.vault.targets.postgres import acquire_connection, native_connection
from navigator_session.vault.targets.user_vault import UserVaultTarget

from .fake_pg import AsyncdbDriver, AsyncdbPool, FakeConnection, FakeDatabase, FakePool
from .test_session_vault import SID, FakeRedis, VaultDb

TABLE = "auth.user_vault_secrets"


def seed(db: FakeDatabase, count: int) -> list[dict[str, Any]]:
    rows = [
        {
            "id": uuid.uuid4(), "user_id": 1, "key": f"key-{i}", "ciphertext_db": os.urandom(16),
            "key_version": 1, "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "updated_at": datetime(2026, 1, 1, tzinfo=timezone.utc), "deleted_at": None,
        }
        for i in range(count)
    ]
    db.table(TABLE).extend(rows)
    return rows


@pytest.fixture
def db() -> FakeDatabase:
    return FakeDatabase()


@pytest.fixture(params=[False, True], ids=["context-acquire", "awaitable-acquire"])
def asyncdb_pool(request, db) -> AsyncdbPool:
    return AsyncdbPool(FakePool(db), awaitable=request.param)


class TestNativeConnection:
    def test_unwraps_asyncdb_driver(self, db):
        raw = FakeConnection(db)
        assert native_connection(AsyncdbDriver(raw)) is raw

    def test_native_connection_passes_through(self, db):
        raw = FakeConnection(db)
        assert native_connection(raw) is raw

    @pytest.mark.parametrize("raw", [None, object()], ids=["none", "no-execute"])
    def test_rejects_driver_without_native_connection(self, raw):
        with pytest.raises(TypeError, match="engine"):
            native_connection(AsyncdbDriver(raw))

    def test_rejects_asyncdb_style_connection_without_engine(self):
        class _Conn:
            async def fetch_all(self, *args):
                return None

        with pytest.raises(TypeError, match="asyncdb-style"):
            native_connection(_Conn())


@pytest.mark.asyncio
class TestAcquireConnection:
    async def test_yields_native_connection_and_releases_driver(self, asyncdb_pool):
        async with acquire_connection(asyncdb_pool) as conn:
            assert isinstance(conn, FakeConnection)
            assert asyncdb_pool.released == 0
        assert asyncdb_pool.released == 1
        assert asyncdb_pool.inner.in_use == 0

    async def test_refused_driver_is_still_released(self, db):
        class _BadPool(AsyncdbPool):
            async def _acquire_driver(self):
                driver = await super()._acquire_driver()
                driver._raw = None
                return driver

        pool = _BadPool(FakePool(db), awaitable=True)
        with pytest.raises(TypeError):
            async with acquire_connection(pool):
                pass
        assert pool.released == 1 and pool.inner.in_use == 0


@pytest.mark.asyncio
class TestPostgresTargetOnAsyncdbPool:
    async def test_transaction_commits_and_rolls_back(self, db, asyncdb_pool):
        seed(db, 2)
        target = UserVaultTarget(asyncdb_pool)
        [rows] = [batch async for batch in target.iter_batches(10)]
        async with target.transaction():
            await target.write(rows[0], {"ciphertext_db": b"rotated"}, 2)
        stored = {r["id"]: r["ciphertext_db"] for r in db.table(TABLE)}
        assert stored[rows[0].pk] == b"rotated"

        before = [r["ciphertext_db"] for r in db.table(TABLE)]
        with pytest.raises(RuntimeError):
            async with target.transaction():
                await target.write(rows[1], {"ciphertext_db": b"lost"}, 2)
                raise RuntimeError("abort batch")
        assert [r["ciphertext_db"] for r in db.table(TABLE)] == before

    async def test_write_to_missing_row_raises(self, asyncdb_pool):
        target = UserVaultTarget(asyncdb_pool)
        missing = VaultRow(
            ref="gone", pk=uuid.uuid4(), identity={"user_id": 1, "key": "k"}, values={}
        )
        with pytest.raises(LookupError):
            await target.write(missing, {"ciphertext_db": b"x"}, 2)

    async def test_rejected_write_raises(self, db, asyncdb_pool, monkeypatch):
        seed(db, 1)
        target = UserVaultTarget(asyncdb_pool)
        [rows] = [batch async for batch in target.iter_batches(10)]

        async def _reject(self, sql, *args):
            raise RuntimeError("db rejected the write")

        monkeypatch.setattr(FakeConnection, "execute", _reject)
        with pytest.raises(RuntimeError, match="rejected"):
            await target.write(rows[0], {"ciphertext_db": b"x"}, 2)


@pytest.mark.asyncio
class TestSessionVaultOnAsyncdbPool:
    @pytest.fixture(params=[False, True], ids=["context-acquire", "awaitable-acquire"])
    def vault_db(self, request):
        store = VaultDb()
        return store, AsyncdbPool(store, awaitable=request.param)

    async def test_set_and_delete_persist(self, keyring, vault_db):
        store, pool = vault_db
        vault = SessionVault(SID, 42, pool, FakeRedis(), session_ttl=600, keyring=keyring)
        await vault.set("k", "v")
        assert store.active(42, "k") is not None
        await vault.delete("k")
        assert store.active(42, "k") is None
        assert [a["operation"] for a in store.audit] == ["set", "delete"]

    async def test_failed_write_raises_and_is_not_cached(self, keyring, vault_db):
        store, pool = vault_db
        redis = FakeRedis()
        vault = SessionVault(SID, 42, pool, redis, session_ttl=600, keyring=keyring)
        store.fail_on.add("upsert")
        with pytest.raises(RuntimeError, match="db down"):
            await vault.set("k", "v")
        assert await vault.keys() == [] and redis.data == {}
