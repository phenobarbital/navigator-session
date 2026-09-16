"""Tests for SessionVault v2 (FEAT-099, TASK-073)."""
import base64
import json
import logging
import os
import pickle
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import navigator_session.vault.session_vault as sv
from navigator_session.vault import (
    KeyRing,
    SessionVault,
    VaultCryptoError,
    VaultIntegrityError,
    VaultSecretMetadata,
    open_sealed,
    read_header,
    seal,
)
from navigator_session.vault.registry import VaultRow
from navigator_session.vault.targets.user_vault import UserVaultTarget

FIXTURES = Path(__file__).parent / "fixtures"
SID = "5f0c2d3e-1a2b-4c5d-8e9f-0a1b2c3d4e5f"
TARGET_AUDIT_OPERATIONS = {"set", "get", "delete", "rotate", "quarantine", "integrity_fail"}


def _norm(sql: str) -> str:
    return " ".join(sql.split())


class VaultDb:
    """Emulates auth.user_vault_secrets / auth.user_vault_audit for SessionVault SQL.

    Enforces the *target* schema after navigator-auth migration 002:
    operation in TARGET_AUDIT_OPERATIONS and session_id <= 64 chars.
    """

    def __init__(self) -> None:
        self.secrets: list[dict[str, Any]] = []
        self.audit: list[dict[str, Any]] = []
        self.fail_on: set[str] = set()

    def active(self, user_id: int, key: str) -> dict[str, Any] | None:
        return next(
            (r for r in self.secrets
             if r["user_id"] == user_id and r["key"] == key and r["deleted_at"] is None),
            None,
        )

    def add_row(self, user_id: int, key: str, blob: bytes, key_version: int = 1) -> dict[str, Any]:
        row = {
            "id": uuid.uuid4(), "user_id": user_id, "key": key, "ciphertext_db": blob,
            "key_version": key_version, "updated_at": datetime(2026, 1, 2, tzinfo=timezone.utc),
            "deleted_at": None,
        }
        self.secrets.append(row)
        return row

    @asynccontextmanager
    async def _conn(self):
        yield VaultDbConnection(self)

    def acquire(self):
        return self._conn()


class VaultDbConnection:
    def __init__(self, db: VaultDb) -> None:
        self.db = db

    async def execute(self, sql: str, *args: Any) -> str:
        stmt = _norm(sql)
        if stmt == _norm(sv._UPSERT_SECRET):
            if "upsert" in self.db.fail_on:
                raise RuntimeError("db down")
            user_id, key, blob, key_version = args
            row = self.db.active(user_id, key)
            if row is None:
                self.db.add_row(user_id, key, blob, key_version)
            else:
                row.update(ciphertext_db=blob, key_version=key_version,
                           updated_at=datetime.now(timezone.utc))
            return "INSERT 0 1"
        if stmt == _norm(sv._SOFT_DELETE_SECRET):
            row = self.db.active(*args)
            if row:
                row["deleted_at"] = datetime.now(timezone.utc)
            return f"UPDATE {1 if row else 0}"
        if stmt == _norm(sv._INSERT_AUDIT):
            if "audit" in self.db.fail_on:
                raise RuntimeError("audit down")
            user_id, key, operation, key_version, session_id = args
            assert operation in TARGET_AUDIT_OPERATIONS
            assert session_id is None or len(session_id) <= 64
            self.db.audit.append(dict(user_id=user_id, key=key, operation=operation,
                                      key_version=key_version, session_id=session_id))
            return "INSERT 0 1"
        raise AssertionError(f"unexpected SQL: {stmt}")

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        assert _norm(sql) == _norm(sv._SELECT_ALL_ACTIVE)
        (user_id,) = args
        return [
            {k: r[k] for k in ("key", "ciphertext_db", "key_version", "updated_at")}
            for r in self.db.secrets if r["user_id"] == user_id and r["deleted_at"] is None
        ]


class FakeRedis:
    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}
        self.ttls: dict[str, int] = {}

    async def setex(self, name: str, ttl: int, value: bytes) -> None:
        self.data[name] = value
        self.ttls[name] = ttl

    async def get(self, name: str) -> bytes | None:
        return self.data.get(name)

    async def delete(self, name: str) -> None:
        self.data.pop(name, None)


@pytest.fixture
def db():
    return VaultDb()


@pytest.fixture
def redis():
    return FakeRedis()


@pytest.fixture
def vault(keyring, db, redis):
    return SessionVault(SID, 42, db, redis, session_ttl=600, keyring=keyring)


def db_context_for(user_id: int, key: str):
    row = VaultRow(ref="r", pk=None, identity={"user_id": user_id, "key": key}, values={})
    return UserVaultTarget(db_pool=object()).context_for(row, "ciphertext_db")


class TestValidationAndInit:
    @pytest.mark.parametrize("key", ["jira:access_token", "a", "x" * 255, "ñandú/key.v2"])
    def test_accepts(self, vault, key):
        vault._validate_key(key)

    @pytest.mark.parametrize("key", ["", "x" * 256, "bad\nkey", "nul\x00", "del\x7f", None, 5])
    def test_rejects(self, vault, key):
        with pytest.raises(ValueError):
            vault._validate_key(key)

    @pytest.mark.parametrize("sid", ["", None])
    def test_session_uuid_required(self, keyring, db, sid):
        with pytest.raises(ValueError):
            SessionVault(sid, 1, db, keyring=keyring)

    def test_user_id_coercion(self, keyring, db):
        assert SessionVault(SID, "7", db, keyring=keyring)._user_id == 7
        with pytest.raises(ValueError):
            SessionVault(SID, True, db, keyring=keyring)
        with pytest.raises(ValueError):
            SessionVault(SID, "alice", db, keyring=keyring)

    def test_keyring_defaults_to_env(self, master_key_env, db):
        vault = SessionVault(SID, 1, db)
        assert vault._keyring.active_key_id == 1
        assert not hasattr(vault, "_master_keys")

    def test_session_key_cache_not_serializable(self, vault, master_keys):
        with pytest.raises(TypeError):
            pickle.dumps(vault._keyring)
        for key in master_keys.values():
            assert key.hex() not in repr(vault._keyring)


@pytest.mark.asyncio
class TestSetGet:
    @pytest.mark.parametrize(
        "value", ["sk-test", 42, 3.14, {"a": [1, {"b": None}]}, [1, "two"], b"\x00\xff", True, None]
    )
    async def test_roundtrip(self, vault, value):
        await vault.set("secret", value)
        assert await vault.get("secret") == value

    async def test_colon_keys_roundtrip(self, vault):
        """F4: VaultTokenSync writes {provider}:{field} keys."""
        await vault.set("jira:access_token", "tok")
        await vault.set("jira:refresh_token", "ref")
        assert await vault.get("jira:access_token") == "tok"
        assert sorted(await vault.keys()) == ["jira:access_token", "jira:refresh_token"]

    async def test_set_returns_metadata_and_overwrites(self, vault, db):
        first = await vault.set("k", "v1")
        second = await vault.set("k", "v2")
        assert isinstance(second, VaultSecretMetadata)
        assert second.key == "k" and second.key_version == 1 and second.updated_at >= first.updated_at
        assert await vault.get("k") == "v2"
        assert len([r for r in db.secrets if r["deleted_at"] is None]) == 1

    async def test_default_on_miss_and_validation(self, vault):
        assert await vault.get("missing", "dflt") == "dflt"
        with pytest.raises(ValueError):
            await vault.get("bad\nkey")
        with pytest.raises(ValueError):
            await vault.set("", "v")

    async def test_db_write_happens_before_cache(self, vault, db, redis):
        db.fail_on.add("upsert")
        with pytest.raises(RuntimeError):
            await vault.set("k", "v")
        assert await vault.keys() == [] and redis.data == {} and await vault.list_metadata() == []

    async def test_max_keys(self, vault):
        vault._max_keys_per_user = 3
        for i in range(3):
            await vault.set(f"k{i}", i)
        with pytest.raises(ValueError, match="Max secrets"):
            await vault.set("k3", 3)
        await vault.set("k0", "overwrite")  # overwrite does not count


@pytest.mark.asyncio
class TestDatabaseLayer:
    async def test_db_blob_is_v2_bound_to_user_and_key(self, vault, db, keyring):
        await vault.set("api", "sk-test")
        [row] = db.secrets
        header = read_header(row["ciphertext_db"])
        assert row["ciphertext_db"][0] == 0xA2 and header.key_id == row["key_version"] == 1
        assert b"sk-test" not in row["ciphertext_db"]
        plaintext = open_sealed(row["ciphertext_db"], db_context_for(42, "api"), keyring)
        assert json.loads(plaintext) == "sk-test"
        with pytest.raises(VaultIntegrityError):
            open_sealed(row["ciphertext_db"], db_context_for(43, "api"), keyring)

    async def test_audit_uses_session_hmac(self, vault, db):
        await vault.set("api", "v")
        await vault.delete("api")
        assert [a["operation"] for a in db.audit] == ["set", "delete"]
        for audit in db.audit:
            assert audit["session_id"] == vault._sid_hmac
            assert len(audit["session_id"]) == 64 and SID not in audit["session_id"]
            assert audit["user_id"] == 42 and audit["key_version"] == 1

    async def test_delete(self, vault, db, redis):
        await vault.set("api", "v")
        await vault.delete("api")
        assert db.secrets[0]["deleted_at"] is not None
        assert not await vault.exists("api") and redis.data == {}
        assert await vault.get("api") is None and await vault.list_metadata() == []


@pytest.mark.asyncio
class TestSessionLayerAndRedis:
    async def test_redis_names_hide_session_and_key(self, vault, redis):
        await vault.set("jira:access_token", "tok")
        [name] = redis.data
        assert name.startswith("vault:v2:")
        assert SID not in name and "jira" not in name and "access_token" not in name
        assert redis.ttls[name] == 600

    async def test_get_falls_back_to_redis_and_caches(self, vault, keyring, db, redis):
        await vault.set("k", {"x": 1})
        other = SessionVault(SID, 42, db, redis, keyring=keyring)  # same session, empty cache
        assert await other.get("k") == {"x": 1}
        assert await other.exists("k")

    async def test_without_redis(self, keyring, db):
        vault = SessionVault(SID, 42, db, None, keyring=keyring)
        await vault.set("k", "v")
        assert await vault.get("k") == "v"
        await vault.delete("k")
        assert await vault.get("k", "d") == "d"

    async def test_tampered_redis_entry(self, vault, keyring, db, redis):
        await vault.set("k", "v")
        name = next(iter(redis.data))
        redis.data[name] = redis.data[name][:-1] + bytes([redis.data[name][-1] ^ 1])
        fresh = SessionVault(SID, 42, db, redis, keyring=keyring)
        with pytest.raises(VaultIntegrityError):
            await fresh.get("k")
        assert not await fresh.exists("k")

    async def test_redis_entry_swapped_between_keys(self, vault, keyring, db, redis):
        await vault.set("a", "secret-a")
        await vault.set("b", "secret-b")
        fresh = SessionVault(SID, 42, db, redis, keyring=keyring)
        redis.data[fresh._redis_key("b")] = redis.data[fresh._redis_key("a")]
        with pytest.raises(VaultIntegrityError):
            await fresh.get("b")

    async def test_other_session_cannot_open_entries(self, vault, keyring, db, redis):
        await vault.set("k", "v")
        intruder = SessionVault("another-session", 42, db, redis, keyring=keyring)
        redis.data[intruder._redis_key("k")] = redis.data[vault._redis_key("k")]
        with pytest.raises(VaultIntegrityError):
            await intruder.get("k")

    async def test_redis_dump_plus_session_id_is_not_enough(self, vault, redis):
        """F1: without master keys, Redis contents + session cookie decrypt nothing."""
        await vault.set("api", "sk-test")
        blob = next(iter(redis.data.values()))
        # v1-style derivation from the session id alone
        v1_key = HKDF(hashes.SHA256(), 32, None, b"vault-session").derive(SID.encode())
        for nonce, ct in ((blob[4:16], blob[16:]), (blob[:12], blob[12:])):
            with pytest.raises(InvalidTag):
                AESGCM(v1_key).decrypt(nonce, ct, None)
        attacker = KeyRing({1: os.urandom(32)}, 1)
        with pytest.raises(VaultIntegrityError):
            open_sealed(blob, vault._session_context("api"), attacker, session_uuid=SID)

    async def test_deterministic_session_scheme_across_instances(self, keyring, db, redis):
        sid = "telegram-persistent:7"
        writer = SessionVault(sid, 7, db, redis, keyring=keyring)
        await writer.set("jira:access_token", "tok")
        reader = await SessionVault.load_for_session(sid, 7, db, redis, keyring=keyring)
        assert await reader.get("jira:access_token") == "tok"
        assert reader._redis_key("jira:access_token") == writer._redis_key("jira:access_token")


@pytest.mark.asyncio
class TestLoadForSession:
    async def test_loads_and_reseals_for_new_session(self, vault, keyring, db, redis):
        await vault.set("a", "one")
        await vault.set("b", {"two": 2})
        loaded = await SessionVault.load_for_session("new-session", 42, db, redis, keyring=keyring)
        assert await loaded.get("a") == "one" and await loaded.get("b") == {"two": 2}
        metadata = await loaded.list_metadata()
        assert [m.key for m in metadata] == ["a", "b"]
        assert all(set(m.model_dump()) == {"key", "updated_at", "key_version"} for m in metadata)
        assert loaded._redis_key("a") in redis.data

    async def test_cross_user_row_skipped_and_audited(self, keyring, db, redis):
        owner = SessionVault(SID, 1, db, redis, keyring=keyring)
        await owner.set("api", "owner-secret")
        victim_blob = db.secrets[0]["ciphertext_db"]
        db.add_row(2, "stolen", victim_blob)
        victim = SessionVault("s2", 2, db, redis, keyring=keyring)
        await victim.set("mine", "ok")

        loaded = await SessionVault.load_for_session("s3", 2, db, redis, keyring=keyring)
        assert await loaded.keys() == ["mine"]
        assert await loaded.get("stolen") is None
        [fail] = [a for a in db.audit if a["operation"] == "integrity_fail"]
        assert fail["user_id"] == 2 and fail["key"] == "stolen"
        assert fail["session_id"] == keyring.naming_hmac("s3")

    async def test_v1_and_unknown_key_rows_skipped(self, master_keys, db):
        v1 = json.loads((FIXTURES / "v1_blobs.json").read_text())
        record = next(r for r in v1["records"] if r["layer"] == "db")
        db.add_row(9, "legacy", base64.b64decode(record["blob_b64"]))
        future_ring = KeyRing({**master_keys, 3: os.urandom(32)}, 3)
        db.add_row(9, "future", seal(b'"x"', db_context_for(9, "future"), future_ring), 3)
        ring = KeyRing(master_keys, 1)
        await SessionVault(SID, 9, db, keyring=ring).set("good", "g")

        loaded = await SessionVault.load_for_session("s", 9, db, keyring=ring)
        assert await loaded.keys() == ["good"]
        assert sorted(a["key"] for a in db.audit if a["operation"] == "integrity_fail") == [
            "future", "legacy"
        ]

    async def test_audit_failure_does_not_break_load(self, keyring, db, caplog):
        db.add_row(5, "bad", b"\xa2" + os.urandom(40))
        db.fail_on.add("audit")
        with caplog.at_level(logging.ERROR, logger="navigator.vault"):
            loaded = await SessionVault.load_for_session("s", 5, db, keyring=keyring)
        assert await loaded.keys() == []
        assert "Failed to audit vault integrity failures" in caplog.text

    async def test_rows_written_by_session_vault_open_with_target_context(self, vault, db, keyring):
        await vault.set("api", "sk")
        row = db.secrets[0]
        target = UserVaultTarget(db_pool=object())
        vault_row = VaultRow(ref="r", pk=row["id"], identity={"user_id": row["user_id"], "key": row["key"]},
                             values={"ciphertext_db": row["ciphertext_db"]})
        assert open_sealed(row["ciphertext_db"], target.context_for(vault_row, "ciphertext_db"), keyring)


@pytest.mark.asyncio
async def test_no_secrets_or_session_ids_in_logs(keyring, db, redis, caplog):
    with caplog.at_level(logging.DEBUG, logger="navigator.vault"):
        vault = SessionVault(SID, 42, db, redis, keyring=keyring)
        await vault.set("api", "sk-super-secret")
        await vault.get("api")
        db.add_row(42, "tampered", b"\xa2" + os.urandom(40))
        await SessionVault.load_for_session(SID, 42, db, redis, keyring=keyring)
        name = next(iter(redis.data))
        redis.data[name] = b"\xa2" + os.urandom(40)
        with pytest.raises(VaultCryptoError):  # random header → unsupported or integrity
            await SessionVault(SID, 42, db, redis, keyring=keyring).get("api")
    assert "sk-super-secret" not in caplog.text
    assert SID not in caplog.text
    for row in db.secrets:
        assert row["ciphertext_db"].hex()[:32] not in caplog.text
    assert "integrity" in caplog.text
