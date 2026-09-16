"""Tests for registry-driven master key rotation (FEAT-099, TASK-074)."""
import base64
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from navigator_session.vault import (
    KeyRing,
    UnknownKeyVersionError,
    open_sealed,
    read_header,
    rotate_master_key,
    seal,
)
from navigator_session.vault.registry import VaultRow
from navigator_session.vault.targets.postgres import PostgresTarget
from navigator_session.vault.targets.user_vault import UserVaultTarget

from .fake_pg import FakeDatabase, FakePool

FIXTURES = Path(__file__).parent / "fixtures"
VAULT_TABLE = "auth.user_vault_secrets"
AUDIT_TABLE = "auth.user_vault_audit"
MULTI_TABLE = "test.multi_tokens"


class MultiTokenTarget(PostgresTarget):
    """Multi-field target shaped like auth.user_identities."""

    name = MULTI_TABLE
    table = MULTI_TABLE
    purpose = "identity"
    pk_column = "id"
    identity_columns = ("user_id", "provider")
    encrypted_fields = ("access_token", "refresh_token")
    include_field_in_context = True
    key_version_column = "key_version"
    touch_column = None
    state_columns = ()
    quarantine_assignments = "enabled = false"


def _identity_row(pk, identity):
    return VaultRow(ref="seed", pk=pk, identity=identity, values={})


@pytest.fixture
def ring3(master_keys):
    """Ring with versions 1, 2 and 3 (v1 active)."""
    return KeyRing({**master_keys, 3: os.urandom(32)}, 1)


@pytest.fixture
def db():
    return FakeDatabase()


@pytest.fixture
def vault_target(db):
    return UserVaultTarget(FakePool(db))


@pytest.fixture
def multi_target(db):
    return MultiTokenTarget(FakePool(db))


def seed_vault(db, target, ring, count=5, key_id=1, deleted_every=0):
    rows = []
    for i in range(count):
        pk, identity = uuid.uuid4(), {"user_id": 10 + i, "key": f"secret-{i}"}
        blob = seal(
            json.dumps(f"value-{i}").encode(),
            target.context_for(_identity_row(pk, identity), "ciphertext_db"),
            ring, key_id=key_id,
        )
        row = {
            "id": pk, **identity, "ciphertext_db": blob, "key_version": key_id,
            "updated_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "deleted_at": datetime(2026, 1, 1, tzinfo=timezone.utc) if deleted_every and i % deleted_every == 0 else None,
        }
        db.table(VAULT_TABLE).append(row)
        rows.append(row)
    return rows


def seed_multi(db, target, ring, pk, user_id, access_key_id=1, refresh_key_id=1, refresh=True):
    identity = {"user_id": user_id, "provider": "google"}
    base = _identity_row(pk, identity)
    row = {
        "id": pk, **identity,
        "access_token": seal(b"acc", target.context_for(base, "access_token"), ring, key_id=access_key_id),
        "refresh_token": (
            seal(b"ref", target.context_for(base, "refresh_token"), ring, key_id=refresh_key_id)
            if refresh else None
        ),
        "key_version": access_key_id,
    }
    db.table(MULTI_TABLE).append(row)
    return row


def open_vault_row(target, row, ring):
    vrow = _identity_row(row["id"], {"user_id": row["user_id"], "key": row["key"]})
    return json.loads(open_sealed(row["ciphertext_db"], target.context_for(vrow, "ciphertext_db"), ring))


@pytest.mark.asyncio
class TestRotation:
    async def test_rotates_all_targets(self, db, vault_target, multi_target, keyring):
        seed_vault(db, vault_target, keyring, count=7, deleted_every=3)
        seed_multi(db, multi_target, keyring, 1, 10)
        seed_multi(db, multi_target, keyring, 2, 11, refresh=False)

        stats = await rotate_master_key([vault_target, multi_target], 1, 2, keyring, batch_size=3)

        assert stats[VAULT_TABLE] == {"total": 7, "rotated": 7, "skipped": 0, "errors": 0, "failed_refs": []}
        assert stats[MULTI_TABLE]["rotated"] == 2
        for row in db.table(VAULT_TABLE):  # soft-deleted rows included
            assert read_header(row["ciphertext_db"]).key_id == 2 and row["key_version"] == 2
            assert open_vault_row(vault_target, row, keyring).startswith("value-")
        for row in db.table(MULTI_TABLE):
            assert read_header(row["access_token"]).key_id == 2 and row["key_version"] == 2
        assert db.table(MULTI_TABLE)[1]["refresh_token"] is None

    async def test_rotation_audit(self, db, vault_target, keyring):
        seed_vault(db, vault_target, keyring, count=2)
        await rotate_master_key([vault_target], 1, 2, keyring)
        audits = db.table(AUDIT_TABLE)
        assert [a["operation"] for a in audits] == ["rotate", "rotate"]
        assert all(a["key_version"] == 2 and a["session_id"] is None for a in audits)

    async def test_mixed_row_only_reseals_old_fields(self, db, multi_target, keyring):
        row = seed_multi(db, multi_target, keyring, 1, 10, access_key_id=1, refresh_key_id=2)
        refresh_before = row["refresh_token"]
        stats = await rotate_master_key([multi_target], 1, 2, keyring)
        stored = db.table(MULTI_TABLE)[0]
        assert stats[MULTI_TABLE]["rotated"] == 1
        assert read_header(stored["access_token"]).key_id == 2
        assert stored["refresh_token"] == refresh_before
        ctx = multi_target.context_for(_identity_row(1, {"user_id": 10, "provider": "google"}), "access_token")
        assert open_sealed(stored["access_token"], ctx, keyring) == b"acc"

    async def test_idempotent(self, db, vault_target, multi_target, keyring):
        seed_vault(db, vault_target, keyring, count=4)
        seed_multi(db, multi_target, keyring, 1, 10)
        await rotate_master_key([vault_target, multi_target], 1, 2, keyring)
        snapshot = [dict(r) for r in db.table(VAULT_TABLE)]
        stats = await rotate_master_key([vault_target, multi_target], 1, 2, keyring)
        assert stats[VAULT_TABLE]["rotated"] == 0 and stats[VAULT_TABLE]["skipped"] == 4
        assert stats[MULTI_TABLE]["skipped"] == 1
        assert db.table(VAULT_TABLE) == snapshot

    async def test_other_key_versions_untouched(self, db, vault_target, ring3):
        rows = seed_vault(db, vault_target, ring3, count=2, key_id=3)
        before = [r["ciphertext_db"] for r in rows]
        stats = await rotate_master_key([vault_target], 1, 2, ring3)
        assert stats[VAULT_TABLE]["skipped"] == 2
        assert [r["ciphertext_db"] for r in db.table(VAULT_TABLE)] == before


@pytest.mark.asyncio
class TestErrors:
    async def test_bad_rows_left_intact_and_reported(self, db, vault_target, keyring):
        rows = seed_vault(db, vault_target, keyring, count=6)
        # tampered tag
        rows[1]["ciphertext_db"] = rows[1]["ciphertext_db"][:-1] + bytes([rows[1]["ciphertext_db"][-1] ^ 1])
        # blob moved from another user's row
        rows[2]["ciphertext_db"] = rows[3]["ciphertext_db"]
        # legacy v1 blob
        v1 = json.loads((FIXTURES / "v1_blobs.json").read_text())
        rows[4]["ciphertext_db"] = base64.b64decode(v1["records"][0]["blob_b64"])
        broken = {rows[i]["id"]: rows[i]["ciphertext_db"] for i in (1, 2, 4)}

        stats = await rotate_master_key([vault_target], 1, 2, keyring, batch_size=2)

        s = stats[VAULT_TABLE]
        assert (s["total"], s["rotated"], s["errors"]) == (6, 3, 3)
        assert sorted(s["failed_refs"]) == sorted(vault_target.ref_for(pk) for pk in broken)
        for row in db.table(VAULT_TABLE):
            if row["id"] in broken:
                assert row["ciphertext_db"] == broken[row["id"]] and row["key_version"] == 1
            else:
                assert read_header(row["ciphertext_db"]).key_id == 2

    async def test_unknown_key_versions_rejected_before_reading(self, db, vault_target, keyring):
        seed_vault(db, vault_target, keyring, count=1)
        db.statements.clear()
        for old, new in ((9, 2), (1, 9)):
            with pytest.raises(UnknownKeyVersionError):
                await rotate_master_key([vault_target], old, new, keyring)
        assert db.statements == []

    async def test_field_on_missing_key_version_is_an_error(self, db, multi_target, ring3, master_keys):
        """A row with one field on the old key and one on a version the ring lost stays intact."""
        row = seed_multi(db, multi_target, ring3, 1, 10, access_key_id=1, refresh_key_id=3)
        before = dict(row)
        stats = await rotate_master_key([multi_target], 1, 2, KeyRing(master_keys, 1))
        assert stats[MULTI_TABLE]["errors"] == 1 and stats[MULTI_TABLE]["rotated"] == 0
        assert db.table(MULTI_TABLE)[0] == before

    @pytest.mark.parametrize("old,new,size", [(1, 1, 10), (1, 2, 0)])
    async def test_argument_validation(self, vault_target, keyring, old, new, size):
        with pytest.raises(ValueError):
            await rotate_master_key([vault_target], old, new, keyring, batch_size=size)

    async def test_vanished_row_counted_as_error(self, db, vault_target, keyring, monkeypatch):
        seed_vault(db, vault_target, keyring, count=2)
        original_write = vault_target.write
        calls = {"n": 0}

        async def flaky_write(row, blobs, key_version):
            calls["n"] += 1
            if calls["n"] == 1:
                raise LookupError(f"{row.ref} not found")
            await original_write(row, blobs, key_version)

        monkeypatch.setattr(vault_target, "write", flaky_write)
        stats = await rotate_master_key([vault_target], 1, 2, keyring)
        assert stats[VAULT_TABLE]["rotated"] == 1 and stats[VAULT_TABLE]["errors"] == 1

    async def test_unexpected_failure_rolls_back_batch(self, db, vault_target, keyring, monkeypatch):
        rows = seed_vault(db, vault_target, keyring, count=4)
        before = {r["id"]: r["ciphertext_db"] for r in rows}
        original_write = vault_target.write
        calls = {"n": 0}

        async def failing_write(row, blobs, key_version):
            calls["n"] += 1
            if calls["n"] == 4:
                raise RuntimeError("database connection lost")
            await original_write(row, blobs, key_version)

        monkeypatch.setattr(vault_target, "write", failing_write)
        with pytest.raises(RuntimeError):
            await rotate_master_key([vault_target], 1, 2, keyring, batch_size=2)
        by_id = {r["id"]: r for r in db.table(VAULT_TABLE)}
        ordered = sorted(before)
        # first batch committed, second batch rolled back entirely
        assert all(read_header(by_id[pk]["ciphertext_db"]).key_id == 2 for pk in ordered[:2])
        assert all(by_id[pk]["ciphertext_db"] == before[pk] for pk in ordered[2:])


@pytest.mark.asyncio
async def test_no_plaintext_or_blobs_in_logs(db, vault_target, keyring, caplog):
    rows = seed_vault(db, vault_target, keyring, count=3)
    rows[0]["ciphertext_db"] = b"\xa2" + os.urandom(40)
    with caplog.at_level(logging.DEBUG, logger="navigator.vault"):
        await rotate_master_key([vault_target], 1, 2, keyring)
    assert "value-" not in caplog.text
    for row in db.table(VAULT_TABLE):
        assert row["ciphertext_db"].hex()[:32] not in caplog.text
    assert "cannot rotate" in caplog.text


def test_legacy_shim_removed():
    with pytest.raises(ImportError):
        __import__("navigator_session.vault._legacy_v1_shim")
