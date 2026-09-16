"""Tests for the offline v1 → v2 migration runner (FEAT-099, TASK-075)."""
import copy
import json
import logging
import os
import uuid
from datetime import datetime, timezone

import orjson
import pytest

from navigator_session.vault import open_sealed, read_header, seal
from navigator_session.vault.migrate import (
    BackupError,
    BackupIntegrityError,
    JsonlBackupSource,
    migrate_v1_to_v2,
    restore_backup,
    verify_v2,
)
from navigator_session.vault.migrate.backup import target_filename
from navigator_session.vault.migrate.legacy_v1 import LegacyV1Reader
from navigator_session.vault.registry import VaultRow
from navigator_session.vault.targets.postgres import PostgresTarget
from navigator_session.vault.targets.user_vault import UserVaultTarget

from .fake_pg import FakeDatabase, FakePool
from .v1_helpers import encrypt_v1_db

VAULT = "auth.user_vault_secrets"
MULTI = "test.bot_configs"


class BotConfigTarget(PostgresTarget):
    """Multi-field target whose v1 plaintext carries an in-plaintext context envelope."""

    name = MULTI
    table = MULTI
    purpose = "parrot-user-bot"
    identity_columns = ("user_id", "chatbot_id")
    encrypted_fields = ("mcp_config", "tools_config")
    include_field_in_context = True
    key_version_column = "key_version"
    touch_column = None
    state_columns = ("enabled",)
    quarantine_assignments = "enabled = false"

    def legacy_unwrap(self, field, plaintext, row):
        envelope = orjson.loads(plaintext)
        if envelope.get("_ctx") != {"u": row.identity["user_id"], "f": field}:
            raise ValueError("context envelope mismatch")
        return orjson.dumps(envelope["v"])


@pytest.fixture
def db():
    return FakeDatabase()


@pytest.fixture
def legacy(master_keys):
    return LegacyV1Reader(master_keys)


@pytest.fixture
def vault_target(db):
    return UserVaultTarget(FakePool(db))


@pytest.fixture
def bot_target(db):
    return BotConfigTarget(FakePool(db))


@pytest.fixture
def backup_dir(tmp_path):
    path = tmp_path / "vault-backups"
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


def seed_v1_vault(db, master_keys, count=6, deleted_every=0):
    for i in range(count):
        db.table(VAULT).append({
            "id": uuid.uuid4(), "user_id": 100 + i, "key": f"svc:{i}",
            "ciphertext_db": encrypt_v1_db(orjson.dumps(f"secret-{i}"), 1, master_keys[1]),
            "key_version": 1,
            "updated_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "deleted_at": datetime(2026, 1, 1, tzinfo=timezone.utc) if deleted_every and i % deleted_every == 0 else None,
        })
    return db.table(VAULT)


def seed_v1_bots(db, master_keys):
    def env(user, field, value):
        return encrypt_v1_db(orjson.dumps({"_ctx": {"u": user, "f": field}, "v": value}), 2, master_keys[2])
    rows = [
        {"id": 1, "user_id": 1, "chatbot_id": "bot-a",
         "mcp_config": env(1, "mcp_config", [{"server": "a"}]), "tools_config": env(1, "tools_config", []),
         "key_version": 2, "enabled": True},
        {"id": 2, "user_id": 2, "chatbot_id": "bot-b",
         "mcp_config": None, "tools_config": None, "key_version": 1, "enabled": True},
        # v1 envelope copied from user 1 (context mismatch) → must fail, not be legitimised
        {"id": 3, "user_id": 3, "chatbot_id": "bot-c",
         "mcp_config": env(1, "mcp_config", [{"server": "stolen"}]), "tools_config": None,
         "key_version": 2, "enabled": True},
    ]
    db.table(MULTI).extend(rows)
    return rows


def vault_ctx(target, row):
    return target.context_for(VaultRow(ref="r", pk=row["id"], identity={"user_id": row["user_id"], "key": row["key"]}, values={}), "ciphertext_db")


def snapshot(db):
    return copy.deepcopy(db.tables)


@pytest.mark.asyncio
class TestDryRun:
    async def test_counts_without_writes_or_backup(self, db, vault_target, keyring, legacy, master_keys):
        seed_v1_vault(db, master_keys, count=4)
        before = snapshot(db)
        report = await migrate_v1_to_v2([vault_target], keyring, dry_run=True, quarantine=False,
                                        backup_dir=None, legacy=legacy)
        assert report.dry_run and report.backup_dir is None and report.ok
        assert report.targets[0].migrated == 4 and report.targets[0].failed == 0
        assert db.tables == before
        assert not any(s.startswith("UPDATE") for s in db.statements)

    async def test_dry_run_rejects_quarantine(self, vault_target, keyring, legacy):
        with pytest.raises(ValueError):
            await migrate_v1_to_v2([vault_target], keyring, dry_run=True, quarantine=True,
                                   backup_dir=None, legacy=legacy)


@pytest.mark.asyncio
class TestArguments:
    async def test_run_requires_backup_dir(self, db, vault_target, keyring, legacy, master_keys):
        seed_v1_vault(db, master_keys, count=1)
        with pytest.raises(ValueError, match="backup_dir"):
            await migrate_v1_to_v2([vault_target], keyring, dry_run=False, quarantine=False,
                                   backup_dir=None, legacy=legacy)
        assert db.statements == []

    @pytest.mark.parametrize("run_id", ["", "has space", "x" * 33])
    async def test_invalid_run_id(self, vault_target, keyring, legacy, backup_dir, run_id):
        with pytest.raises(ValueError):
            await migrate_v1_to_v2([vault_target], keyring, dry_run=False, quarantine=False,
                                   backup_dir=backup_dir, run_id=run_id or "bad id", legacy=legacy)

    async def test_unsafe_backup_dir_blocks_writes(self, db, vault_target, keyring, legacy, master_keys, tmp_path):
        seed_v1_vault(db, master_keys, count=1)
        shared = tmp_path / "shared"
        shared.mkdir()
        os.chmod(shared, 0o755)
        with pytest.raises(BackupError):
            await migrate_v1_to_v2([vault_target], keyring, dry_run=False, quarantine=False,
                                   backup_dir=shared, legacy=legacy)
        assert db.statements == []


@pytest.mark.asyncio
class TestRun:
    async def test_migrates_everything_with_backup_first(
        self, db, vault_target, bot_target, keyring, legacy, master_keys, backup_dir, monkeypatch
    ):
        seed_v1_vault(db, master_keys, count=5, deleted_every=2)
        seed_v1_bots(db, master_keys)
        original_write = PostgresTarget.write

        async def asserting_write(self, row, blobs, key_version):
            manifest = json.loads((backup_dir / "run-1" / "manifest.json").read_text())
            assert manifest["targets"][self.name]["complete"], "write before backup completed"
            await original_write(self, row, blobs, key_version)

        monkeypatch.setattr(PostgresTarget, "write", asserting_write)
        report = await migrate_v1_to_v2([vault_target, bot_target], keyring, dry_run=False,
                                        quarantine=False, backup_dir=backup_dir, run_id="run-1",
                                        legacy=legacy, batch_size=2)

        vault_report, bot_report = report.targets
        assert (vault_report.total, vault_report.migrated, vault_report.backup_records) == (5, 5, 5)
        assert (bot_report.migrated, bot_report.empty, bot_report.failed) == (1, 1, 1)
        assert bot_report.failed_refs == [f"{MULTI}:id=3"] and not report.ok

        for row in db.table(VAULT):  # soft-deleted rows included
            assert read_header(row["ciphertext_db"]).key_id == 1 and row["key_version"] == 1
            assert orjson.loads(open_sealed(row["ciphertext_db"], vault_ctx(vault_target, row), keyring)).startswith("secret-")
        bot = db.table(MULTI)[0]
        ctx = bot_target.context_for(VaultRow(ref="r", pk=1, identity={"user_id": 1, "chatbot_id": "bot-a"}, values={}), "mcp_config")
        assert orjson.loads(open_sealed(bot["mcp_config"], ctx, keyring)) == [{"server": "a"}]
        assert db.table(MULTI)[2]["mcp_config"][0] != 0xA2  # failed row untouched

    async def test_backup_has_no_plaintext(self, db, vault_target, keyring, legacy, master_keys, backup_dir):
        seed_v1_vault(db, master_keys, count=3)
        await migrate_v1_to_v2([vault_target], keyring, dry_run=False, quarantine=False,
                               backup_dir=backup_dir, run_id="run-1", legacy=legacy)
        content = (backup_dir / "run-1" / target_filename(VAULT)).read_text()
        assert content.count("\n") == 3 and "secret-" not in content

    async def test_already_v2_rows_counted(self, db, vault_target, keyring, legacy, master_keys, backup_dir):
        rows = seed_v1_vault(db, master_keys, count=2)
        rows[0]["ciphertext_db"] = seal(b'"new"', vault_ctx(vault_target, rows[0]), keyring)
        report = await migrate_v1_to_v2([vault_target], keyring, dry_run=False, quarantine=False,
                                        backup_dir=backup_dir, legacy=legacy)
        assert (report.targets[0].already_v2, report.targets[0].migrated) == (1, 1)

    async def test_resume_after_interruption(self, db, vault_target, keyring, legacy, master_keys, backup_dir, monkeypatch):
        seed_v1_vault(db, master_keys, count=6)
        original = snapshot(db)
        original_write = PostgresTarget.write
        calls = {"n": 0}

        async def crashing_write(self, row, blobs, key_version):
            calls["n"] += 1
            if calls["n"] == 3:
                raise RuntimeError("connection lost")
            await original_write(self, row, blobs, key_version)

        monkeypatch.setattr(PostgresTarget, "write", crashing_write)
        with pytest.raises(RuntimeError):
            await migrate_v1_to_v2([vault_target], keyring, dry_run=False, quarantine=False,
                                   backup_dir=backup_dir, run_id="run-1", legacy=legacy, batch_size=2)
        backup_file = backup_dir / "run-1" / target_filename(VAULT)
        mtime = backup_file.stat().st_mtime_ns
        monkeypatch.setattr(PostgresTarget, "write", original_write)

        report = await migrate_v1_to_v2([vault_target], keyring, dry_run=False, quarantine=False,
                                        backup_dir=backup_dir, run_id="run-1", legacy=legacy, batch_size=2)
        assert (report.targets[0].already_v2, report.targets[0].migrated) == (2, 4)
        assert backup_file.stat().st_mtime_ns == mtime  # export not redone

        await restore_backup([vault_target], backup_dir / "run-1")
        assert db.tables[VAULT] == original[VAULT]  # backup still holds pre-migration data

    async def test_failures_without_quarantine(self, db, vault_target, keyring, legacy, master_keys, backup_dir):
        rows = seed_v1_vault(db, master_keys, count=3)
        rows[1]["ciphertext_db"] = encrypt_v1_db(b'"x"', 1, os.urandom(32))  # wrong master key
        bad = rows[1]["ciphertext_db"]
        report = await migrate_v1_to_v2([vault_target], keyring, dry_run=False, quarantine=False,
                                        backup_dir=backup_dir, legacy=legacy)
        assert not report.ok and report.targets[0].failed == 1 and report.targets[0].quarantined == 0
        assert rows[1]["ciphertext_db"] == bad and rows[1]["deleted_at"] is None

    async def test_quarantine(self, db, vault_target, keyring, legacy, master_keys, backup_dir):
        rows = seed_v1_vault(db, master_keys, count=3)
        rows[2]["ciphertext_db"] = b"\x00\x05" + os.urandom(40)  # unknown key version 5
        report = await migrate_v1_to_v2([vault_target], keyring, dry_run=False, quarantine=True,
                                        backup_dir=backup_dir, run_id="run-q", legacy=legacy)
        assert report.ok and report.targets[0].quarantined == 1
        assert rows[2]["deleted_at"] is not None
        [audit] = db.table("auth.user_vault_audit")
        assert audit["operation"] == "quarantine" and audit["session_id"] == "run:run-q"
        assert JsonlBackupSource(backup_dir / "run-q").quarantined_refs() == {vault_target.ref_for(rows[2]["id"])}


@pytest.mark.asyncio
class TestVerify:
    async def test_verify_before_and_after(self, db, vault_target, bot_target, keyring, legacy, master_keys, backup_dir):
        rows = seed_v1_vault(db, master_keys, count=3)
        rows[0]["ciphertext_db"] = b"\x00\x09" + os.urandom(40)
        assert not (await verify_v2([vault_target], keyring)).verified

        await migrate_v1_to_v2([vault_target], keyring, dry_run=False, quarantine=True,
                               backup_dir=backup_dir, run_id="run-v", legacy=legacy)
        without_exclusions = await verify_v2([vault_target], keyring)
        assert not without_exclusions.verified and without_exclusions.targets[0].failed == 1

        refs = JsonlBackupSource(backup_dir / "run-v").quarantined_refs()
        report = await verify_v2([vault_target], keyring, exclude_refs=refs)
        assert report.verified and report.targets[0].already_v2 == 2 and report.targets[0].quarantined == 1

    async def test_tampered_v2_fails_verification(self, db, vault_target, keyring):
        row = {"id": uuid.uuid4(), "user_id": 1, "key": "k", "key_version": 1,
               "updated_at": None, "deleted_at": None}
        blob = seal(b'"v"', vault_ctx(vault_target, row), keyring)
        row["ciphertext_db"] = blob[:-1] + bytes([blob[-1] ^ 1])
        db.table(VAULT).append(row)
        assert not (await verify_v2([vault_target], keyring)).verified


@pytest.mark.asyncio
class TestRestore:
    async def test_migrate_quarantine_restore_is_byte_identical(
        self, db, vault_target, bot_target, keyring, legacy, master_keys, backup_dir
    ):
        rows = seed_v1_vault(db, master_keys, count=4, deleted_every=3)
        rows[1]["ciphertext_db"] = b"\x00\x08" + os.urandom(40)
        seed_v1_bots(db, master_keys)
        before = {name: copy.deepcopy(db.tables[name]) for name in (VAULT, MULTI)}

        report = await migrate_v1_to_v2([vault_target, bot_target], keyring, dry_run=False,
                                        quarantine=True, backup_dir=backup_dir, run_id="run-r", legacy=legacy)
        restore = await restore_backup([vault_target, bot_target], backup_dir / "run-r")

        assert [t.restored for t in restore.targets] == [4, 3]
        assert restore.operation == "restore" and restore.run_id == "run-r"
        assert {name: db.tables[name] for name in (VAULT, MULTI)} == before
        json.loads(report.model_dump_json())

    async def test_restore_verifies_before_writing(self, db, vault_target, keyring, legacy, master_keys, backup_dir):
        seed_v1_vault(db, master_keys, count=2)
        await migrate_v1_to_v2([vault_target], keyring, dry_run=False, quarantine=False,
                               backup_dir=backup_dir, run_id="run-t", legacy=legacy)
        migrated = snapshot(db)
        path = backup_dir / "run-t" / target_filename(VAULT)
        path.write_text(path.read_text().replace("svc:0", "svc:9"))
        with pytest.raises(BackupIntegrityError):
            await restore_backup([vault_target], backup_dir / "run-t")
        assert db.tables == migrated

    async def test_restore_requires_known_targets(self, db, vault_target, keyring, legacy, master_keys, backup_dir):
        seed_v1_vault(db, master_keys, count=1)
        await migrate_v1_to_v2([vault_target], keyring, dry_run=False, quarantine=False,
                               backup_dir=backup_dir, run_id="run-u", legacy=legacy)
        with pytest.raises(BackupError, match="not available"):
            await restore_backup([], backup_dir / "run-u")


@pytest.mark.asyncio
async def test_no_plaintext_in_logs(db, vault_target, keyring, legacy, master_keys, backup_dir, caplog):
    rows = seed_v1_vault(db, master_keys, count=3)
    rows[0]["ciphertext_db"] = encrypt_v1_db(b'"secret-bad"', 1, os.urandom(32))
    with caplog.at_level(logging.DEBUG, logger="navigator.vault"):
        await migrate_v1_to_v2([vault_target], keyring, dry_run=False, quarantine=True,
                               backup_dir=backup_dir, legacy=legacy)
    assert "secret-" not in caplog.text
    assert "cannot migrate" in caplog.text and "LegacyV1Error" in caplog.text
