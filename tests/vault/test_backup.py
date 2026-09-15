"""Tests for raw migration backups (FEAT-099, TASK-075)."""
import json
import os
import stat

import pytest

from navigator_session.vault.migrate.backup import (
    MANIFEST_NAME,
    BackupError,
    BackupIntegrityError,
    JsonlBackupSink,
    JsonlBackupSource,
    prepare_backup_dir,
    target_filename,
)


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def backup_root(tmp_path):
    root = tmp_path / "backups"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    return root


async def export(sink, target, records):
    sink.begin(target)
    for record in records:
        await sink.write(target, record)
    sink.finish(target, len(records))


class TestPrepare:
    def test_creates_private_run_dir(self, tmp_path):
        run_dir, resumed = prepare_backup_dir(tmp_path / "new" / "nested", "run-1")
        assert not resumed and run_dir.is_dir()
        assert mode(run_dir) == 0o700 and mode(run_dir.parent) & 0o077 == 0

    def test_rejects_world_accessible_dir(self, tmp_path):
        shared = tmp_path / "shared"
        shared.mkdir()
        os.chmod(shared, 0o755)
        with pytest.raises(BackupError, match="accessible by other users"):
            prepare_backup_dir(shared, "run-1")

    def test_rejects_file_path(self, tmp_path):
        path = tmp_path / "file"
        path.write_text("x")
        with pytest.raises(BackupError):
            prepare_backup_dir(path, "run-1")

    def test_rejects_non_empty_run_dir_without_manifest(self, backup_root):
        (backup_root / "run-1").mkdir()
        (backup_root / "run-1" / "stray.txt").write_text("x")
        with pytest.raises(BackupError, match="not empty"):
            prepare_backup_dir(backup_root, "run-1")

    def test_resume_detected_by_manifest(self, backup_root):
        run_dir, _ = prepare_backup_dir(backup_root, "run-1")
        JsonlBackupSink(run_dir, "run-1")
        assert prepare_backup_dir(backup_root, "run-1") == (run_dir, True)


@pytest.mark.asyncio
class TestSinkSource:
    async def test_roundtrip_permissions_and_manifest(self, backup_root):
        run_dir, _ = prepare_backup_dir(backup_root, "run-1")
        sink = JsonlBackupSink(run_dir, "run-1")
        records = [{"ref": f"t:id={i}", "values": {"c": "YWJj"}} for i in range(3)]
        await export(sink, "docdb:user_credentials", records)

        path = run_dir / target_filename("docdb:user_credentials")
        assert path.name == "docdb_user_credentials.jsonl"
        assert mode(path) == 0o600 and mode(run_dir / MANIFEST_NAME) == 0o600
        manifest = json.loads((run_dir / MANIFEST_NAME).read_text())
        entry = manifest["targets"]["docdb:user_credentials"]
        assert entry["complete"] and entry["count"] == 3 and len(entry["sha256"]) == 64
        assert manifest["run_id"] == "run-1" and manifest["navigator_session_version"]

        source = JsonlBackupSource(run_dir)
        source.verify()
        assert source.targets() == ["docdb:user_credentials"]
        assert [r async for r in source.read("docdb:user_credentials")] == records

    async def test_count_mismatch_rejected(self, backup_root):
        run_dir, _ = prepare_backup_dir(backup_root, "run-1")
        sink = JsonlBackupSink(run_dir, "run-1")
        sink.begin("t")
        await sink.write("t", {"a": 1})
        with pytest.raises(BackupError, match="wrote 1 records but reported 2"):
            sink.finish("t", 2)

    async def test_write_requires_begin(self, backup_root):
        run_dir, _ = prepare_backup_dir(backup_root, "run-1")
        with pytest.raises(BackupError):
            await JsonlBackupSink(run_dir, "run-1").write("t", {})

    async def test_verify_detects_tampering_and_incomplete(self, backup_root):
        run_dir, _ = prepare_backup_dir(backup_root, "run-1")
        sink = JsonlBackupSink(run_dir, "run-1")
        await export(sink, "t", [{"a": 1}, {"a": 2}])
        sink.begin("partial")
        await sink.write("partial", {"a": 1})
        sink.abort("partial")

        with pytest.raises(BackupIntegrityError, match="incomplete"):
            JsonlBackupSource(run_dir).verify(["partial"])
        path = run_dir / target_filename("t")
        path.write_text(path.read_text().replace('"a":2', '"a":3'))
        with pytest.raises(BackupIntegrityError, match="checksum"):
            JsonlBackupSource(run_dir).verify(["t"])

    async def test_quarantine_refs_and_resume(self, backup_root):
        run_dir, _ = prepare_backup_dir(backup_root, "run-1")
        sink = JsonlBackupSink(run_dir, "run-1")
        await export(sink, "t", [{"a": 1}])
        sink.record_quarantine("t", "t:id=1")
        sink.record_quarantine("t", "t:id=1")
        reopened = JsonlBackupSink(run_dir, "run-1")
        assert reopened.is_complete("t")
        assert JsonlBackupSource(run_dir).quarantined_refs() == {"t:id=1"}
        with pytest.raises(BackupError, match="belongs to run"):
            JsonlBackupSink(run_dir, "other-run")

    async def test_bad_manifest(self, backup_root):
        with pytest.raises(BackupIntegrityError):
            JsonlBackupSource(backup_root / "missing")
        (backup_root / "weird").mkdir()
        (backup_root / "weird" / MANIFEST_NAME).write_text(json.dumps({"format": "other"}))
        with pytest.raises(BackupIntegrityError, match="unsupported"):
            JsonlBackupSource(backup_root / "weird")
