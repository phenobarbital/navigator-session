"""Tests for the navigator-vault CLI (FEAT-099, TASK-076)."""
import argparse
import fnmatch
import importlib
import io
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import orjson
import pytest

import navigator_session.vault.migrate.cli as cli
from navigator_session.vault import read_header
from navigator_session.vault.migrate.backup import target_filename
from navigator_session.vault.targets.user_vault import UserVaultTarget

from .fake_pg import FakeDatabase, FakePool
from .v1_helpers import encrypt_v1_db

ROOT = Path(__file__).resolve().parents[2]
VAULT = "auth.user_vault_secrets"


class ScanRedis:
    """Redis double exposing only SCAN and UNLINK (KEYS would raise AttributeError)."""

    def __init__(self, keys):
        self.data = {k: b"x" for k in keys}
        self.scan_calls = 0
        self._snapshot: list[str] = []

    async def scan(self, cursor=0, match="*", count=10):
        # Real SCAN returns every key present for the whole iteration, even if
        # other keys are deleted meanwhile: iterate a snapshot taken at cursor 0.
        self.scan_calls += 1
        if int(cursor) == 0:
            self._snapshot = sorted(self.data)
        page = self._snapshot[int(cursor):int(cursor) + count]
        nxt = int(cursor) + count
        found = [n for n in page if n in self.data and fnmatch.fnmatch(n, match)]
        return (0 if nxt >= len(self._snapshot) else nxt), found

    async def unlink(self, *names):
        for name in names:
            self.data.pop(name, None)


@pytest.fixture
def db():
    return FakeDatabase()


@pytest.fixture
def backup_dir(tmp_path):
    path = tmp_path / "backups"
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


@pytest.fixture(autouse=True)
def registered_entry_points(monkeypatch):
    monkeypatch.setattr(cli, "_entry_point_names", lambda: ["user_vault"])


def seed(db, master_keys, count=3):
    for i in range(count):
        db.table(VAULT).append({
            "id": uuid.uuid4(), "user_id": i + 1, "key": f"k{i}",
            "ciphertext_db": encrypt_v1_db(orjson.dumps(f"secret-{i}"), 1, master_keys[1]),
            "key_version": 1, "updated_at": datetime(2026, 1, 1, tzinfo=timezone.utc), "deleted_at": None,
        })
    return db.table(VAULT)


def run(argv, db=None, redis=None, confirm=lambda prompt: "", discover=None):
    opened = {"count": 0}

    @asynccontextmanager
    async def resources(args):
        opened["count"] += 1
        res = {}
        if db is not None:
            res["db_pool"] = FakePool(db, max_size=2)
        if redis is not None:
            res["redis"] = redis
        yield res

    out = io.StringIO()
    code = cli.main(
        argv,
        resources_factory=resources,
        discover=discover or (lambda **r: [UserVaultTarget(r["db_pool"])] if "db_pool" in r else []),
        confirm=confirm,
        out=out,
    )
    return code, out.getvalue(), opened["count"]


class TestUsage:
    def test_help_documents_runbook(self, capsys):
        assert cli.main(["--help"]) == cli.EXIT_OK
        assert "migrate --dry-run" in capsys.readouterr().out

    @pytest.mark.parametrize("argv", [["migrate"], ["migrate", "--dry-run", "--run"], ["nope"], []])
    def test_usage_errors_exit_3(self, argv):
        assert cli.main(argv) == cli.EXIT_CONFIG

    def test_run_requires_backup_dir_before_opening_resources(self, db, master_key_env):
        seed(db, master_key_env)
        code, _, opened = run(["migrate", "--run"], db=db)
        assert code == cli.EXIT_CONFIG and opened == 0 and db.statements == []

    def test_dry_run_rejects_quarantine(self, db, master_key_env):
        assert run(["migrate", "--dry-run", "--quarantine"], db=db)[0] == cli.EXIT_CONFIG

    def test_missing_master_keys(self, db, clean_vault_env):
        assert run(["migrate", "--dry-run"], db=db)[0] == cli.EXIT_CONFIG

    def test_console_script_declared(self):
        tomllib = pytest.importorskip("tomllib")
        scripts = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["scripts"]
        module, attr = scripts["navigator-vault"].split(":")
        assert getattr(importlib.import_module(module), attr) is cli.console_entry


class TestTargets:
    def test_unknown_target(self, db, master_key_env):
        assert run(["migrate", "--dry-run", "--target", "nope"], db=db)[0] == cli.EXIT_CONFIG

    def test_unconfigured_entry_points_block_run(self, db, master_key_env, backup_dir, monkeypatch):
        seed(db, master_key_env)
        monkeypatch.setattr(cli, "_entry_point_names", lambda: ["identity", "user_vault"])
        code, _, _ = run(["migrate", "--run", "--backup-dir", str(backup_dir)], db=db)
        assert code == cli.EXIT_CONFIG and not any(s.startswith("UPDATE") for s in db.statements)
        code, _, _ = run(["migrate", "--run", "--backup-dir", str(backup_dir), "--target", VAULT], db=db)
        assert code == cli.EXIT_OK

    def test_list_targets(self, db, monkeypatch):
        monkeypatch.setattr(cli, "_entry_point_names", lambda: ["identity", "user_vault"])
        code, out, _ = run(["list-targets"], db=db)
        assert code == cli.EXIT_OK and VAULT in out and "1 registered target(s) not configured" in out


class TestMigrateVerifyRestore:
    def test_full_runbook(self, db, master_key_env, backup_dir, tmp_path):
        rows = seed(db, master_key_env, count=3)
        before = [dict(r) for r in rows]

        code, out, _ = run(["migrate", "--dry-run"], db=db)
        assert code == cli.EXIT_OK and "migrated" in out and "secret-" not in out

        report_path = tmp_path / "report.json"
        code, out, _ = run(["--report", str(report_path), "migrate", "--run", "--backup-dir",
                            str(backup_dir), "--run-id", "run-1", "--batch-size", "2"], db=db)
        assert code == cli.EXIT_OK
        report = json.loads(report_path.read_text())
        assert report["run_id"] == "run-1" and report["targets"][0]["migrated"] == 3
        assert oct(os.stat(report_path).st_mode & 0o777) == "0o600"
        assert all(read_header(r["ciphertext_db"]).key_id == 1 for r in db.table(VAULT))

        assert run(["verify", "--backup-dir", str(backup_dir / "run-1")], db=db)[0] == cli.EXIT_OK

        code, out, _ = run(["restore", "--backup-dir", str(backup_dir / "run-1")], db=db,
                           confirm=lambda prompt: "wrong")
        assert code == cli.EXIT_ABORTED and "aborted" in out
        assert read_header(db.table(VAULT)[0]["ciphertext_db"])

        code, _, _ = run(["restore", "--backup-dir", str(backup_dir / "run-1")], db=db,
                         confirm=lambda prompt: "run-1")
        assert code == cli.EXIT_OK
        assert db.table(VAULT) == before

    def test_failures_exit_2_and_quarantine_exit_0(self, db, master_key_env, backup_dir):
        rows = seed(db, master_key_env, count=2)
        rows[0]["ciphertext_db"] = encrypt_v1_db(b'"x"', 1, os.urandom(32))
        code, out, _ = run(["migrate", "--run", "--backup-dir", str(backup_dir), "--run-id", "a"], db=db)
        assert code == cli.EXIT_FAILURES and "failed:" in out
        assert run(["verify"], db=db)[0] == cli.EXIT_FAILURES

        code, _, _ = run(["migrate", "--run", "--backup-dir", str(backup_dir), "--run-id", "b",
                          "--quarantine"], db=db)
        assert code == cli.EXIT_OK
        assert run(["verify"], db=db)[0] == cli.EXIT_FAILURES  # quarantined row still v1
        assert run(["verify", "--backup-dir", str(backup_dir / "b")], db=db)[0] == cli.EXIT_OK

    def test_tampered_backup_exit_4(self, db, master_key_env, backup_dir):
        seed(db, master_key_env, count=2)
        run(["migrate", "--run", "--backup-dir", str(backup_dir), "--run-id", "t"], db=db)
        path = backup_dir / "t" / target_filename(VAULT)
        path.write_text(path.read_text().replace("k0", "k9"))
        assert run(["restore", "--backup-dir", str(backup_dir / "t"), "--yes"], db=db)[0] == cli.EXIT_BACKUP

    def test_unsafe_backup_dir_exit_4(self, db, master_key_env, tmp_path):
        seed(db, master_key_env, count=1)
        shared = tmp_path / "shared"
        shared.mkdir()
        os.chmod(shared, 0o755)
        assert run(["migrate", "--run", "--backup-dir", str(shared)], db=db)[0] == cli.EXIT_BACKUP

    def test_concurrent_writers_warning(self, db, master_key_env, backup_dir, monkeypatch, caplog):
        seed(db, master_key_env, count=1)
        stamps = iter(["t1", "t2"])

        async def fake_activity(pool):
            return next(stamps)

        monkeypatch.setattr(cli, "_latest_user_activity", fake_activity)
        with caplog.at_level(logging.WARNING, logger="navigator.vault"):
            run(["migrate", "--run", "--backup-dir", str(backup_dir), "--run-id", "cw"], db=db)
        assert "writes by other clients were detected" in caplog.text


class TestRotate:
    def test_rotate(self, db, master_key_env, backup_dir):
        seed(db, master_key_env, count=2)
        run(["migrate", "--run", "--backup-dir", str(backup_dir)], db=db)
        code, out, _ = run(["rotate", "--from", "1", "--to", "2"], db=db)
        assert code == cli.EXIT_OK and "rotated=2" in out
        assert all(read_header(r["ciphertext_db"]).key_id == 2 for r in db.table(VAULT))

    def test_rotate_unknown_key(self, db, master_key_env):
        assert run(["rotate", "--from", "1", "--to", "9"], db=db)[0] == cli.EXIT_CONFIG

    def test_rotate_errors_exit_2(self, db, master_key_env):
        seed(db, master_key_env, count=1)  # still v1 → cannot be rotated
        db.table(VAULT)[0]["ciphertext_db"] = b"\xa2\x01\x00\x01" + os.urandom(40)
        assert run(["rotate", "--from", "1", "--to", "2"], db=db)[0] == cli.EXIT_FAILURES


class TestPurgeRedis:
    KEYS = ["vault:v2:aa:bb", "vault:5f0c:api", "session:abc", "session:def", "user:alice", "other:1"]

    def test_dry_run_counts_only(self):
        redis = ScanRedis(self.KEYS)
        code, out, _ = run(["purge-redis", "--sessions", "--dry-run"], redis=redis)
        assert code == cli.EXIT_OK and "would delete 2 key(s) matching vault:*" in out
        assert "would delete 2 key(s) matching session:*" in out and len(redis.data) == 6

    def test_purges_vault_only_by_default(self):
        redis = ScanRedis(self.KEYS)
        assert run(["purge-redis"], redis=redis)[0] == cli.EXIT_OK
        assert sorted(redis.data) == ["other:1", "session:abc", "session:def", "user:alice"]

    def test_purges_sessions(self):
        redis = ScanRedis(self.KEYS * 1 + [f"vault:x:{i}" for i in range(1200)])
        assert run(["purge-redis", "--sessions"], redis=redis)[0] == cli.EXIT_OK
        assert sorted(redis.data) == ["other:1", "user:alice"]
        assert redis.scan_calls > 2  # paginated SCAN


class TestResources:
    def ns(self, **kw):
        return argparse.Namespace(dsn=None, redis_url=None, **kw)

    def test_dsn_resolution(self, monkeypatch):
        monkeypatch.setenv("VAULT_DB_DSN", "postgres://u:p@h/db")
        assert cli.resolve_dsn(self.ns()) == "postgres://u:p@h/db"
        assert cli.resolve_dsn(argparse.Namespace(dsn="postgres://x", redis_url=None)) == "postgres://x"

    def test_redis_url_resolution(self, monkeypatch):
        monkeypatch.setenv("VAULT_REDIS_URL", "redis://r:6379/3")
        assert cli.resolve_redis_url(self.ns()) == "redis://r:6379/3"
        monkeypatch.delenv("VAULT_REDIS_URL")
        assert cli.resolve_redis_url(self.ns()).startswith("redis")
