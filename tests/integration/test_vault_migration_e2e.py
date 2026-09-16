"""
Cross-repo migration rehearsal (FEAT-099, TASK-085).

Seeds v1 ciphertext in three protected targets that stand in for the real
stores — a single-field PostgreSQL table (``auth.user_vault_secrets``), a
multi-field one with a legacy in-plaintext envelope (``users_bots``) and a
document store (``user_credentials``) — and drives the **real** CLI through the
runbook: list-targets → dry-run → run (with backup) → verify → restore.

The stores are in-memory doubles so the rehearsal runs anywhere; the SQL of the
navigator-auth schema migration was exercised against a real PostgreSQL in
TASK-078, and the runbook covers the production rehearsal.
"""
from __future__ import annotations

import base64
import copy
import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import orjson
import pytest

from navigator_session.vault import KeyRing, open_sealed, read_header
from navigator_session.vault.migrate import JsonlBackupSource
from navigator_session.vault.migrate import cli as vault_cli
from navigator_session.vault.registry import VaultRow
from navigator_session.vault.targets.postgres import PostgresTarget
from navigator_session.vault.targets.user_vault import UserVaultTarget

from tests.vault.fake_pg import FakeDatabase, FakePool
from tests.vault.v1_helpers import encrypt_v1_db

VAULT_TABLE = "auth.user_vault_secrets"
BOTS_TABLE = "navigator.users_bots"
DOCDB_TARGET = "docdb:user_credentials"


# ---------------------------------------------------------------------------
# Stand-ins for the targets contributed by the other repositories
# ---------------------------------------------------------------------------

class UsersBotsLikeTarget(PostgresTarget):
    """Multi-field target whose v1 plaintext carries a ``_ctx`` envelope."""

    name = table = BOTS_TABLE
    purpose = "parrot-user-bot"
    pk_column = "chatbot_id"
    identity_columns = ("user_id", "chatbot_id")
    encrypted_fields = ("mcp_config", "tools_config")
    include_field_in_context = True
    key_version_column = None
    touch_column = None
    state_columns = ("enabled",)
    quarantine_assignments = "enabled = false"

    def context_value(self, column: str, value: Any) -> Any:
        return int(value) if column == "user_id" else str(value)

    def pk_from_json(self, value: Any) -> Any:
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))

    def state_from_json(self, column: str, value: Any) -> Any:
        return None if value is None else bool(value)

    def legacy_unwrap(self, field: str, plaintext: bytes, row: Any) -> bytes:
        envelope = orjson.loads(plaintext)
        expected = {
            "u": int(row.identity["user_id"]),
            "c": str(row.identity["chatbot_id"]),
            "f": field,
        }
        if envelope.get("_ctx") != expected:
            raise ValueError("context envelope mismatch")
        return orjson.dumps({"v": envelope["v"]})


class DocumentStoreTarget:
    """Minimal document-store target (base64 values, natural-key addressing)."""

    name = DOCDB_TARGET
    encrypted_fields = ("credential",)

    def __init__(self, store: dict[str, list[dict]]) -> None:
        self.store = store

    def _docs(self) -> list[dict]:
        return self.store.setdefault("user_credentials", [])

    def context_for(self, row: Any, field: str):
        from navigator_session.vault import VaultContext

        return VaultContext(
            purpose="parrot-credential", layer="db",
            fields=(
                ("user_id", int(row.identity["user_id"])),
                ("name", str(row.identity["name"])),
                ("field", "credential"),
            ),
        )

    async def iter_batches(self, batch_size: int):
        documents = sorted(self._docs(), key=lambda d: (str(d["user_id"]), d["name"]))
        for start in range(0, len(documents), batch_size):
            yield [self._row(doc) for doc in documents[start:start + batch_size]]

    @asynccontextmanager
    async def transaction(self):
        yield None

    async def write(self, row, blobs, key_version):
        doc = self._find(row)
        doc["credential"] = base64.b64encode(bytes(blobs["credential"])).decode("ascii")
        doc["key_version"] = key_version

    async def quarantine(self, row, reason, run_id):
        doc = self._find(row)
        self.store.setdefault("user_credentials_quarantine", []).append(
            {**doc, "reason": reason, "run_id": run_id}
        )
        self._docs().remove(doc)

    async def export_raw(self, sink) -> int:
        count = 0
        async for batch in self.iter_batches(50):
            for row in batch:
                await sink.write(self.name, {
                    "ref": row.ref, "pk": dict(row.identity), "identity": dict(row.identity),
                    "values": {
                        "credential": base64.b64encode(row.values["credential"]).decode("ascii")
                    },
                    "key_version": row.key_version,
                    "document": row.state["document"],
                })
                count += 1
        return count

    async def restore_raw(self, source) -> int:
        count = 0
        async for record in source.read(self.name):
            identity = record["identity"]
            docs = self._docs()
            for existing in list(docs):
                if all(existing.get(k) == v for k, v in identity.items()):
                    docs.remove(existing)
            docs.append(dict(record["document"]))
            quarantined = self.store.get("user_credentials_quarantine")
            if quarantined is not None:
                remaining = [
                    d for d in quarantined
                    if not all(d.get(k) == v for k, v in identity.items())
                ]
                if remaining:
                    self.store["user_credentials_quarantine"] = remaining
                else:
                    self.store.pop("user_credentials_quarantine", None)
            count += 1
        return count

    def _find(self, row) -> dict:
        for doc in self._docs():
            if all(doc.get(k) == v for k, v in row.identity.items()):
                return doc
        raise LookupError(f"{row.ref} not found")

    def _row(self, doc: dict) -> VaultRow:
        identity = {"user_id": doc["user_id"], "name": doc["name"]}
        return VaultRow(
            ref=f"{self.name}:user_id={doc['user_id']},name={doc['name']}",
            pk=identity, identity=identity,
            values={"credential": base64.b64decode(doc["credential"])},
            key_version=doc.get("key_version"),
            state={"document": dict(doc)},
        )


# ---------------------------------------------------------------------------
# Fixtures: v1 data across the three stores
# ---------------------------------------------------------------------------

MASTER_KEYS = {1: b"\x77" * 32}
BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def keyring():
    return KeyRing(MASTER_KEYS, 1)


@pytest.fixture
def stores():
    return {"pg": FakeDatabase(), "docdb": {}}


@pytest.fixture
def targets(stores):
    pool = FakePool(stores["pg"], max_size=2)
    return [
        UserVaultTarget(pool),
        UsersBotsLikeTarget(pool),
        DocumentStoreTarget(stores["docdb"]),
    ]


def seed(stores, *, broken: bool = False) -> dict[str, Any]:
    """Seed v1 ciphertext; with ``broken`` one row is undecryptable."""
    db = stores["pg"]
    for i in range(4):
        db.table(VAULT_TABLE).append({
            "id": uuid.uuid4(), "user_id": 10 + i, "key": f"svc:{i}",
            "ciphertext_db": encrypt_v1_db(orjson.dumps(f"secret-{i}"), 1, MASTER_KEYS[1]),
            "key_version": 1, "updated_at": BASE_TIME,
            "deleted_at": BASE_TIME if i == 3 else None,  # soft-deleted rows migrate too
        })
    if broken:
        db.table(VAULT_TABLE)[1]["ciphertext_db"] = encrypt_v1_db(
            b'"x"', 1, os.urandom(32)  # sealed with a key we do not have
        )

    def envelope(user_id, bot_id, field, value):
        return encrypt_v1_db(
            orjson.dumps({"_v": 1, "_ctx": {"u": user_id, "c": str(bot_id), "f": field}, "v": value}),
            1, MASTER_KEYS[1],
        )

    bot_a, bot_b = uuid.UUID(int=1), uuid.UUID(int=2)
    db.table(BOTS_TABLE).extend([
        {"chatbot_id": bot_a, "user_id": 10, "enabled": True,
         "mcp_config": envelope(10, bot_a, "mcp_config", [{"server": "a"}]),
         "tools_config": envelope(10, bot_a, "tools_config", [])},
        # v1 blob copied from bot A: the legacy envelope check must reject it
        {"chatbot_id": bot_b, "user_id": 11, "enabled": True,
         "mcp_config": envelope(10, bot_a, "mcp_config", [{"server": "stolen"}]),
         "tools_config": None},
    ])

    stores["docdb"]["user_credentials"] = [
        {"user_id": 10, "name": "prod_pg", "key_version": 1,
         "credential": base64.b64encode(
             encrypt_v1_db(orjson.dumps({"driver": "pg", "password": "p"}), 1, MASTER_KEYS[1])
         ).decode()},
    ]
    return {"bot_a": bot_a, "bot_b": bot_b}


def snapshot(stores) -> dict:
    return json.loads(json.dumps(
        {"pg": stores["pg"].tables, "docdb": stores["docdb"]}, default=str
    ))


def run_cli(argv, targets, out, vault_env, *, entry_points=("user_vault",)):
    """Invoke the real CLI with injected resources and target discovery."""
    @asynccontextmanager
    async def resources(_args):
        yield {"db_pool": object()}

    return vault_cli.main(
        argv,
        resources_factory=resources,
        discover=lambda **_kw: targets,
        confirm=lambda _prompt: "yes",
        out=out,
    )


@pytest.fixture
def vault_env(monkeypatch):
    for name in [n for n in os.environ if n.startswith("VAULT_")]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("VAULT_MASTER_KEY_v1", base64.b64encode(MASTER_KEYS[1]).decode())
    monkeypatch.setenv("VAULT_ACTIVE_KEY_ID", "1")
    monkeypatch.setattr(vault_cli, "_entry_point_names", lambda: ["user_vault"])


@pytest.fixture
def backup_dir(tmp_path):
    path = tmp_path / "vault-backups"
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


# ---------------------------------------------------------------------------
# The rehearsal
# ---------------------------------------------------------------------------

class TestMigrationRehearsal:
    def test_runbook_end_to_end(self, stores, targets, keyring, vault_env, backup_dir, capsys):
        ids = seed(stores)
        before = snapshot(stores)
        out = capsys

        # 1. list-targets
        assert run_cli(["list-targets"], targets, os.sys.stdout, vault_env) == 0

        # 2. dry run — no writes
        assert run_cli(["migrate", "--dry-run"], targets, os.sys.stdout, vault_env) == 2
        assert snapshot(stores) == before  # the stolen bot row fails, nothing is written

        # 3. run with backup and quarantine
        code = run_cli(
            ["migrate", "--run", "--backup-dir", str(backup_dir), "--run-id", "rehearsal",
             "--quarantine"],
            targets, os.sys.stdout, vault_env,
        )
        assert code == 0

        # every remaining row is v2 and opens with its context
        for row in stores["pg"].table(VAULT_TABLE):
            assert read_header(row["ciphertext_db"]).key_id == 1
            context = targets[0].context_for(
                VaultRow(ref="r", pk=row["id"],
                         identity={"user_id": row["user_id"], "key": row["key"]}, values={}),
                "ciphertext_db",
            )
            assert orjson.loads(
                open_sealed(row["ciphertext_db"], context, keyring)
            ).startswith("secret-")

        bots = {r["chatbot_id"]: r for r in stores["pg"].table(BOTS_TABLE)}
        assert bots[ids["bot_a"]]["mcp_config"][0] == 0xA2
        assert bots[ids["bot_b"]]["enabled"] is False  # quarantined, blob untouched
        assert bots[ids["bot_b"]]["mcp_config"][0] != 0xA2

        document = stores["docdb"]["user_credentials"][0]
        assert base64.b64decode(document["credential"])[0] == 0xA2

        # 4. verify (excluding the quarantined row)
        run_dir = backup_dir / "rehearsal"
        assert run_cli(["verify"], targets, os.sys.stdout, vault_env) == 2
        assert run_cli(
            ["verify", "--backup-dir", str(run_dir)], targets, os.sys.stdout, vault_env
        ) == 0

        # backups hold v1 ciphertext only, never plaintext
        exported = "\n".join(p.read_text() for p in run_dir.glob("*.jsonl"))
        assert "secret-" not in exported and "password" not in exported
        assert JsonlBackupSource(run_dir).quarantined_refs()

        # 5. rollback restores every store byte-for-byte
        assert run_cli(
            ["restore", "--backup-dir", str(run_dir), "--yes"], targets, os.sys.stdout, vault_env
        ) == 0
        assert snapshot(stores) == before

    def test_second_run_is_idempotent(self, stores, targets, vault_env, backup_dir):
        seed(stores)
        stores["pg"].table(BOTS_TABLE).pop()  # drop the deliberately broken row
        assert run_cli(
            ["migrate", "--run", "--backup-dir", str(backup_dir), "--run-id", "first"],
            targets, os.sys.stdout, vault_env,
        ) == 0
        migrated = snapshot(stores)

        assert run_cli(
            ["migrate", "--run", "--backup-dir", str(backup_dir), "--run-id", "second",
             "--report", str(backup_dir / "second.json")],
            targets, os.sys.stdout, vault_env,
        ) == 0
        report = json.loads((backup_dir / "second.json").read_text())
        assert all(t["migrated"] == 0 for t in report["targets"])
        assert sum(t["already_v2"] for t in report["targets"]) > 0
        assert snapshot(stores) == migrated

    def test_undecryptable_row_blocks_without_quarantine(
        self, stores, targets, vault_env, backup_dir
    ):
        seed(stores, broken=True)
        code = run_cli(
            ["migrate", "--run", "--backup-dir", str(backup_dir), "--run-id", "blocked"],
            targets, os.sys.stdout, vault_env,
        )
        assert code == 2
        assert run_cli(["verify"], targets, os.sys.stdout, vault_env) == 2


class TestRotationAfterMigration:
    def test_rotate_reseals_every_target(self, stores, targets, vault_env, backup_dir, monkeypatch):
        seed(stores)
        stores["pg"].table(BOTS_TABLE).pop()
        run_cli(
            ["migrate", "--run", "--backup-dir", str(backup_dir), "--run-id", "pre-rotate"],
            targets, os.sys.stdout, vault_env,
        )
        monkeypatch.setenv("VAULT_MASTER_KEY_v2", base64.b64encode(b"\x88" * 32).decode())

        assert run_cli(
            ["rotate", "--from", "1", "--to", "2"], targets, os.sys.stdout, vault_env
        ) == 0
        assert all(
            read_header(r["ciphertext_db"]).key_id == 2
            for r in stores["pg"].table(VAULT_TABLE)
        )
        assert all(
            read_header(r["mcp_config"]).key_id == 2
            for r in stores["pg"].table(BOTS_TABLE)
        )
        assert read_header(
            base64.b64decode(stores["docdb"]["user_credentials"][0]["credential"])
        ).key_id == 2
        # rotation does not change the naming key, so Redis names stay valid
        ring = KeyRing({**MASTER_KEYS, 2: b"\x88" * 32}, 2)
        assert ring.naming_hmac("sid") == KeyRing(MASTER_KEYS, 1).naming_hmac("sid")
