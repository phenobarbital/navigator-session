"""
Offline v1 → v2 migration runner: migrate, verify and restore.

``migrate_v1_to_v2`` (non dry-run), per target:

1. Export every row as stored to the run backup and seal it in the manifest
   **before** the first write (skipped when resuming a complete export).
2. Iterate rows in keyset batches, one transaction per batch. For each
   non-NULL field: keep it if it already opens as v2 with the target context;
   otherwise decrypt it as v1, apply the target's optional ``legacy_unwrap``
   hook, and seal it as v2 under the active key. The row is written once.
3. Rows that cannot be migrated are reported; with ``quarantine=True`` the
   target quarantines them and the manifest records their refs.

A dry run performs step 2 without writing and needs no backup. Re-running with
the same ``run_id`` resumes: migrated rows count as ``already_v2``.

Services must be stopped during the run (see the migration runbook).

Security Note:
    Plaintext exists only in local variables while a row is processed. Never log
    plaintext, blobs or keys; failures are logged by row ref and error class.
"""
import logging
import re
import secrets
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Collection, Optional

from ..envelope import VaultCryptoError, open_sealed, seal
from ..keyring import KeyRing
from ..registry import ProtectedTarget
from .backup import BackupError, JsonlBackupSink, JsonlBackupSource, prepare_backup_dir
from .legacy_v1 import LegacyV1Reader
from .models import MigrationReport, MigrationTargetReport

logger = logging.getLogger("navigator.vault")

RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_V2_FORMAT_BYTE = 0xA2


def new_run_id() -> str:
    """Generate a sortable run id, e.g. ``20260915T211500-1a2b3c4d``."""
    return f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{secrets.token_hex(4)}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _opens_as_v2(blob: bytes, context: Any, keyring: KeyRing) -> bool:
    if not blob or blob[0] != _V2_FORMAT_BYTE:
        return False
    try:
        open_sealed(blob, context, keyring)
        return True
    except VaultCryptoError:
        return False


async def migrate_v1_to_v2(
    targets: list[ProtectedTarget],
    keyring: KeyRing,
    *,
    dry_run: bool,
    quarantine: bool,
    backup_dir: Optional[Path],
    batch_size: int = 100,
    run_id: Optional[str] = None,
    legacy: Optional[LegacyV1Reader] = None,
) -> MigrationReport:
    """Migrate every v1 ciphertext of ``targets`` to envelope v2.

    Args:
        targets: Protected targets to migrate.
        keyring: v2 key ring (new blobs use its active key).
        dry_run: Decrypt-only pass; no writes, no backup.
        quarantine: Quarantine rows that cannot be migrated.
        backup_dir: Directory for the raw backup; required unless ``dry_run``.
        batch_size: Rows per batch/transaction.
        run_id: Run identifier; reuse an existing one to resume.
        legacy: v1 reader; defaults to ``LegacyV1Reader.from_env()``.

    Returns:
        Migration report (``report.ok`` is False when unquarantined failures remain).

    Raises:
        ValueError: On invalid arguments (missing backup dir, bad run id, ...).
        BackupError: If the backup directory is unsafe or an export fails.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be >= 1")
    if dry_run and quarantine:
        raise ValueError("quarantine cannot be combined with dry_run")
    if not dry_run and backup_dir is None:
        raise ValueError("backup_dir is required to run a migration")
    run_id = run_id or new_run_id()
    if not RUN_ID_PATTERN.match(run_id):
        raise ValueError("run_id must be 1-32 characters of [A-Za-z0-9_-]")
    legacy = legacy if legacy is not None else LegacyV1Reader.from_env()

    sink: Optional[JsonlBackupSink] = None
    report = MigrationReport(operation="migrate", run_id=run_id, started_at=_utcnow(), dry_run=dry_run)
    if not dry_run:
        run_dir, resumed = prepare_backup_dir(Path(backup_dir), run_id)  # type: ignore[arg-type]
        sink = JsonlBackupSink(run_dir, run_id)
        report.backup_dir = str(run_dir)
        logger.info("Vault migration run %s %s (backup: %s)", run_id,
                    "resumed" if resumed else "started", run_dir)
    else:
        logger.info("Vault migration dry run %s started", run_id)

    for target in targets:
        result = MigrationTargetReport(target=target.name)
        report.targets.append(result)
        if sink is not None:
            result.backup_records = await _export(target, sink)
        async for batch in target.iter_batches(batch_size):
            async with (nullcontext() if dry_run else target.transaction()):
                for row in batch:
                    result.total += 1
                    await _migrate_row(
                        target, row, keyring, legacy, result,
                        dry_run=dry_run, quarantine=quarantine, run_id=run_id, sink=sink,
                    )
        logger.info(
            "Vault migration %s: total=%d migrated=%d already_v2=%d empty=%d failed=%d quarantined=%d",
            target.name, result.total, result.migrated, result.already_v2, result.empty,
            result.failed, result.quarantined,
        )

    report.finished_at = _utcnow()
    return report


async def _export(target: ProtectedTarget, sink: JsonlBackupSink) -> int:
    if sink.is_complete(target.name):
        count = int(sink.manifest["targets"][target.name]["count"])
        logger.info("Vault migration %s: backup already complete (%d records)", target.name, count)
        return count
    sink.begin(target.name)
    try:
        exported = await target.export_raw(sink)
        sink.finish(target.name, exported)
    except Exception as err:
        sink.abort(target.name)
        raise BackupError(f"backup export of {target.name!r} failed: {type(err).__name__}: {err}") from err
    logger.info("Vault migration %s: exported %d records", target.name, exported)
    return exported


async def _migrate_row(
    target: ProtectedTarget,
    row: Any,
    keyring: KeyRing,
    legacy: LegacyV1Reader,
    result: MigrationTargetReport,
    *,
    dry_run: bool,
    quarantine: bool,
    run_id: str,
    sink: Optional[JsonlBackupSink],
) -> None:
    present = {field: bytes(blob) for field, blob in row.values.items() if blob is not None}
    if not present:
        result.empty += 1
        return

    new_blobs: dict[str, Optional[bytes]] = {}
    try:
        for field, blob in present.items():
            context = target.context_for(row, field)
            if _opens_as_v2(blob, context, keyring):
                continue
            plaintext = legacy.decrypt(blob)
            unwrap = getattr(target, "legacy_unwrap", None)
            if unwrap is not None:
                plaintext = unwrap(field, plaintext, row)
            new_blobs[field] = seal(plaintext, context, keyring)
    except Exception as err:  # noqa: BLE001 - any per-row failure is reported, not fatal
        result.failed += 1
        result.failed_refs.append(row.ref)
        logger.error("Vault migration %s: cannot migrate %s: %s", target.name, row.ref, type(err).__name__)
        if quarantine and not dry_run:
            await target.quarantine(row, type(err).__name__, run_id)
            if sink is not None:
                sink.record_quarantine(target.name, row.ref)
            result.quarantined += 1
        return

    if not new_blobs:
        result.already_v2 += 1
        return
    if not dry_run:
        await target.write(row, new_blobs, keyring.active_key_id)
    result.migrated += 1


async def verify_v2(
    targets: list[ProtectedTarget],
    keyring: KeyRing,
    *,
    exclude_refs: Collection[str] = (),
    batch_size: int = 500,
) -> MigrationReport:
    """Check that every non-NULL field of every row opens as v2 with its context.

    Args:
        targets: Protected targets to verify.
        keyring: v2 key ring.
        exclude_refs: Row refs to skip (e.g. rows quarantined by the migration;
            see ``JsonlBackupSource.quarantined_refs()``).
        batch_size: Rows per read batch.

    Returns:
        Report with ``verified`` True when no row failed.
    """
    report = MigrationReport(operation="verify", started_at=_utcnow(), dry_run=True)
    excluded = set(exclude_refs)
    for target in targets:
        result = MigrationTargetReport(target=target.name)
        report.targets.append(result)
        async for batch in target.iter_batches(batch_size):
            for row in batch:
                result.total += 1
                if row.ref in excluded:
                    result.quarantined += 1
                    continue
                present = {f: bytes(b) for f, b in row.values.items() if b is not None}
                if not present:
                    result.empty += 1
                elif all(_opens_as_v2(b, target.context_for(row, f), keyring) for f, b in present.items()):
                    result.already_v2 += 1
                else:
                    result.failed += 1
                    result.failed_refs.append(row.ref)
    report.verified = all(t.failed == 0 for t in report.targets)
    report.finished_at = _utcnow()
    logger.info("Vault verification %s", "passed" if report.verified else "FAILED")
    return report


async def restore_backup(
    targets: list[ProtectedTarget],
    run_dir: Path,
    *,
    only: Optional[Collection[str]] = None,
) -> MigrationReport:
    """Restore targets from a run backup (rollback).

    Every selected backup file is verified (completeness, count, SHA-256)
    before any row is touched.

    Args:
        targets: Discovered protected targets.
        run_dir: ``<backup_dir>/<run_id>`` directory.
        only: Optional subset of target names to restore.

    Returns:
        Report with ``restored`` counts per target.

    Raises:
        BackupIntegrityError: If the backup does not verify.
        BackupError: If a backed-up target is not among ``targets``.
    """
    source = JsonlBackupSource(Path(run_dir))
    names = [n for n in source.targets() if only is None or n in set(only)]
    by_name = {t.name: t for t in targets}
    missing = [n for n in names if n not in by_name]
    if missing:
        raise BackupError(f"backed-up targets not available for restore: {missing}")
    source.verify(names)

    report = MigrationReport(
        operation="restore", run_id=source.run_id, started_at=_utcnow(), backup_dir=str(run_dir)
    )
    for name in names:
        restored = await by_name[name].restore_raw(source)
        report.targets.append(MigrationTargetReport(target=name, restored=restored))
        logger.info("Vault restore %s: %d records restored", name, restored)
    report.finished_at = _utcnow()
    return report
