"""Offline v1 → v2 vault migration.

Intentionally does **not** re-export the legacy v1 reader: v1 decryption exists
only inside :mod:`navigator_session.vault.migrate.legacy_v1` and is used solely
by the runner.
"""
from .backup import BackupError, BackupIntegrityError, JsonlBackupSink, JsonlBackupSource
from .models import MigrationReport, MigrationTargetReport
from .runner import migrate_v1_to_v2, new_run_id, restore_backup, verify_v2

__all__ = [
    "BackupError",
    "BackupIntegrityError",
    "JsonlBackupSink",
    "JsonlBackupSource",
    "MigrationReport",
    "MigrationTargetReport",
    "migrate_v1_to_v2",
    "new_run_id",
    "restore_backup",
    "verify_v2",
]
