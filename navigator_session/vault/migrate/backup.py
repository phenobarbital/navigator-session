"""
Raw pre-migration backups: one JSONL file per target plus a manifest.

Layout::

    <backup_dir>/<run_id>/manifest.json
    <backup_dir>/<run_id>/<sanitized target name>.jsonl

Records are produced by ``ProtectedTarget.export_raw`` and contain stored blobs
(base64) and row identity only — never plaintext. Files are created ``0600``
inside a ``0700`` run directory; the parent backup directory must not be
world-accessible. The manifest stores per-target record counts, SHA-256 of the
file, completion state and the refs quarantined by the run, and is rewritten
atomically.

Security Note:
    Backups hold v1 ciphertext that remains decryptable with the current master
    keys. Store them securely and delete them after the rollback period.
"""
import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Mapping, Optional, TextIO

from ...version import __version__

MANIFEST_NAME = "manifest.json"
MANIFEST_FORMAT = "navigator-vault-backup/1"
_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]")


class BackupError(RuntimeError):
    """The backup directory or export cannot be used safely."""


class BackupIntegrityError(BackupError):
    """A backup file is missing, incomplete or does not match its manifest."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def target_filename(target: str) -> str:
    """Return the JSONL file name used for a target."""
    return _UNSAFE.sub("_", target) + ".jsonl"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_backup_dir(backup_dir: Path, run_id: str) -> tuple[Path, bool]:
    """Validate the backup directory and create or reopen the run directory.

    Args:
        backup_dir: Operator-provided directory (created ``0700`` if missing).
        run_id: Run identifier; the run directory is ``backup_dir / run_id``.

    Returns:
        ``(run_dir, resumed)`` — ``resumed`` is True when a manifest for this
        run already exists.

    Raises:
        BackupError: If the directory is world-accessible, not a directory,
            not writable, or the run directory exists without a manifest and
            is not empty.
    """
    backup_dir = Path(backup_dir)
    try:
        backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as err:
        raise BackupError(f"cannot create backup directory {backup_dir}: {err}") from err
    if not backup_dir.is_dir():
        raise BackupError(f"backup path {backup_dir} is not a directory")
    mode = stat.S_IMODE(backup_dir.stat().st_mode)
    if mode & 0o007:
        raise BackupError(
            f"backup directory {backup_dir} is accessible by other users "
            f"(mode {mode:o}); use a directory with no 'other' permissions"
        )
    if not os.access(backup_dir, os.W_OK | os.X_OK):
        raise BackupError(f"backup directory {backup_dir} is not writable")

    run_dir = backup_dir / run_id
    if (run_dir / MANIFEST_NAME).is_file():
        return run_dir, True
    if run_dir.exists() and any(run_dir.iterdir()):
        raise BackupError(f"run directory {run_dir} exists, is not empty and has no manifest")
    run_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(run_dir, 0o700)
    return run_dir, False


class JsonlBackupSink:
    """Writes raw target records and maintains the run manifest.

    Args:
        run_dir: Directory returned by :func:`prepare_backup_dir`.
        run_id: Run identifier recorded in the manifest.
    """

    def __init__(self, run_dir: Path, run_id: str) -> None:
        self.run_dir = Path(run_dir)
        self._manifest_path = self.run_dir / MANIFEST_NAME
        if self._manifest_path.is_file():
            self.manifest = json.loads(self._manifest_path.read_text())
            if self.manifest.get("run_id") != run_id:
                raise BackupError(
                    f"manifest in {self.run_dir} belongs to run {self.manifest.get('run_id')!r}"
                )
        else:
            self.manifest = {
                "format": MANIFEST_FORMAT,
                "run_id": run_id,
                "created_at": _now(),
                "navigator_session_version": __version__,
                "targets": {},
            }
            self._save_manifest()
        self._handles: dict[str, TextIO] = {}
        self._counts: dict[str, int] = {}

    def is_complete(self, target: str) -> bool:
        """True when ``target`` was fully exported in this run."""
        return bool(self.manifest["targets"].get(target, {}).get("complete"))

    def begin(self, target: str) -> None:
        """Start (or restart) the export of ``target``, truncating its file."""
        path = self.run_dir / target_filename(target)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.chmod(path, 0o600)
        self._handles[target] = os.fdopen(fd, "w", encoding="utf-8")
        self._counts[target] = 0
        entry = self.manifest["targets"].setdefault(target, {})
        entry.update(
            file=path.name, complete=False, count=0, sha256=None,
            started_at=_now(), finished_at=None,
        )
        entry.setdefault("quarantined_refs", [])
        self._save_manifest()

    async def write(self, target: str, record: Mapping[str, Any]) -> None:
        """Append one record (``BackupSink`` protocol)."""
        handle = self._handles.get(target)
        if handle is None:
            raise BackupError(f"export of {target!r} was not started")
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        self._counts[target] += 1

    def finish(self, target: str, exported: int) -> None:
        """Flush, fsync and seal ``target`` in the manifest.

        Raises:
            BackupError: If the number of written records differs from ``exported``.
        """
        handle = self._handles.pop(target)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        written = self._counts.pop(target)
        if written != exported:
            raise BackupError(
                f"export of {target!r} wrote {written} records but reported {exported}"
            )
        path = self.run_dir / target_filename(target)
        entry = self.manifest["targets"][target]
        entry.update(count=written, sha256=_sha256(path), complete=True, finished_at=_now())
        self._save_manifest()

    def abort(self, target: str) -> None:
        """Close an unfinished export without marking it complete."""
        handle = self._handles.pop(target, None)
        self._counts.pop(target, None)
        if handle is not None:
            handle.close()

    def record_quarantine(self, target: str, ref: str) -> None:
        """Remember a quarantined row so ``verify`` can exclude it."""
        entry = self.manifest["targets"].setdefault(target, {"quarantined_refs": []})
        refs = entry.setdefault("quarantined_refs", [])
        if ref not in refs:
            refs.append(ref)
        self._save_manifest()

    def _save_manifest(self) -> None:
        tmp = self._manifest_path.with_suffix(".json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(self.manifest, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self._manifest_path)
        os.chmod(self._manifest_path, 0o600)


class JsonlBackupSource:
    """Reads a run backup (``BackupSource`` protocol).

    Args:
        run_dir: ``<backup_dir>/<run_id>`` directory containing ``manifest.json``.

    Raises:
        BackupIntegrityError: If the manifest is missing or unreadable.
    """

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir)
        manifest_path = self.run_dir / MANIFEST_NAME
        try:
            self.manifest = json.loads(manifest_path.read_text())
        except (OSError, ValueError) as err:
            raise BackupIntegrityError(f"cannot read backup manifest {manifest_path}: {err}") from err
        if self.manifest.get("format") != MANIFEST_FORMAT:
            raise BackupIntegrityError(f"unsupported backup format {self.manifest.get('format')!r}")

    @property
    def run_id(self) -> str:
        return str(self.manifest["run_id"])

    def targets(self) -> list[str]:
        """Targets with a complete export."""
        return sorted(t for t, e in self.manifest["targets"].items() if e.get("complete"))

    def quarantined_refs(self) -> set[str]:
        """All row refs quarantined by the run."""
        return {
            ref for entry in self.manifest["targets"].values()
            for ref in entry.get("quarantined_refs", [])
        }

    def verify(self, targets: Optional[list[str]] = None) -> None:
        """Check completeness, record counts and SHA-256 of the given targets.

        Raises:
            BackupIntegrityError: On any mismatch.
        """
        for target in targets if targets is not None else list(self.manifest["targets"]):
            entry = self.manifest["targets"].get(target)
            if not entry or not entry.get("complete"):
                raise BackupIntegrityError(f"backup of {target!r} is missing or incomplete")
            path = self.run_dir / entry["file"]
            if not path.is_file():
                raise BackupIntegrityError(f"backup file {path} is missing")
            if _sha256(path) != entry["sha256"]:
                raise BackupIntegrityError(f"backup file {path} does not match its checksum")
            with path.open("rb") as handle:
                lines = sum(1 for _ in handle)
            if lines != entry["count"]:
                raise BackupIntegrityError(f"backup file {path} has {lines} records, expected {entry['count']}")

    async def read(self, target: str) -> AsyncIterator[Mapping[str, Any]]:
        """Yield the records of ``target``."""
        entry = self.manifest["targets"].get(target)
        if not entry or not entry.get("complete"):
            raise BackupIntegrityError(f"backup of {target!r} is missing or incomplete")
        with (self.run_dir / entry["file"]).open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    yield json.loads(line)
