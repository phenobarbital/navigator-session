"""Migration, verification and restore reports (never contain secrets)."""
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


class MigrationTargetReport(BaseModel):
    """Per-target outcome.

    Attributes:
        target: Target name.
        total: Rows visited.
        migrated: Rows re-sealed as v2 (or that would be, in a dry run).
        already_v2: Rows whose every non-NULL field already opens as v2.
        empty: Rows with no encrypted value (all fields NULL).
        failed: Rows that could not be migrated/verified.
        quarantined: Failed rows quarantined by this run.
        restored: Rows restored from a backup.
        backup_records: Records exported to the backup for this target.
        failed_refs: Secret-free references of failed rows.
    """

    target: str
    total: int = 0
    migrated: int = 0
    already_v2: int = 0
    empty: int = 0
    failed: int = 0
    quarantined: int = 0
    restored: int = 0
    backup_records: Optional[int] = None
    failed_refs: list[str] = Field(default_factory=list)


class MigrationReport(BaseModel):
    """Outcome of a migrate / verify / restore operation.

    Attributes:
        operation: Which operation produced the report.
        run_id: Migration run identifier (backup subdirectory name).
        started_at: UTC start time.
        finished_at: UTC end time (``None`` while running).
        dry_run: True when no data was written.
        backup_dir: Run backup directory, when one was used.
        targets: Per-target results.
        verified: For ``verify``: every non-quarantined row opens as v2.
    """

    operation: Literal["migrate", "verify", "restore"]
    run_id: Optional[str] = None
    started_at: datetime
    finished_at: Optional[datetime] = None
    dry_run: bool = False
    backup_dir: Optional[str] = None
    targets: list[MigrationTargetReport] = Field(default_factory=list)
    verified: bool = False

    @property
    def ok(self) -> bool:
        """True when every failed row was quarantined (or there were no failures)."""
        return all(t.failed == t.quarantined for t in self.targets)
