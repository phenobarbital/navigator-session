"""
Vault Context Registry — protected stores shared by runtime, rotation and migration.

Every store that holds vault ciphertexts is described by a
:class:`ProtectedTarget`: its name, its encrypted fields, how to build the
:class:`~navigator_session.vault.context.VaultContext` for a row/field, and how
to iterate, write, quarantine, export and restore its rows.

Packages contribute targets through the entry-point group
``navigator_session.vault_targets``. Each entry point is a factory::

    def factory(resources: Mapping[str, Any]) -> ProtectedTarget | None

``resources`` carries shared handles (e.g. ``db_pool``, ``redis``,
``docdb_factory``). A factory returns ``None`` when its resource is not
configured, so navigator-session never depends on engines it does not use
(DocumentDB targets live in ai-parrot).

Security Note:
    ``TargetRow.ref`` and backup records must never contain plaintext.
"""
import logging
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field as dc_field
from importlib.metadata import entry_points
from typing import Any, AsyncIterator, Mapping, Optional, Protocol, runtime_checkable

from .context import VaultContext

logger = logging.getLogger("navigator.vault")

ENTRY_POINT_GROUP = "navigator_session.vault_targets"


@dataclass(frozen=True)
class VaultRow:
    """A stored row/document of a protected target.

    Attributes:
        ref: Printable, secret-free identity (e.g. ``"auth.user_vault_secrets:id=..."``).
        pk: Primary key value used to address the row on write/restore.
        identity: Columns used to build the row's contexts (e.g. ``user_id``, ``key``).
        values: Encrypted field name → stored blob (``None`` when the field is NULL).
        key_version: Stored key version column, when the target has one.
        state: Lifecycle columns exported and restored verbatim (e.g. ``deleted_at``).
    """

    ref: str
    pk: Any
    identity: Mapping[str, Any]
    values: Mapping[str, Optional[bytes]]
    key_version: Optional[int] = None
    state: Mapping[str, Any] = dc_field(default_factory=dict)


@runtime_checkable
class TargetRow(Protocol):
    """Minimal row shape consumed by rotation and migration."""

    ref: str
    values: Mapping[str, Optional[bytes]]


class BackupSink(Protocol):
    """Destination for raw (as-stored) target records before migration."""

    async def write(self, target: str, record: Mapping[str, Any]) -> None:
        """Persist one JSON-serializable record for ``target``."""
        ...


class BackupSource(Protocol):
    """Source of raw records previously written to a :class:`BackupSink`."""

    def read(self, target: str) -> AsyncIterator[Mapping[str, Any]]:
        """Iterate the records stored for ``target``."""
        ...


@runtime_checkable
class ProtectedTarget(Protocol):
    """A store holding vault ciphertexts.

    Targets may additionally implement
    ``legacy_unwrap(field: str, plaintext: bytes, row: TargetRow) -> bytes``
    to post-process legacy v1 plaintext during migration (e.g. verify and
    strip an in-plaintext context envelope).
    """

    name: str
    encrypted_fields: tuple[str, ...]

    def context_for(self, row: TargetRow, field: str) -> VaultContext:
        """Build the context binding ``field`` of ``row``."""
        ...

    def iter_batches(self, batch_size: int) -> AsyncIterator[list[TargetRow]]:
        """Iterate all rows (including soft-deleted ones) in deterministic batches."""
        ...

    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Group writes/quarantines into one transaction."""
        ...

    async def write(
        self, row: TargetRow, blobs: Mapping[str, Optional[bytes]], key_version: int
    ) -> None:
        """Replace the stored blobs of ``row`` and record ``key_version``."""
        ...

    async def quarantine(self, row: TargetRow, reason: str, run_id: str) -> None:
        """Remove ``row`` from runtime reads without modifying its blobs."""
        ...

    async def export_raw(self, sink: BackupSink) -> int:
        """Export every row as stored; return the number of records."""
        ...

    async def restore_raw(self, source: BackupSource) -> int:
        """Restore rows from an export; return the number of records."""
        ...


TargetFactory = Any  # Callable[[Mapping[str, Any]], Optional[ProtectedTarget]]


def discover_targets(**resources: Any) -> list[ProtectedTarget]:
    """Load protected targets registered under ``navigator_session.vault_targets``.

    Args:
        **resources: Shared handles passed to every factory (``db_pool``, ``redis``, ...).

    Returns:
        Targets in entry-point name order. Factories that raise are logged and
        skipped; factories returning ``None`` (resource not configured) are skipped.

    Raises:
        ValueError: If two targets share the same ``name``.
    """
    targets: list[ProtectedTarget] = []
    seen: dict[str, str] = {}
    for ep in sorted(entry_points(group=ENTRY_POINT_GROUP), key=lambda e: e.name):
        try:
            factory = ep.load()
            target = factory(resources)
        except Exception as err:  # noqa: BLE001 - one broken plugin must not block the rest
            logger.warning(
                "Vault target entry point %r failed to load: %s: %s",
                ep.name, type(err).__name__, err,
            )
            continue
        if target is None:
            logger.debug("Vault target entry point %r not configured; skipped", ep.name)
            continue
        if not isinstance(target, ProtectedTarget):
            logger.warning(
                "Vault target entry point %r returned %s, not a ProtectedTarget; skipped",
                ep.name, type(target).__name__,
            )
            continue
        if target.name in seen:
            raise ValueError(
                f"Duplicate vault target name {target.name!r} from entry points "
                f"{seen[target.name]!r} and {ep.name!r}"
            )
        seen[target.name] = ep.name
        targets.append(target)
    logger.debug("Discovered vault targets: %s", [t.name for t in targets])
    return targets
