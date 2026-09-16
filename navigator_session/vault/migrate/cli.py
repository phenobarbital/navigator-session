"""
``navigator-vault`` — operator CLI for the vault migration runbook.

Runbook order (services stopped)::

    navigator-vault list-targets
    navigator-vault migrate --dry-run
    navigator-vault migrate --run --backup-dir /secure/path [--quarantine]
    navigator-vault verify --backup-dir /secure/path/<run_id>
    navigator-vault purge-redis --sessions
    # rollback:  navigator-vault restore --backup-dir /secure/path/<run_id>

Resources:
    database  --dsn, else VAULT_DB_DSN, else DBUSER/DBPWD/DBHOST/DBPORT/DBNAME (navconfig)
    redis     --redis-url, else VAULT_REDIS_URL, else SESSION_URL (navigator-session conf)
    keys      VAULT_MASTER_KEY_v{N}, VAULT_ACTIVE_KEY_ID, VAULT_CIPHER_BACKEND, VAULT_NAMING_KEY_ID

Exit codes:
    0 success · 1 aborted by operator · 2 rows failed / verification failed
    3 usage or configuration error · 4 backup error

Security Note:
    Output lists row refs, counts and error classes only — never values, blobs,
    keys or the database DSN.
"""
import argparse
import asyncio
import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Optional, TextIO

from ..envelope import UnknownKeyVersionError
from ..key_rotation import rotate_master_key
from ..keyring import KeyRing
from ..registry import ENTRY_POINT_GROUP, ProtectedTarget, discover_targets
from .backup import BackupError, JsonlBackupSource
from .models import MigrationReport
from .runner import migrate_v1_to_v2, restore_backup, verify_v2

logger = logging.getLogger("navigator.vault")

EXIT_OK = 0
EXIT_ABORTED = 1
EXIT_FAILURES = 2
EXIT_CONFIG = 3
EXIT_BACKUP = 4

_DB_COMMANDS = {"migrate", "verify", "restore", "rotate", "list-targets"}
_ACTIVITY_SQL = (
    "SELECT max(created_at) AS latest FROM auth.user_vault_audit "
    "WHERE operation IN ('set', 'get', 'delete')"
)

ResourcesFactory = Callable[[argparse.Namespace], Any]  # -> async context manager of dict


class ConfigError(Exception):
    """Invalid CLI usage or missing configuration."""


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the ``navigator-vault`` argument parser."""
    parser = argparse.ArgumentParser(
        prog="navigator-vault",
        description="Navigator Session Vault operations (migration, verification, rotation).",
        epilog=(
            "Runbook: stop services → list-targets → migrate --dry-run → "
            "migrate --run --backup-dir DIR → verify --backup-dir DIR/<run_id> → "
            "purge-redis --sessions → deploy. Rollback: restore --backup-dir DIR/<run_id>."
        ),
    )
    parser.add_argument("--dsn", help="PostgreSQL DSN (default: VAULT_DB_DSN or navconfig DB* keys)")
    parser.add_argument("--redis-url", help="Redis URL (default: VAULT_REDIS_URL or SESSION_URL)")
    parser.add_argument("--report", type=Path, help="Write the JSON report to this file")
    parser.add_argument("--log-level", default="INFO", help="Logging level (default: INFO)")
    sub = parser.add_subparsers(dest="command", required=True)

    migrate = sub.add_parser("migrate", help="Migrate v1 ciphertexts to envelope v2")
    mode = migrate.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Decrypt-only pass, no writes")
    mode.add_argument("--run", action="store_true", help="Export backups and migrate")
    migrate.add_argument("--backup-dir", type=Path, help="Backup directory (required with --run)")
    migrate.add_argument("--quarantine", action="store_true", help="Quarantine rows that cannot be migrated")
    migrate.add_argument("--run-id", help="Run identifier; reuse to resume an interrupted run")
    _add_common(migrate, batch=100)

    verify = sub.add_parser("verify", help="Verify every row opens as envelope v2")
    verify.add_argument("--backup-dir", type=Path, help="Run backup dir whose quarantined rows are excluded")
    _add_common(verify, batch=500)

    restore = sub.add_parser("restore", help="Restore targets from a run backup (rollback)")
    restore.add_argument("--backup-dir", type=Path, required=True, help="Run backup dir (<backup-dir>/<run_id>)")
    restore.add_argument("--yes", action="store_true", help="Do not ask for confirmation")
    _add_common(restore, batch=None)

    rotate = sub.add_parser("rotate", help="Re-seal all targets under a new master key")
    rotate.add_argument("--from", dest="old_key_id", type=int, required=True)
    rotate.add_argument("--to", dest="new_key_id", type=int, required=True)
    _add_common(rotate, batch=100)

    purge = sub.add_parser("purge-redis", help="Delete vault cache keys (and sessions) with SCAN")
    purge.add_argument("--sessions", action="store_true", help="Also delete session:* keys (forces re-login)")
    purge.add_argument("--dry-run", action="store_true", help="Count keys without deleting")
    purge.add_argument("--report", dest="report_cmd", type=Path, default=None,
                       help="Write the JSON report to this file")

    sub.add_parser("list-targets", help="List configured protected targets")
    return parser


def _add_common(parser: argparse.ArgumentParser, *, batch: Optional[int]) -> None:
    parser.add_argument("--target", action="append", dest="targets", metavar="NAME",
                        help="Restrict to a target (repeatable)")
    # Also accepted after the subcommand, which is how the runbook spells it.
    parser.add_argument("--report", dest="report_cmd", type=Path, default=None,
                        help="Write the JSON report to this file")
    if batch is not None:
        parser.add_argument("--batch-size", type=int, default=batch)


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

def resolve_dsn(args: argparse.Namespace) -> str:
    """Resolve the PostgreSQL DSN without ever echoing it.

    Raises:
        ConfigError: If no DSN can be built.
    """
    if args.dsn:
        return args.dsn
    if os.environ.get("VAULT_DB_DSN"):
        return os.environ["VAULT_DB_DSN"]
    from navconfig import config  # pylint: disable=import-outside-toplevel

    host, name = config.get("DBHOST"), config.get("DBNAME")
    if not host or not name:
        raise ConfigError("no database configured: use --dsn, VAULT_DB_DSN or DBHOST/DBNAME")
    user, pwd = config.get("DBUSER", fallback=""), config.get("DBPWD", fallback="")
    port = config.get("DBPORT", fallback="5432")
    return f"postgres://{user}:{pwd}@{host}:{port}/{name}"


def resolve_redis_url(args: argparse.Namespace) -> str:
    """Resolve the Redis URL used by the session store."""
    if args.redis_url:
        return args.redis_url
    if os.environ.get("VAULT_REDIS_URL"):
        return os.environ["VAULT_REDIS_URL"]
    from ...conf import SESSION_URL  # pylint: disable=import-outside-toplevel

    return SESSION_URL


@asynccontextmanager
async def default_resources(args: argparse.Namespace) -> AsyncIterator[dict[str, Any]]:
    """Open the database pool and/or Redis client needed by ``args.command``."""
    resources: dict[str, Any] = {}
    pool = redis = None
    try:
        if args.command in _DB_COMMANDS:
            try:
                import asyncpg  # pylint: disable=import-outside-toplevel
            except ImportError as err:
                raise ConfigError("asyncpg is required for database commands") from err
            try:
                pool = await asyncpg.create_pool(resolve_dsn(args), min_size=1, max_size=4)
            except (OSError, asyncpg.PostgresError) as err:
                raise ConfigError(f"cannot connect to the database: {type(err).__name__}") from err
            resources["db_pool"] = pool
        if args.command == "purge-redis":
            from redis import asyncio as aioredis  # pylint: disable=import-outside-toplevel

            redis = aioredis.from_url(resolve_redis_url(args))
            resources["redis"] = redis
        yield resources
    finally:
        if pool is not None:
            await pool.close()
        if redis is not None:
            await redis.aclose()


def _entry_point_names() -> list[str]:
    return sorted(ep.name for ep in entry_points(group=ENTRY_POINT_GROUP))


def select_targets(
    targets: list[ProtectedTarget], names: Optional[list[str]], *, require_all: bool
) -> list[ProtectedTarget]:
    """Filter targets by ``--target`` names.

    Raises:
        ConfigError: On unknown names, no targets, or (``require_all``) when some
            registered entry points produced no target and no ``--target`` was given.
    """
    by_name = {t.name: t for t in targets}
    if names:
        unknown = sorted(set(names) - set(by_name))
        if unknown:
            raise ConfigError(f"unknown or unconfigured targets: {unknown}; available: {sorted(by_name)}")
        return [by_name[n] for n in names]
    if not targets:
        raise ConfigError("no vault targets configured (check installed packages and resources)")
    registered = _entry_point_names()
    if require_all and len(targets) < len(registered):
        raise ConfigError(
            f"only {len(targets)} of {len(registered)} registered vault targets are configured "
            f"(entry points: {registered}); fix their resources or restrict the run with --target"
        )
    return targets


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _print_report(report: MigrationReport, out: TextIO) -> None:
    columns = ("total", "migrated", "already_v2", "empty", "failed", "quarantined", "restored")
    print(f"{report.operation} run_id={report.run_id} dry_run={report.dry_run}"
          + (f" backup={report.backup_dir}" if report.backup_dir else ""), file=out)
    print("  " + "target".ljust(34) + "".join(c.rjust(12) for c in columns), file=out)
    for t in report.targets:
        print("  " + t.target.ljust(34) + "".join(str(getattr(t, c)).rjust(12) for c in columns), file=out)
        for ref in t.failed_refs:
            print(f"    failed: {ref}", file=out)
    if report.operation == "verify":
        print(f"verified={report.verified}", file=out)


def _write_report(path: Optional[Path], payload: Any) -> None:
    if path is None:
        return
    text = payload.model_dump_json(indent=2) if hasattr(payload, "model_dump_json") else json.dumps(payload, indent=2, default=str)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text + "\n")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

async def _latest_user_activity(pool: Any) -> Any:
    """Latest user-initiated vault audit timestamp, or None if unavailable."""
    try:
        async with pool.acquire() as conn:
            return await conn.fetchval(_ACTIVITY_SQL)
    except Exception:  # noqa: BLE001 - best-effort safety check
        return None


async def purge_redis(redis: Any, patterns: list[str], *, dry_run: bool, count: int = 500) -> dict[str, int]:
    """Delete keys matching ``patterns`` using ``SCAN`` + ``UNLINK`` (never ``KEYS``).

    Returns:
        Number of matching keys per pattern.
    """
    totals: dict[str, int] = {}
    for pattern in patterns:
        total, cursor = 0, 0
        while True:
            cursor, keys = await redis.scan(cursor=cursor, match=pattern, count=count)
            if keys:
                total += len(keys)
                if not dry_run:
                    await redis.unlink(*keys)
            if int(cursor) == 0:
                break
        totals[pattern] = total
    return totals


async def _run(
    args: argparse.Namespace,
    resources_factory: ResourcesFactory,
    discover: Callable[..., list[ProtectedTarget]],
    confirm: Callable[[str], str],
    out: TextIO,
) -> int:
    if args.command == "migrate" and args.run and args.backup_dir is None:
        raise ConfigError("--backup-dir is required with --run")
    if args.command == "migrate" and args.dry_run and args.quarantine:
        raise ConfigError("--quarantine cannot be combined with --dry-run")
    if getattr(args, "batch_size", 1) is not None and getattr(args, "batch_size", 1) < 1:
        raise ConfigError("--batch-size must be >= 1")
    keyring = None
    if args.command in {"migrate", "verify", "rotate"}:
        try:
            keyring = KeyRing.from_env()
        except (RuntimeError, ValueError) as err:
            raise ConfigError(f"vault keys: {err}") from err

    async with resources_factory(args) as resources:
        if args.command == "purge-redis":
            patterns = ["vault:*"] + (["session:*"] if args.sessions else [])
            totals = await purge_redis(resources["redis"], patterns, dry_run=args.dry_run)
            for pattern, total in totals.items():
                verb = "would delete" if args.dry_run else "deleted"
                print(f"{verb} {total} key(s) matching {pattern}", file=out)
            _write_report(args.report, totals)
            return EXIT_OK

        targets = discover(**resources)
        if args.command == "list-targets":
            for target in targets:
                print(target.name, file=out)
            missing = len(_entry_point_names()) - len(targets)
            if missing > 0:
                print(f"({missing} registered target(s) not configured)", file=out)
            return EXIT_OK

        if args.command == "migrate":
            selected = select_targets(targets, args.targets, require_all=args.run)
            pool = resources.get("db_pool")
            before = await _latest_user_activity(pool) if pool is not None and args.run else None
            report = await migrate_v1_to_v2(
                selected, keyring, dry_run=args.dry_run, quarantine=args.quarantine,  # type: ignore[arg-type]
                backup_dir=args.backup_dir, batch_size=args.batch_size, run_id=args.run_id,
            )
            if pool is not None and args.run:
                after = await _latest_user_activity(pool)
                if after is not None and after != before:
                    logger.warning(
                        "Vault writes by other clients were detected during the migration; "
                        "stop all services and re-run with --run-id %s", report.run_id,
                    )
            _print_report(report, out)
            _write_report(args.report, report)
            return EXIT_OK if report.ok else EXIT_FAILURES

        if args.command == "verify":
            selected = select_targets(targets, args.targets, require_all=False)
            exclude = JsonlBackupSource(args.backup_dir).quarantined_refs() if args.backup_dir else set()
            report = await verify_v2(selected, keyring, exclude_refs=exclude, batch_size=args.batch_size)  # type: ignore[arg-type]
            _print_report(report, out)
            _write_report(args.report, report)
            return EXIT_OK if report.verified else EXIT_FAILURES

        if args.command == "restore":
            source = JsonlBackupSource(args.backup_dir)
            if not args.yes:
                answer = confirm(
                    f"Restore run {source.run_id} over current data for {source.targets()}? "
                    f"Type the run id to confirm: "
                )
                if answer.strip() != source.run_id:
                    print("restore aborted", file=out)
                    return EXIT_ABORTED
            report = await restore_backup(targets, args.backup_dir, only=args.targets)
            _print_report(report, out)
            _write_report(args.report, report)
            return EXIT_OK

        if args.command == "rotate":
            selected = select_targets(targets, args.targets, require_all=not args.targets)
            stats = await rotate_master_key(
                selected, args.old_key_id, args.new_key_id, keyring, batch_size=args.batch_size,  # type: ignore[arg-type]
            )
            for name, s in stats.items():
                print(f"  {name}: total={s['total']} rotated={s['rotated']} "
                      f"skipped={s['skipped']} errors={s['errors']}", file=out)
                for ref in s["failed_refs"]:
                    print(f"    failed: {ref}", file=out)
            _write_report(args.report, stats)
            return EXIT_OK if all(s["errors"] == 0 for s in stats.values()) else EXIT_FAILURES

    raise ConfigError(f"unknown command {args.command!r}")  # pragma: no cover


def main(
    argv: Optional[list[str]] = None,
    *,
    resources_factory: ResourcesFactory = default_resources,
    discover: Callable[..., list[ProtectedTarget]] = discover_targets,
    confirm: Callable[[str], str] = input,
    out: TextIO = sys.stdout,
) -> int:
    """Run the CLI and return an exit code.

    Args:
        argv: Arguments (defaults to ``sys.argv[1:]``).
        resources_factory: Async context manager factory yielding resources.
        discover: Target discovery function (``discover_targets``).
        confirm: Prompt function used by ``restore`` without ``--yes``.
        out: Stream for human-readable output.
    """
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse: --help → 0, usage error → 2
        return EXIT_OK if exc.code in (0, None) else EXIT_CONFIG
    # `--report` may appear before or after the subcommand; the later one wins.
    args.report = getattr(args, "report_cmd", None) or args.report
    logging.basicConfig(level=args.log_level.upper(), format="%(levelname)s %(name)s: %(message)s")
    try:
        return asyncio.run(_run(args, resources_factory, discover, confirm, out))
    except BackupError as err:
        logger.error("Backup error: %s", err)
        return EXIT_BACKUP
    except (ConfigError, ValueError, UnknownKeyVersionError) as err:
        logger.error("Configuration error: %s", err)
        return EXIT_CONFIG


def console_entry() -> None:
    """Console script entry point."""
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    console_entry()
