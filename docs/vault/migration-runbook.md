# Vault v1 → v2 migration runbook (FEAT-099)

One offline maintenance window converts every vault ciphertext to envelope v2.
Old code cannot read v2 and new code rejects v1, so **all four packages deploy
together** and every session is invalidated.

Scheduling the window is an ops decision. Measure the duration with a rehearsal
on a production-sized copy first and record it in the table at the end.

## Before the window

1. Rehearse on a copy of production data and note the duration.
2. Prepare the secure backup directory (no access for other users):
   ```bash
   install -d -m 700 /secure/vault-backups
   ```
   It will hold **v1 ciphertext**, which the current master keys still decrypt.
   Treat it like the master keys, and delete it once the rollback window closes.
3. Confirm the vault environment on the migration host: `VAULT_MASTER_KEY_v{N}`,
   `VAULT_ACTIVE_KEY_ID`, `VAULT_CIPHER_BACKEND`, and `VAULT_NAMING_KEY_ID` if
   you pin it (see [format.md](format.md)).

## Window

### 1. Stop every vault reader and writer

navigator-auth apps, ai-parrot servers and workers, Telegram/CLI resolvers.
The migration assumes nothing else writes; the CLI warns if it detects vault
audit activity during the run.

### 2. Install the new versions on the migration host

navigator-session 1.0.0, navigator-auth 0.28.0, ai-parrot and
ai-parrot-server. Entry points from every installed package must be visible:

```bash
navigator-vault list-targets
```

Expect: `auth.user_vault_secrets`, `auth.user_identities`,
`docdb:user_credentials`, `docdb:user_llm_keys`, `<schema>.users_bots`.
A missing target means its package or its resource (DB pool, DocumentDB) is not
configured — fix that before migrating, or the run refuses to start.

### 3. Apply the schema migrations

Starting navigator-auth applies them automatically; to do it explicitly, run
its startup once, or apply `navigator_auth/vault/sql/002_vault_crypto_hardening.sql`
and `navigator_auth/identity/sql/003_identity_key_version_integer.sql`. They widen
`session_id` to 64 chars, allow the `quarantine` / `integrity_fail` audit
operations and turn key-version columns into `INTEGER`. Each statement is
conditional, so re-running takes no locks.

**This must happen before `migrate --run`**: quarantine rows cannot be audited
otherwise.

### 4. Dry run

```bash
navigator-vault migrate --dry-run --report /tmp/vault-dry-run.json
```

Decrypts everything, writes nothing. Review the report: `failed` should be `0`.
Any failure is a row whose v1 ciphertext cannot be read (tampered, wrong key
version, or a key no longer configured) — investigate before continuing, or
plan to quarantine it in step 5.

### 5. Migrate

```bash
navigator-vault migrate --run \
  --backup-dir /secure/vault-backups \
  --report /secure/vault-backups/migrate.json \
  [--quarantine]
```

For every target, the CLI first exports each row **as stored** to
`<backup-dir>/<run_id>/<target>.jsonl` plus a manifest with counts and SHA-256,
and only then rewrites rows, one transaction per batch. Note the `run_id` — it
names the backup directory and identifies the run.

`--quarantine` removes rows that cannot be migrated from runtime reads
(PostgreSQL: soft-delete / `enabled = false`; DocumentDB: moved to
`<collection>_quarantine`) and records their refs in the manifest. Without it,
a failure leaves the row untouched and the command exits `2`.

Exit codes: `0` ok · `1` aborted · `2` rows failed · `3` usage/configuration ·
`4` backup problem.

If the run is interrupted, re-run the **same** command with
`--run-id <run_id>`: the export is not repeated and already-migrated rows count
as `already_v2`.

### 6. Verify

```bash
navigator-vault verify --backup-dir /secure/vault-backups/<run_id>
```

Passing `--backup-dir` excludes the rows quarantined by that run (they keep
their v1 ciphertext by design). The report must end with `verified=true`.

### 7. Purge Redis (forces re-login)

```bash
navigator-vault purge-redis --sessions --dry-run   # count first
navigator-vault purge-redis --sessions
```

Deletes `vault:*` (v1 and v2 cache entries) and `session:*` using `SCAN` +
`UNLINK`. The `user:*` identity index is left alone: those entries point at
deleted sessions and are ignored on the next login.

### 8. Deploy and start

Deploy navigator-session 1.0.0, navigator-auth 0.28.0, ai-parrot,
ai-parrot-server and navigator-frontend-next **together**, then start the
services.

### 9. Smoke test

- Log in — the login page shows *"Your session has ended because of a security
  update. Please sign in again."*
- `/profile/secrets`: list, create, replace and delete a secret.
- A call that uses a linked identity (token refresh path).
- A BYOK-backed agent call.
- The integrations panel: providers show `Connected`, not `Needs reconnect`.
- A Telegram/CLI flow that stores tokens (`VaultTokenSync`).

## Rollback

Within the backup retention window:

```bash
# stop services again
navigator-vault restore --backup-dir /secure/vault-backups/<run_id>
# redeploy the previous package versions
```

`restore` verifies every backup file (completeness, record count, SHA-256)
before touching a row, replaces the stored rows byte-for-byte and removes
quarantine copies. v2 data is unreadable by the old code, so the restore must
finish before the old versions start.

## After the window

- Keep the backup directory only as long as you may roll back, then delete it
  (it contains decryptable v1 ciphertext).
- Watch for `integrity_fail` audit rows in `auth.user_vault_audit`: they mean a
  stored secret failed authentication at load time.
- Rotation is now a routine job: `navigator-vault rotate --from N --to M`
  re-seals every registered target.

## Recorded run durations

| Date | Environment | Rows (all targets) | migrate --run | verify | Notes |
|---|---|---|---|---|---|
| 2026-09-16 | Development rehearsal (`tests/integration/test_vault_migration_e2e.py`, in-memory stores) | 6 | 0.05 s | 0.01 s | Correctness rehearsal of the whole sequence; no database round-trips |
| 2026-09-16 | Same host, crypto only (50 000 synthetic rows) | 50 000 | 1.63 s (33 µs/row) | 0.48 s (10 µs/row) | v1 decrypt + v2 seal, single core, AES-GCM |
| _fill in from your production-sized rehearsal_ | | | | | |

The crypto is not the bottleneck: at ~30 000 rows/s per core, even a million
secrets convert in under a minute of CPU. Plan the window around the database —
the export pass, one `UPDATE` per row batched per transaction, and the backup
directory's write throughput — which is why step 1 of "Before the window" asks
for a rehearsal on a production-sized copy.
