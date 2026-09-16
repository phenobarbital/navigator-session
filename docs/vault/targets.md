# Vault protected targets

A **protected target** describes one store that holds vault ciphertexts. The
same descriptions drive rotation (`navigator-vault rotate`), the v1 → v2
migration (`navigator-vault migrate`) and the backups, so runtime code and the
operator tooling can never disagree about which context a row is sealed with.

## Discovery

Targets are contributed through the entry-point group
`navigator_session.vault_targets`:

```toml
[project.entry-points."navigator_session.vault_targets"]
identity = "navigator_auth.identity.targets:factory"
```

Each entry point is a factory `(resources: Mapping[str, Any]) -> ProtectedTarget | None`
that returns `None` when its resource is missing (for example, no DocumentDB
configured). `discover_targets(**resources)` loads them all, skipping factories
that raise, and rejects duplicate names.

Resources passed by the CLI: `db_pool` (PostgreSQL), `redis`, and whatever a
package needs itself (ai-parrot builds its own DocumentDB handle).

Shipped targets:

| Entry point | Package | Store |
|---|---|---|
| `user_vault` | navigator-session | `auth.user_vault_secrets` |
| `identity` | navigator-auth | `auth.user_identities` |
| `parrot_user_credentials` | ai-parrot | `user_credentials` (DocumentDB) |
| `parrot_user_llm_keys` | ai-parrot | `user_llm_keys` (DocumentDB) |
| `parrot_users_bots` | ai-parrot-server | `<PARROT_SCHEMA>.users_bots` |

## Writing a PostgreSQL target

Subclass `PostgresTarget` and declare the layout; keyset pagination,
transactions, writes, quarantine, export and restore come for free:

```python
from navigator_session.vault.targets.postgres import PostgresTarget

class IdentityTarget(PostgresTarget):
    name = table = "auth.user_identities"
    purpose = "identity"
    pk_column = "identity_id"
    identity_columns = ("user_id", "auth_provider", "provider_user_id")
    encrypted_fields = ("access_token", "refresh_token", "id_token")
    include_field_in_context = True      # appends ("field", <column>)
    key_version_column = "key_version"
    state_columns = ("enabled",)          # exported and restored verbatim
    quarantine_assignments = "enabled = false"

def factory(resources):
    pool = resources.get("db_pool")
    return IdentityTarget(pool) if pool else None
```

Hooks worth knowing:

- `context_value(column, value)` — coerce identity values so runtime and
  migration build the *same* context (e.g. `normalize_user_id`).
- `audit_quarantine(conn, row, reason, run_id)` — write an audit row.
- `legacy_unwrap(field, plaintext, row)` — post-process v1 plaintext during
  migration. `users_bots` uses it to verify the pre-1.0 in-plaintext `_ctx`
  envelope, so a blob that had already been substituted is **not** legitimised
  as a v2 ciphertext.

## Writing a non-PostgreSQL target

Implement the `ProtectedTarget` protocol directly (see ai-parrot's
`DocumentDbTarget`): `context_for`, `iter_batches`, `transaction`, `write`,
`quarantine`, `export_raw`, `restore_raw`. Rules that matter:

- Iterate deterministically and address rows by a stable key.
- `TargetRow.ref` must be printable and secret-free — it is what reports and
  logs show.
- `write` receives the sealed bytes; convert them back to the stored
  representation (base64 for text columns).
- `quarantine` must not modify the ciphertext, so a restore can undo it.
- `restore_raw` must **replace** the stored row, not merge, so fields added by
  the migration do not survive a rollback.
