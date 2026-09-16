# Session Vault — envelope v2 format and key schedule

Applies to navigator-session **1.0.0** and later (FEAT-099). Everything the
vault writes — user secrets, the session cache, identity credentials and the
ai-parrot credential stores — uses this single format.

## Why it changed

The pre-1.0 format had two flaws:

1. **The session-layer key came from non-secret data.** It was
   `HKDF(session_uuid, "vault-session")`, and the session id is the cookie
   value *and* part of the Redis key name — so anyone who could read Redis (or
   a snapshot) held both the ciphertext and its key seed.
2. **No associated data.** Ciphertexts were not bound to a row, so a database
   writer could move one user's secret into another user's row, or swap
   `access_token` with `refresh_token`, and decryption succeeded silently.

Envelope v2 fixes both and additionally records the AEAD algorithm, so
changing `VAULT_CIPHER_BACKEND` no longer makes existing data unreadable.

## Wire format

```
offset  size  field
0       1     format_version   0xA2
1       1     alg_id           0x01 AES-256-GCM · 0x02 ChaCha20-Poly1305
2       2     key_id           uint16 big-endian (master key version)
4       12    nonce            random per write
16      n     ciphertext
16+n    16    tag
```

Minimum length is 32 bytes. The 16-byte header is **authenticated**, so
tampering with `key_id` or `alg_id` fails instead of selecting another key.

DocumentDB stores the same bytes base64-encoded; PostgreSQL `bytea` columns
store them raw.

## Associated data

```
AAD = "NAVVAULT-AAD" ‖ header(16B)
      ‖ lp(purpose) ‖ lp(layer) ‖ u16(field_count)
      ‖ for each (name, value): lp(name) ‖ type_tag(1B) ‖ lp(encoded_value)

lp(x)      4-byte big-endian length prefix + UTF-8 bytes
type_tag   0x00 NULL · 0x01 str · 0x02 int (decimal ASCII) · 0x03 UUID (lowercase)
```

Length-prefixing removes concatenation ambiguity (`("a:b","c")` and
`("a","b:c")` encode differently), and `NULL` is distinct from `""`. Values are
typed: `1`, `"1"` and `UUID(...)` versus its string form all differ, so every
caller must use the same Python type on seal and open — that is what
`normalize_user_id()` guarantees for user ids.

### Registered contexts

| Store | purpose | layer | Fields |
|---|---|---|---|
| `auth.user_vault_secrets` | `user-vault` | `db` | `user_id`, `key` |
| Session cache (memory/Redis) | `user-vault` | `session` | `sid_hmac`, `user_id`, `key` |
| `auth.user_identities` | `identity` | `db` | `user_id`, `auth_provider`, `provider_user_id`, `field` |
| `user_credentials` (DocumentDB) | `parrot-credential` | `db` | `user_id`, `name`, `field` |
| `user_llm_keys` (DocumentDB) | `parrot-llm-key` | `db` | `user_id`, `provider`, `field` |
| `users_bots` | `parrot-user-bot` | `db` | `user_id`, `chatbot_id`, `field` |

## Key schedule

All sub-keys are HKDF-SHA256 (32 bytes) from a master key in the ring:

| Sub-key | IKM | `info` |
|---|---|---|
| DB key | `master_key[key_id]` | `"navigator-vault/v2/db" ‖ alg_id` |
| Session key | `master_key[key_id]` | `"navigator-vault/v2/session" ‖ alg_id ‖ lp(session_uuid)` |
| Naming key | `master_key[naming_key_id]` | `"navigator-vault/v2/naming"` |

The session key therefore needs a master key **and** the session id. The naming
key produces the HMACs used for Redis key names and the audit `session_id`
column, so neither exposes a session id or a secret name.

## Environment

| Variable | Meaning |
|---|---|
| `VAULT_MASTER_KEY_v{N}` | base64 of a 32-byte key; several versions may coexist |
| `VAULT_ACTIVE_KEY_ID` | version used for new writes |
| `VAULT_CIPHER_BACKEND` | `aesgcm` (default) or `chacha20`; only affects new writes |
| `VAULT_NAMING_KEY_ID` | version backing the naming key; defaults to the **lowest** id in the ring |

Generate a key with `python -c "from navigator_session.vault import
generate_master_key; print(generate_master_key())"`.

The naming key id must stay in the ring: removing it changes every Redis key
name, orphaning live caches (the process refuses to start in that case).

## API

```python
from navigator_session.vault import KeyRing, VaultContext, seal_value, open_value

keyring = KeyRing.from_env()
context = VaultContext(
    purpose="user-vault", layer="db",
    fields=(("user_id", 42), ("key", "jira:access_token")),
)
blob = seal_value("token", context, keyring)
assert open_value(blob, context, keyring) == "token"
```

Errors (all subclasses of `VaultCryptoError`, none of them `ValueError`, so a
handler mapping `ValueError → 400` cannot swallow them):

| Error | Meaning |
|---|---|
| `VaultIntegrityError` | Tampered data, or the ciphertext belongs to another row/field |
| `UnknownKeyVersionError` | The referenced master key version is not configured |
| `UnsupportedFormatError` | Not a v2 envelope (legacy v1, truncated, unknown algorithm) |

## Threat model

- Redis contents **plus** a stolen session cookie no longer decrypt anything:
  the master keys are required.
- A database writer cannot move ciphertexts between users, rows or columns.
- Anyone holding the master keys can decrypt everything — protect them, and
  remember that migration backups contain v1 ciphertext readable with those
  same keys.
- Plaintext lives in process memory while in use; a memory dump still exposes
  it. Mitigating that needs an HSM/enclave and is out of scope.
