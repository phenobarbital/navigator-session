1.0.0 (2026-09-16)
==================

BREAKING: Session Vault envelope v2 (FEAT-099). Vault data written by 0.10.x
cannot be read by this release and must be migrated offline with the new
``navigator-vault`` CLI; see ``docs/vault/migration-runbook.md``.

- Session-layer keys are derived from a master key **and** the session id, so
  Redis contents plus a session cookie no longer decrypt anything.
- Every ciphertext is bound through AEAD associated data to its purpose, row
  and field: a blob moved between users, rows or columns fails authentication.
- The envelope records format version, algorithm id and key id, so changing
  ``VAULT_CIPHER_BACKEND`` no longer makes existing data unreadable.
- Redis key names and the ``user_vault_audit.session_id`` column store HMACs
  instead of raw session ids; vault key names may now contain ``:``.
- New ``KeyRing``, ``VaultContext``, ``seal``/``open_sealed`` API; the v1
  ``encrypt_for_db``/``decrypt_for_db``/``encrypt_for_session``/
  ``decrypt_for_session`` helpers were removed.
- Protected targets are registered through the ``navigator_session.vault_targets``
  entry-point group and drive rotation, migration and backups.
- ``rotate_master_key(targets, old, new, keyring)`` re-seals every registered
  target; ``SessionVault.set()`` returns metadata and ``list_metadata()`` was
  added.
- New ``navigator-vault`` CLI: ``migrate`` (dry-run/run with mandatory backup,
  resumable, optional quarantine), ``verify``, ``restore``, ``rotate``,
  ``purge-redis`` and ``list-targets``.
- New ``VAULT_NAMING_KEY_ID`` setting (defaults to the lowest key id).

0.0.5 (2022-08-02)
==================

- Removing dependency of navigator.conf

0.0.3 (2022-08-02)
==================

- Code migrated from Navigator API
- Added basic support for Cookie Storage
- Migrated Redis storage to aioredis > 2.x

0.0.1 (2022-08-02)
==================

- First public release
