# SSM host management and guarded bulk import

Use typed `sshctl request` host operations or first-class `sshctl host` commands for single-host changes on SSM 1.4 and later. `import-json` remains a migration/bulk-replacement interface, not the normal agent CRUD path.

## Unlock behavior

`sshctl` reads the vault passphrase from `SSM_MASTER_PASS_FILE` or, by default, `~/.config/ssm/master.pass`. For `ssm`, pass the file globally:

```bash
ssm --master-pass-file ~/.config/ssm/master.pass host list --json
```

Never put the master passphrase in argv or output.

## Inventory

```bash
sshctl host list --json
sshctl host show <exact-alias> --json
```

Host JSON includes address, port, user, group, auth type, and saved key name. It never includes password or private-key material.

## Retry-safe add/upsert

Private key:

```bash
stat -c 'key_file=%n mode=%a size=%s' /secure/new-server.key
sshctl host upsert new-server \
  --host 203.0.113.10 --port 22 --user root --group prod \
  --key-file /secure/new-server.key --verify --json
```

Password:

```bash
sshctl host upsert new-server \
  --host 203.0.113.10 --port 22 --user root \
  --password-file /secure/new-server.password --verify --json
```

Existing saved key:

```bash
sshctl host upsert new-server \
  --host 203.0.113.10 --port 22 --user root \
  --key deploy-key --verify --json
```

Rules:

- New aliases match `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`.
- Host is a hostname or unbracketed IP, without `user@`, URL scheme, path, or whitespace.
- Port is 1-65535; default is 22.
- New hosts require exactly one auth source.
- `--key-file` validates an unencrypted SSH private key before saving it in the encrypted vault.
- No password or private-key value is accepted inline.
- Repeating the same upsert returns `action:"unchanged"` and does not duplicate entries or keys.

When a default key name already contains different material, SSM fails with `key_conflict` instead of overwriting it. Choose a distinct encrypted-vault name:

```bash
sshctl host upsert new-server \
  --host 203.0.113.10 --user root \
  --key-file /secure/new-server.key --key-name new-server-2026 --verify --json
```

## Partial update

Only provided fields change:

```bash
sshctl host update existing-server --host 203.0.113.20 --port 2222 --verify --json
sshctl host update existing-server --group= --verify --json
```

Omitting auth preserves it. Supplying a new auth source switches auth atomically:

```bash
sshctl host update existing-server --key-file /secure/replacement.key --verify --json
sshctl host update existing-server --password-file /secure/replacement.password --verify --json
```

SSM refuses to overwrite a key shared by another host. Use `--key-name` to create a separate saved key.

## Verify, then push

Host mutations require a successful remote refresh. With `--verify` (the request default), the candidate is checked before saving; failure returns `applied:false` and leaves the encrypted vault unchanged. They intentionally do not use silent auto-push. A refresh failure returns `sync_pull_failed`; use `--offline` only when stale local state is explicitly acceptable.

```bash
sshctl host show <alias> --json
sshctl check <alias> --json
sshctl run <alias> --json --argv hostname
sshctl run <alias> --json --argv uname -sr
sshctl --json status
sshctl --json push --only <transaction-id>
```

Use the mutation result's exact `transaction_id`; do not push when verification fails. Bare push is invalid and is rejected before vault unlock or any sync HTTP request. Choose `push --only <transaction-id>`, or use `push --all` only after deliberately reviewing every mutation in the invocation-start pending-ID set. Later transactions remain pending.

An empty invocation-start set never publishes the full local blob. `push --all` compares the exact local encrypted-blob identity, last confirmed remote identity, and current remote identity with one HEAD request. Identical identities return `action:"noop"` with no GET or PUT; a missing or different identity returns `error:"sync_conflict"`, `stage:"sync_compare"`, preserves both sides and private identity evidence, and also performs no GET or PUT.

### Empty-ledger divergence recovery

Retrying `push --all` cannot repair this conflict.

The emitted machine hint is merge-only and does not authorize replacement:

```text
review sshctl --offline --json doctor and preserve the local vault and sync-conflict.json; run sshctl --json pull to adopt remote, then use guarded ssm --offline --json import-json <reviewed-file> --merge and publish its reviewed transaction with sshctl --json push --only <transaction-id>
```

1. Run `sshctl --offline --json doctor` and review the safe `sync_conflict` identities.
2. Preserve private copies of the local encrypted vault, `remote.etag`, and `sync-conflict.json`; keep their permissions private.
3. Prepare the local inventory that must survive as a reviewed import file. Keep secrets in that private file, never in command arguments or logs.
4. Run `sshctl --json pull` to adopt the reviewed remote encrypted blob. If the cached prerequisite does not make replacement safe and pull reports another conflict, stop and retain all evidence for manual repair.
5. If the remote version wins completely, stop. Otherwise, reapply retained local inventory with exactly one guarded command:

   ```bash
   ssm --offline --json import-json <reviewed-file> --merge
   ```

   Or, only after explicit full-replacement review:

   ```bash
   ssm --offline --json import-json <reviewed-file> --replace --yes
   ```

6. Review the returned transaction and publish only that ID:

   ```bash
   sshctl --json push --only <transaction-id>
   ```

There is no force flag, automatic repair, evidence deletion, or empty-ledger overwrite path.

## Remove

After authorization for the exact alias:

```bash
sshctl host remove <alias> --yes --prune-key --json
sshctl host list --json
sshctl --json push --only <removal-transaction-id>
```

`--prune-key` removes only a key with zero remaining host references. Without it, keys are retained.

## Temporary test lifecycle

```bash
alias='zz-ssm-skill-test-demo'

sshctl host upsert "$alias" \
  --host 203.0.113.50 --user root \
  --key-file /secure/test.key --json
sshctl check "$alias" --json

sshctl host remove "$alias" --yes --prune-key --json
sshctl host list --json
```

Push only if the user wants the temporary lifecycle reflected remotely. If add and remove occur before any push, the final vault may already match remote state.

## Guarded legacy bulk import

Use `import-json` only for a reviewed migration. For a one-entry compatibility import, `--merge` and `--expect-count 1` are mandatory:

```bash
ssm --master-pass-file ~/.config/ssm/master.pass \
  import-json /secure/host.json --merge --expect-count 1
```

Accepted shapes are an array, `{ "servers": [...] }`, `{ "servers": { "alias": {...} } }`, or a raw alias map. Supported auth fields include `password`, `private_key`, `private_key_path`, and `key_path`.

Important boundaries:

- Bare `ssm import-json file.json` is rejected. The caller must choose `--merge` or explicitly authorize full replacement with `--replace --yes`.
- Inline secrets in JSON can leak through temp files or logs; path-based material is safer.
- Import merge resolves conflicts by connection/key name, with imported values winning.
- Import does not provide the field-preserving update and key-sharing guards of `sshctl host`.
