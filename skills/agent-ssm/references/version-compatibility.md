# Agent SSM version compatibility

Run `sshctl --json --version` before inventory, sync, SSH, transfer, update, or
mutation commands. Parse one JSON object with `ok:true` and an exact `version`.
Select only the matching row below. An unsupported major or an unlisted version
must fail closed: do not guess flags, schemas, fields, or publication behavior.

| Installed version | Skill branch | Typed request schema | Changed command/result contracts |
| --- | --- | --- | --- |
| v2.3.0 (supported; not latest until promoted) | v2 compatibility branch | `request-v1.schema.json`; request schema version remains 1 with `op:get` and additive fields (see `RELEASE_NOTES.md`) | Vault format v2 with authenticated monotonic generation; upgrade all clients before saving or publishing; conditional sync publication and the additive behavior changes in the v2.2.0 notes |
| v2.2.0 (current/latest) | v2 compatibility branch | `request-v1.schema.json`; request schema version remains 1 with `op:get` as in v2.0.x plus additive fields (see `RELEASE_NOTES.md`) | Additive request/result fields and flags; defaults change (local-first inventory reads, streaming human `run` output, handshake-covering `--connect-timeout`, SSH keepalive) and some error codes change (`internal` becomes `connection_lost`/`handshake_failed`, and so on). See `RELEASE_NOTES.md` for the compatibility switches (`sync_mode: strict`, `SSM_RUN_OUTPUT=buffered`, `SSM_KEEPALIVE=0`). |
| v2.1.0 (supported previous v2 patch) | v2 compatibility branch | `request-v1.schema.json`; request schema version remains 1 with `op:get` plus additive fields (see `RELEASE_NOTES.md`) | The v2.1.0 defaults and error-code compatibility switches described in `RELEASE_NOTES.md`. |
| v2.0.2 (supported previous v2 patch) | v2 compatibility branch | `request-v1.schema.json`; request schema version remains 1 and adds strict `op:get` | Bare push is invalid. `push --all` is limited to the non-empty invocation-start pending set and an empty set never PUTs. Online `--refresh=0` is invalid unless global `--offline` is explicit. Invalid present `cloud.json` returns `sync_config_error`. Direct/request transfer results branch on `direction` and `kind`; directory results explicitly use `atomic:false`, `integrity:not_available`, and `resume:unsupported`. |
| v2.0.1 (supported previous v2 patch) | v2 compatibility branch | `request-v1.schema.json`; request schema version remains 1 and adds strict `op:get` | Same v2 protocol, schema, publication, refresh, sync-config, and transfer-result compatibility behavior as v2.0.2. |
| v2.0.0 (supported earlier v2 patch) | v2 compatibility branch | `request-v1.schema.json`; request schema version remains 1 and adds strict `op:get` | Same v2 protocol, schema, publication, refresh, sync-config, and transfer-result compatibility behavior as v2.0.2. |
| v1.4.3 / v1.4.4 | v1 compatibility branch | `request-v1-bridge.schema.json`; request schema version remains 1 and has no `op:get` | Prefer explicit `push --only` or deliberately reviewed `push --all` even though historical bare-push compatibility may exist. Use direct `sshctl get`; do not assume v2 transfer `direction`/`kind` parity, v2 directory guarantees, fatal-invalid-`cloud.json` behavior, or the v2 online `--refresh=0` rejection. Keep online refresh positive and avoid legacy auto-publishing mutation entry points. |

## Common safe subset

- Exact aliases only; never auto-select suggestions.
- Use `sshctl --json run <alias> --argv ...` for reviewed literals and a
  file-backed request for dynamic argv or scripts.
- Use typed host mutations, require verification, and publish only a changed
  result's exact `transaction_id` with `push --only`.
- Never use bare push. Use `push --all` only after explicit review of the
  non-empty pending set, regardless of whether a v1 binary still accepts a
  historical bare form.
- Keep online streams on a positive refresh interval in both branches. Never
  silently switch to offline inventory.
- Preserve the executable, encrypted state, pending IDs, publication intent,
  and recovery evidence after any ambiguous failure.

## Explicit major migration

An ordinary or automatic v1 update stays in major 1 even though v2.2.0 is the
current/latest Release. The prepared v2.3.0 remains non-latest until
published-asset canaries pass and a separate promotion. On v1.4.4, use
`ssm update --major` to review the exact v2.3.0 candidate and BC-1 through
BC-10. Use `ssm update --major --yes` only
after automated preflight and manual consumer checks pass. Authorization never
bypasses the selected digest, exact-tag provenance, or replacement recovery.

After a successful migration, rerun `sshctl --json --version`; enter the v2
compatibility branch only when it returns exact `2.0.0`, `2.0.1`, `2.0.2`, `2.1.0`, or `2.2.0`, or `2.3.0`. If it still reports
major 1, reports an unsupported major, or cannot be parsed, stop without
issuing state-aware commands.
