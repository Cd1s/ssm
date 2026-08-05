# Agent SSM version compatibility

Run `sshctl --json --version` before inventory, sync, SSH, transfer, update, or
mutation commands. Parse one JSON object with `ok:true` and an exact `version`.
Select only the matching row below. An unsupported major or an unlisted version
must fail closed: do not guess flags, schemas, fields, or publication behavior.

| Installed version | Skill branch | Typed request schema | Changed command/result contracts |
| --- | --- | --- | --- |
| v2.0.1 (current/latest) | v2 compatibility branch | `request-v1.schema.json`; request schema version remains 1 and adds strict `op:get` | Bare push is invalid. `push --all` is limited to the non-empty invocation-start pending set and an empty set never PUTs. Online `--refresh=0` is invalid unless global `--offline` is explicit. Invalid present `cloud.json` returns `sync_config_error`. Direct/request transfer results branch on `direction` and `kind`; directory results explicitly use `atomic:false`, `integrity:not_available`, and `resume:unsupported`. |
| v2.0.0 (supported previous v2 patch) | v2 compatibility branch | `request-v1.schema.json`; request schema version remains 1 and adds strict `op:get` | Same v2 protocol, schema, publication, refresh, sync-config, and transfer-result compatibility behavior as v2.0.1. |
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

An ordinary or automatic v1 update stays in major 1 even though v2.0.1 is the
current/latest Release. On v1.4.4, use `ssm update --major` to review the exact
v2.0.1 candidate and BC-1 through BC-10. Use `ssm update --major --yes` only
after automated preflight and manual consumer checks pass. Authorization never
bypasses the selected digest, exact-tag provenance, or replacement recovery.

After a successful migration, rerun `sshctl --json --version`; enter the v2
compatibility branch only when it returns exact `2.0.0` or `2.0.1`. If it still reports
major 1, reports an unsupported major, or cannot be parsed, stop without
issuing state-aware commands.
