---
name: agent-ssm
description: "Use Cd1s/ssm for non-interactive SSH inventory, execution, transfers, and troubleshooting through an encrypted vault. Trigger for sshctl/ssm work, exact host aliases, request files, scoped pushes, host-key verification, or secret-safe remote automation."
metadata:
  hermes:
    tags: [ssh, ssm, servers, vault, automation]
---

# Agent SSM

This is the official skill for the current GitHub latest `ssm`/`sshctl` v2.0.2
binary. It also supports v2.1.0 (not GitHub latest until a separate
promotion) and the previous v2.0.1 and v2.0.0 patches in the v2
compatibility branch and contains a deliberately separate compatibility branch
for the supported v1.4.3/v1.4.4 binaries. Read the [version compatibility reference](references/version-compatibility.md),
[v1→v2 migration guide](../../docs/migration-v1-to-v2.md), and
[update-provenance runbook](../../docs/update-provenance-runbook.md) before a
cross-major rollout.

Fresh installations use the current GitHub latest Release:

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
```

## Start here: identify the exact binary first

Run the read-only version probe before inventory, sync, SSH, transfers, updates,
or mutations:

```bash
command -v sshctl
sshctl --json --version
```

Parse one JSON object with `ok:true` and an exact `version`, then select exactly
one branch:

| Exact version | Skill branch | Request schema |
| --- | --- | --- |
| v2.1.0 (supported; not latest until promoted) | v2 compatibility branch | `references/request-v1.schema.json` |
| **v2.0.2 (current/latest)** | v2 compatibility branch | `references/request-v1.schema.json` |
| v2.0.1 (supported previous v2 patch) | v2 compatibility branch | `references/request-v1.schema.json` |
| v2.0.0 (supported earlier v2 patch) | v2 compatibility branch | `references/request-v1.schema.json` |
| v1.4.3 / v1.4.4 | v1 compatibility branch | `references/request-v1-bridge.schema.json` |

Request schema version remains 1 in both branches. The v2 schema adds strict
`op:get`; the v1 bridge does not. An unlisted version or unsupported major must
fail closed: do not guess flags, fields, schemas, or publication behavior, and
do not issue state-aware commands. Use the [exact-tag skill deployment procedure](references/install-update.md)
to install a matching official skill.

After selecting the branch, begin safe discovery:

```bash
sshctl --help
sshctl <command> --help
sshctl --json status
sshctl --json host list
```

Use exact aliases. Search and suggestions return candidates only; never select
one automatically. Normal `--json` commands emit one JSON value, while explicit
`run --stream` emits one NDJSON value per input line. Classify results with
`ok`, `error`, and `stage`; a remote program may exit 255, so `exit` alone does
not prove SSH transport failure.

## Choose the smallest safe operation

- Fixed, reviewed literal argv: `sshctl --json run <exact-alias> --argv <command> [args...]`.
  Remote argv boundary: after the alias, `--argv`, `--`, or the first non-option word starts the remote command; everything after it (`-h`, `--help`, `--json`, ...) reaches the remote program untouched. Put sshctl options such as `--json`, `--timeout`, or `--help` before that boundary. The same holds for `exec`, `plan`, `map`, and script arguments after `--`.
- Local stdin: `--stdin` forwards it in every mode including `--json` (`printf 'a\n' | sshctl --json run <exact-alias> --stdin --argv cat`), `--no-stdin` never forwards (like `ssh -n`), and `--stdin-file <path>` is `< path` (request v1 `stdin_file`). Without them, human mode forwards a non-terminal stdin directly and `--json` does not; an unforwarded piped stdin adds `stdin_forwarded:false` plus a `warning` to the JSON result, and forwarding adds `stdin_forwarded:true`. `SSM_FORWARD_STDIN=1` forwards by default (including `--json`), `SSM_FORWARD_STDIN=0` equals `--no-stdin`, and explicit flags win. `-s`, `-f`, `--scripts`, `map`, and `run --stream` reject `--stdin`/`--stdin-file` with `invalid_arguments`. A default human run whose stdin is a never-ending pipe (common when CI or an agent inherits stdin) waits forever if the remote command reads stdin: add `--no-stdin` or `</dev/null`. In `while read` loops always pass `--no-stdin` (or `</dev/null`) so a call does not consume the loop's input.
- Repeated simple argv on one exact alias: keep `sshctl run <exact-alias> --stream` open and send one JSON string array per line. Online streams require a positive --refresh interval (30s by default); `--refresh=0` is valid only with explicit global `--offline`. Inspect every NDJSON result. In the default local_first mode sync failures never stop the stream; in `sync_mode: strict` a refresh failure is terminal.
- When a host is rebooting or a route is transient, use `sshctl wait <exact-alias> [--timeout 5m] [--interval 5s]` instead of an external sleep loop (`--interval` at least 1s, exponential backoff with jitter). `--until tcp` checks only TCP reachability; the default `ssh` makes one real SSH connection per attempt (no separate banner-only probe, which sshd logs as a pre-auth failure). `wait` never retries authentication or host-key failures: `auth_failed`, `host_key_*`, missing credentials and alias errors stop it immediately with the real error (fail2ban bans repeated failed logins); only `dial_*` and handshake failures before the server host key arrives keep it waiting (a drop or timeout after key exchange, possibly mid-authentication, is reported, never retried), and a timeout is `wait_timeout` with the last cause. Through a `proxy_jump` alias the rule is per hop: a transport failure before the failing hop's own host key arrived (target behind the jump down or refusing) keeps waiting and only re-logs in to earlier hops successfully; an auth failure at any hop or any failure after a hop's host key arrived is never retried; `--until tcp` is rejected for jump aliases. `--until cmd:` is not implemented.
- Dynamic, untrusted, or data-dependent argv: use request schema version 1 with `op:"run"` and the schema selected above.
- Shell syntax or a generated script: use `script_file` with optional `script_args` and `shell`; use preflight where supported.
- Non-shell script (Python, Perl, Ruby): `sshctl --json run <exact-alias> -f script.py --interpreter python3 -- args...` or request `script_file` plus `interpreter`. The script still travels over stdin and runs as `<interpreter> - args...`. `interpreter` is one program name, an absolute path, or `env <name>`; without it a non-shell shebang returns `invalid_arguments`. `preflight` is shell-only and is rejected with a non-shell interpreter.
- Secrets: use `secret_files` or credential file options. Values are paths, never secret contents.
- Host changes: use typed `host.add|host.update|host.upsert|host.remove`; verify first, then publish only a changed result's exact `transaction_id`.
- Regular-file upload: use typed `put`; add `resume:"v1"` only when requested and `sha256:true` when integrity verification is required. Auto-created parent directories default to 0755; use `dir_mode` (or `--dir-mode`) to override (an octal mode of at most 0777 that keeps owner write and execute, i.e. includes 0300; 0500 or 0644 are rejected before connecting).
- Download: v1 uses direct `sshctl get`; v2 may use direct get or request schema v1 `op:"get"` (`sha256`, `timeout`, `transfer` allowed; no `resume`). Direct get accepts `--json`, `--timeout`, `--sha256`, `--sftp` in any position.
- Target without a POSIX shell (Windows OpenSSH, appliances, SFTP-only accounts): when `put`/`get` return `remote_shell_unsupported`, retry the single file with `--sftp` (or `transfer:"sftp"` in the request; request `shell`/`sftp` override the host setting for that operation, `auto` or omitted keeps it), or set the host once with `host update <alias> --transfer sftp` (`host.transfer` in a host request). Never switch protocol silently; never send directories or `resume` over SFTP.
- Host behind a bastion: set `host update <alias> --proxy-jump <jump-alias>` (`host.proxy_jump` in a host request; empty clears; chains up to 5 jump hosts, no cycles). Everything (`run`, `map`, `put`, `get`, `cp`, `check`, `doctor`, `host-key`) then works on the target alias. Each hop verifies its own host key locally and authenticates with its own credentials; nothing is forwarded. A failure names the failing hop in `via` (jump alias or the target itself): fix or trust that alias, not the target. `host-key inspect|accept <target>` handles the target's key only; trust every jump alias first. Older clients (v2.0.2 and earlier) ignore `proxy_jump` and drop it when they re-save the synced vault, so upgrade every client before using it; each target behind a jump opens its own jump connection. `proxy_jump_invalid` (exit 2, `stage:validate`) means a missing alias, a cycle, or more than 5 jump hosts and nothing was dialed.
- Copy a file between two hosts: `sshctl cp <alias-a>:<path> <alias-b>:<path> [--timeout 5m] [--json]` (`--timeout` bounds the probe and transfer after connecting; identical alias and path is refused) streams one regular file through this machine (no local disk). It publishes on B only after the source digest, the locally computed digest, and B's digest all agree and leaves no partial file on B; the JSON result carries `source_sha256`, `local_sha256`, `destination_sha256`, `bytes`, `route:"local_relay"`. Both hosts need a POSIX shell plus `sha256sum`/`shasum`/`openssl`; directories return `unsupported_transfer_option`. `--direct` (A pushing to B) is intentionally unavailable: it would put B's credentials on A or forward the local agent to A, so anyone controlling A could reach B; adding it needs an explicit user decision, so never work around it with a hand-made `ssh` from A.
- Fleet work: use `sshctl map` with explicit argv or scripts and inspect every result.
- Large or long-running output (byte pipes, logs, archives): use human-mode `sshctl run <exact-alias> --argv ...`, which streams without a size limit and exits with the remote exit status; `--json` holds the whole output in memory. Streamed stdout is byte-exact; streamed stderr masks explicit `--secret` values as `***`; a local SIGINT/SIGTERM is forwarded to the remote command and exits with `error:interrupted`.
- If a field or flag is uncertain, run the relevant command help or read the selected schema. Never guess.

When a typed request is required, create JSON with a file-writing API and run:

```bash
sshctl request --file ./ssm-request.json
```

`argv`, `script_file`, and compatibility-only `shell_command` are mutually
exclusive. Prefer `argv` for literal arguments and `script_file` for shell
semantics; `shell_command` has quoting and expansion risk.

## Inventory and publication

State-changing successful mutations return a stable `transaction_id`. An
idempotent update/upsert may instead return `changed:false`,
`action:"unchanged"`, and omit `transaction_id`; it creates no transaction, so
do not publish that no-op.

Review the secret-free pending list, then publish one reviewed change with:

```bash
sshctl --json push --only <transaction-id>
```

Bare `push` is invalid in v2 and must not be relied on in v1. Use
`sshctl --json push --all` only after explicit review of every mutation in the
non-empty pending set. In v2, that set is fixed at invocation start; later
transactions remain pending. An empty `--all` scope never publishes a full
local blob: identical local/cached/remote identities return `action:"noop"`,
while missing or divergent identities return `error:"sync_conflict"` and
preserve both sides. Follow [guarded empty-ledger recovery](references/import-json.md)
for pull, reviewed `--merge`, and a new scoped transaction.

Sync is local-first by default: read commands use the local inventory, never
wait for the sync service, and start a detached background sync when one is due.
Decide whether the inventory can be trusted from `sshctl --json status`, not
from a command failure: `remote_state` (`checked`, `unreachable`, `not_checked`,
`not_configured`, `auto_sync_disabled`), `last_successful_sync`,
`last_sync_error` (`cause`, redacted `message`, `at`), `next_sync_attempt`,
`cache_age_seconds`, and `inventory_stale`. `run` JSON results carry
`inventory_stale:true` when the cache is older than `stale_after` (7 days by
default). Do not add `--offline` to work around an unreachable service; local
reads already work. `--offline` is deprecated for reads (accepted for
compatibility) and now only suppresses background sync, as does
`SSM_OFFLINE=1`. `run` JSON results add `inventory_unsynced:true` (sync configured
but never confirmed) and `inventory_sync_error:"<cause>"` (the most recent sync
attempt failed) so an agent can see it without calling `status`; human mode does
not warn about a failed attempt. In `strict` mode and for explicit `sync`/`pull`
a concurrent local writer can cause a "vault is busy" failure (retry), and
`pull --adopt-remote <sha256> --yes` is refused if the local vault changed after
the conflict evidence was recorded (re-check the conflict). When `remote_state` is `unreachable` or `inventory_stale` is
true, tell the caller before relying on host details that may have changed;
run `sshctl --json sync` to force a strict pull. Explicit `sync`, `pull`, and
`push` stay strict, and setting `sync_mode: strict` (or `SSM_SYNC_MODE=strict`)
restores refresh-before-read, where `sync_pull_failed` fails the command and
must not be bypassed silently. `ssm login` fetches the inventory once right after authenticating (the explicit
`sync` path); run `sshctl sync` only if its stderr warned that the initial pull
failed. Sync failures carry
a stable top-level `cause` (also `cause=` in human output, and in
`last_sync_error`); branch on it:
`auth` (HTTP 401/403) and `missing_token` need a human to run `ssm login`,
so do not retry and do not add `--offline`; `tls` needs a human to inspect the
certificate, never bypass verification; `dns`, `connect_refused`, `timeout`,
`http_5xx`, and `network` may be retried later; `unknown` is unclassified.
`message` includes the redacted underlying error. `cloud.json` is a
path to local configuration, never a value to print or copy into a request.

## Host keys

On `host_key_unknown`, `host_key_mismatch`, or `host_key_type_changed`:

1. Run `sshctl host-key inspect <exact-alias> --json`.
2. Verify the complete `observed_fingerprint` through a trusted channel.
3. With authorization, accept that exact fingerprint using `--fingerprint ... --yes --json`.

`host_key_mismatch` is a changed key of a recorded type; `host_key_type_changed` (inspect status `type_changed`) means the server no longer offers any recorded key type. Accept replaces only the same-type entry. Read `observed_fingerprint` from the top level of the inspect document, also on failure.

Never delete/rescan automatically, accept a changed key blindly, or send
credentials before verification.

## Transfer and result contracts

In the v2 compatibility branch, branch on `direction` (`put`/`get`) and `kind`
(`file`/`directory`). Directory put/get explicitly report
`atomic:false`, `integrity:not_available`, and `resume:unsupported`; directory
get omits `bytes_received`. File get reports `bytes_received`,
`atomic:true`, `integrity:not_checked`, and `resume:unsupported`. Do not infer
guarantees from `action` or an omitted field. The v1 branch must not assume
these v2 fields or request `op:get`.

`--sha256` needs `sha256sum`, `shasum`, or `openssl` on the remote host; when
none exists the error is `integrity_tool_unavailable` (stage `capability`), so
retry without `--sha256` rather than treating it as a permission failure. A
directory put whose remote tar fails reports `stage:remote_extract` with the
remote message; the destination may be partially written and no per-file retry
happens (the per-file fallback runs only when local `tar` is missing).
Directory get rejects `--sha256` and never hangs when the local extractor
exits early.

SFTP mode (`--sftp`, request `transfer:"sftp"`, or a host with `transfer: sftp`;
`auto|shell|sftp`, default `auto`) covers single regular files only and runs no
remote command. Directories and `resume` fail with `unsupported_transfer_option`;
a server without the subsystem fails with `sftp_unavailable`. Its guarantees
differ from the shell path, so read the result fields: get is staged locally and
published atomically, and `--sha256` hashes the received stream against the
server-reported size and the staged file (there is no remote digest command);
put writes a temporary sibling and renames it, reports `atomic:true` only when
the server has `posix-rename@openssh.com` (otherwise `atomic:false`), and with
`--sha256` reads the temporary file back over SFTP (`integrity_tool_unavailable`
(stage `capability`) with `integrity:not_available` when the server refuses; nothing is published).
A destination directory is rejected untouched. A timed-out SFTP put may leave a
`.ssm-upload.*` temp file; the failure message names it if cleanup failed.
In the default shell mode `get` returns `remote_shell_unsupported` (stage
`discovery`) when the path probe output is unparseable, the shell errors, or exec
is refused; `put` returns it only when exec is refused.

`cp` (host to host, issue #86) reads the source with the `get` path and writes
the destination with the `put` temporary-file-plus-rename script, relaying the
bytes in memory through this machine. The destination refuses to publish unless
its digest of the temporary file equals the source host's digest, and the copy
succeeds only when the source digest, the relayed bytes' digest, and the
destination digest are equal (`integrity:"sha256_verified"`); a mismatch is
`integrity_failed`/`integrity:"mismatch"` and leaves the previous destination
intact. A missing SHA-256 tool on either host is `integrity_tool_unavailable`
(`stage:capability`). Only single regular files and shell-mode hosts are
supported; the source mode is kept when it has `stat`, otherwise `0600`.

ProxyJump (`proxy_jump`, issue #86): the failure field `via` is additive and
present only for jumped connections; it never replaces `error`, `stage`, or
`exit`. Handshake and dial deadlines of the connect timeout apply to every hop,
and a stalled tunnelled handshake is `handshake_failed` with `via` set.

Resume is regular-file-only and must be explicitly enabled with `--resume=v1`.
Incompatible, corrupt, or ambiguous state returns a classified partial-state
error and never replaces the destination. See [import and recovery guidance](references/import-json.md)
for the related guarded recovery rules.

## Exit codes

In `--json` mode decide by the `error` field, not the exit code: a remote program can exit with any code, and pipes such as `2>&1 | tail` lose it.

| Exit | Meaning |
|---|---|
| 0 | Success. |
| 1 | An sshctl failure that is not an SSH transport failure: `internal`, vault, sync and update errors, every `host` and `host-key` subcommand failure (including `alias_not_found` there), `script_syntax_error`, and `put`/`get` transfer errors (`remote_write_failed`, `transfer_timeout`, `integrity_failed`, `partial_state_*`, `local_read_failed`); or a remote command that exited 1. Read `error`. |
| 2 | Invalid arguments or request (`invalid_arguments`, `invalid_request`), or a remote command that exited 2. |
| 124 | `--exec-timeout` expired in `run` or `map` (`exec_timeout`): SIGTERM was sent and the session closed after a grace period. Same status as GNU `timeout`; a remote command can also exit 124, so read `error`. |
| 127 | The remote script interpreter is missing (`interpreter_not_found`), or a remote command that exited 127. |
| 128 + signal | A local SIGINT/SIGTERM/SIGHUP stopped `run` (`interrupted`; 130, 143, 129). The signal was forwarded and the remote command may still be running. |
| 255 | An SSH transport failure in `run`, `map`, `check`, `doctor`, `put`, or `get`: `dial_timeout`, `dial_refused`, `dial_network`, `handshake_failed`, `host_key_unknown`/`host_key_mismatch`/`host_key_type_changed` (the connection was refused), `auth_failed`, `no_auth_configured`, `session_failed`, `session_limit`, `connection_lost`; also `alias_not_found` from `run`, `map`, `check`, and `doctor`. A remote command can also exit 255. |
| any other | The remote command's own exit status, passed through unchanged. |

`map` exits with the first failed result's exit code; every result carries its own `error`. A `put`/`get` whose connection breaks midway is `connection_lost` with exit 255, like `run`, because it is a transport failure rather than a transfer-specific error.

**Contract change.** A `put`/`get` whose connection breaks midway used to report `remote_write_failed` (or `remote_read_failed` for a download) with exit 1. It now reports `connection_lost` with exit 255 and `outcome:"unknown"`. sshctl's own `--timeout` abort of a file or directory `get`, or of a file `put`, is unchanged: `transfer_timeout`, exit 1, no `outcome`. The `host` subcommands' `alias_not_found` has JSON `exit` 255 but process exit 1; decide by `error`.

Whether a retry is safe depends on whether the command was sent:

`--retry-dial N[:backoff]` (N at most 10, exponential backoff with jitter)
retries only pre-command `dial_*` and `handshake_failed` failures that happen
before the server host key arrives (never a drop or timeout during
authentication), and reports
`dial_attempts` when given or when a retry happened; it never retries
`auth_failed`, `host_key_*`, a command after `connection_lost`, or anything
after the session is open.

- Safe to retry: `dial_timeout`, `dial_refused`, `dial_network`, and `handshake_failed` (`stage:handshake`: TCP connected but the SSH handshake failed, for example EOF, connection reset, or a protocol error, and no command was sent), and `session_failed` or `session_limit` at `stage:session` when the session could not be opened, because the command was never sent. `session_limit` means the server's per-connection session cap (sshd `MaxSessions`) stayed full: sshctl backs off for a free slot within the connection timeout without closing the shared connection or interrupting running sessions, and returns this only when none frees; lower `-j` or raise sshd `MaxSessions`. A deterministic handshake failure such as `no common algorithm` fails the same way every time, so retrying is pointless; fix the algorithm or server configuration instead. `auth_failed` and `host_key_*` keep their own codes and need a fix, not a retry.
- Do not retry blindly: `exec_timeout` (`stage:remote_execution`, with `timed_out:true`). The command ran until `--exec-timeout`; the remote process may still be running after SIGTERM and the session close. Check the host first.
- Not safe to retry: `connection_lost` (`stage:remote_execution`, plus `outcome:"unknown"`). The connection dropped after the command was sent, for example when the host rebooted or `sysupgrade` ran, so the remote command may still be running or may have finished. Check the process state on the host first.

`outcome` is an additive field that appears only on `connection_lost`.

## Timeouts and keepalive (releases after v2.0.2)

Check `sshctl --help` for `--exec-timeout` before relying on these; v2.0.2 and older only have `--timeout`.

- `--connect-timeout <duration>`: TCP connect plus SSH handshake (default 15s). Expiry is `handshake_failed` (`stage:handshake`, safe to retry) or `dial_timeout` if TCP never connected. `SSM_CONNECT_TIMEOUT` is the environment form.
- Deprecated `--timeout <duration>` on `run`/`exec`/`plan`/`map` (and `run --stream`): compatible alias of `--connect-timeout` (both set one value, the last on the command line wins, and either beats an inherited `SSM_CONNECT_TIMEOUT`/`SSM_TIMEOUT`). It is a connection timeout, not an execution timeout; older agents used it as an execution limit and it never was one.
- `--exec-timeout <duration>` (also `map`, `run --stream`, and `exec_timeout` in request v1 run/plan): the command's run limit. SIGTERM at the deadline, session closed after a 5s grace period, result `exec_timeout` with exit 124 (even if the command traps TERM and exits 0 once SIGTERM was sent), `timed_out:true`, and the `stdout`/`stderr` received so far. Use it instead of wrapping sshctl in an outer `timeout`, which loses buffered output.
- `put`/`get` `--timeout`: the file-transfer timeout (`transfer_timeout`), unchanged.
- Keepalive: `keepalive@openssh.com` every 15s, connection closed after 3 unanswered probes (a running command then fails as `connection_lost`). `SSM_KEEPALIVE=0` disables it, an unparseable value falls back to 15s; `SSM_KEEPALIVE=<duration>` sets the interval.

## Failure rules

- `alias_not_found`: list/search and ask for an exact alias if needed; never execute a suggestion.
- `unknown_command` (exit 2): the first word is not a sshctl subcommand or existing alias; follow the `hint` (for example an ssm-only command such as `keys`, or a near-miss like `stauts` -> `status`) and never treat the word as an alias.
- `invalid_arguments` from `run|exec|plan|map` with an unknown option: the `hint` suggests the real option (`--script-file` -> `-f`, `--fetch` -> `get`); fix the option, do not guess more.
- `sync_push_failed`: preserve the verified pending mutation and retry the same scoped transaction ID.
- `dial_*|auth_failed`: diagnose network or credentials, not quoting.
- `handshake_failed` (`stage:handshake`): no command was sent, so retrying is safe, except deterministic failures such as `no common algorithm`, which need a configuration fix. `session_failed` and `session_limit` at `stage:session` (session could not be opened) are also safe to retry; for `session_limit` lower `-j` or raise sshd `MaxSessions`.
- `exec_timeout` (`stage:remote_execution`, `timed_out:true`, exit 124): `--exec-timeout` expired; received output is in the result; the remote process may still be running, so check the host before rerunning, then raise `--exec-timeout` or move long work to the background on the host.
- `connection_lost` (`stage:remote_execution`, `outcome:"unknown"`): the command was sent and may still be running or may have finished; check the process state on the host first; retrying is not safe.
- `remote_failed|remote_script_failed`: transport succeeded; preserve remote exit and structured stderr.
- `interpreter_not_found|script_syntax_error`: correct interpreter or syntax before execution.
- `transfer_timeout|partial_state_*|integrity_failed`: do not publish or append ambiguous data.
- Unknown categories: run `sshctl --json doctor <exact-alias> --deep` after the version branch is selected.

## Environment variables and connection reuse

`SSM_CONNECT_TIMEOUT` is the environment form of `--connect-timeout`; `SSM_TIMEOUT` is its deprecated compatibility alias (ranked below it) and
`SSM_DIAL_TIMEOUT` an older name read last. All three bound TCP connect plus SSH handshake only.
`SSM_REUSE=0|off|false|no` disables the process-local connection pool;
`status` reports `reuse_scope=process`, and no connection is reused across
processes. `SSM_FORWARD_STDIN=1|0` controls default stdin forwarding,
`SSM_RUN_OUTPUT=buffered` restores buffered output, `SSM_CONFIG_DIR` selects
the config directory, and `SSM_MASTER_PASS_FILE` points to a protected file (same as the global `--master-pass-file <path>`).
`SSM_TRACE=1` is the same as `--trace`/`-v`: the redacted remote command (and
script digest) is written to stderr before running. `SSM_UPDATE_REPO=<owner/repo>|off`
chooses the GitHub repository `ssm update` reads releases from (default
`Cd1s/ssm`; for tests and forks; it ranks above the `update_repo` config file and
`settings.json` key, and `off` disables updates). It does not bypass the SHA-256
or provenance checks, and provenance stays pinned to the `Cd1s/ssm` release
workflow identity, so another repository's release cannot be installed without a
credential issued for `Cd1s/ssm`; it only decides where versions are looked up, so
set it in trusted environments only and never to install third-party builds.

## Option reference

`run`/`exec`/`plan`/`map` options (before the remote-command boundary):

- `--argv`: the rest is the literal remote argv. `--raw`: join words with single spaces, no quoting, remote shell parsing (compatibility only; not with `--argv` or script options).
- `--plan`/`--dry-run`: show `remote_command` and risk without connecting or running (`plan` is `run --plan`).
- `-j`/`--jobs`/`--parallel <n>`: `map` worker count (default 8); a single-host `run` ignores it.
- `--trace`/`-v`: same as `SSM_TRACE=1`. `--no-reuse`: no connection pool for this call (`SSM_REUSE=0`).
- Scripts: `-f`/`--file <path>` (repeatable) and `--scripts a.sh,b.sh` read local files, `-s`/`--script` reads the script from local stdin; `--shell <name>` or `--interpreter <program>` picks the runner; `--preflight` checks shell syntax first and `--no-preflight` turns it off again (the last one wins).
- `--secret`/`-e NAME=@file`: set `NAME` in the remote environment from a file (`NAME=value` works but exposes the value on the command line; output is redacted).
- `--retry-dial N[:backoff]`: pre-command dial retries; rules are in the failure-retry notes above (`dial_attempts`).
- `--stream` with `--refresh <duration>`: the long-lived argv stream of `run <alias> --stream`.

Other commands:

- Global: `--json`, `--offline` (deprecated for reads), `--master-pass-file <path>`, `--version`.
- `host add|update|upsert`: `--host`, `--port`, `--user`, `--group`, `--transfer auto|shell|sftp`, `--proxy-jump <alias>`, exactly one of `--key <name>`, `--key-file <path>` (with optional `--key-name <name>`), or `--password-file <path>`, plus `--verify` (verify before saving; a failed verification saves nothing) and `--push` (requires `--verify`). `host search --filter <query>` replaces the positional query; `host remove` needs `--yes` and optionally `--prune-key`.
- `import-json <path>`: `--merge` or `--replace --yes`, `--manifest <path>` (aliases for entries that have none), `--expect-count <n>` (fail unless the file yields exactly n hosts; 0 disables the check).
- `wait <alias>`: `--timeout`, `--interval`, `--until ssh|tcp`; see "Choose the smallest safe operation".
- Sync service (human-run, not for agents): `ssm login`/`register` take `--server`, `--email`, `--password-file`; `ssm server` takes `--listen` and `--data-dir`.

## Updates and rollback

The current v2.0.2 is GitHub latest. Same-major automatic/manual updates remain
the default. A v1.4.3/v1.4.4 ordinary update remains in major 1 even though
v2.0.2 is current/latest. Review a cross-major candidate with:

```bash
ssm update --major
```

Only after the migration guide's automated and manual checks pass may the caller
explicitly authorize the cross-major update:

```bash
ssm update --major --yes
```

The authorization flag never bypasses pinned digest or keyless provenance
verification. Rerun `sshctl --json --version` after replacement and enter the
v2 branch only on exact `2.0.0`, `2.0.1`, `2.0.2`, or `2.1.0`. Preserve the old executable, encrypted vault,
pending ledger, `publishing-intent.json`, and recovery evidence until exact
identities are reconciled.

## Hard boundaries

- Never print or read aloud `master.pass`, `cloud.json`, private keys, tokens, passwords, decrypted vault data, or secret-file contents.
- Never put credentials in argv, JSON values, logs, Issues, or commits; only protected file paths may be referenced.
- Never use bare `ssh`/`sshpass`, a TUI, an interactive shell, or terminal prompts for normal remote administration.
- Never guess aliases, repair host keys automatically, silently go offline, or publish unrelated transactions.
- Never continue on an unparseable version, an unlisted version, or an unsupported major; fail closed before state-aware commands.
- Do not claim success without checking the structured result and the requested postcondition.
