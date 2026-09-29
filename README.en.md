# ssm

## The one-minute explanation

`ssm` is a non-interactive SSH management tool for agents, scripts, and automation. It helps you keep host records, check connections, run commands, and transfer files without opening a TUI, an interactive shell, or a prompt on the remote machine. It is a good fit when SSH work needs to be safe and repeatable.

`ssm` and `sshctl` are the same binary under two command names. The installer normally creates `/usr/local/bin/ssm` and `/usr/local/bin/sshctl -> /usr/local/bin/ssm`; the examples below use the agent-oriented `sshctl` name.

Passwords and private keys are never printed. The master passphrase is read from the local `~/.config/ssm/master.pass` by default; host passwords, private keys, and host records live in the local encrypted vault. When adding or changing a host, pass only restricted file paths such as `--password-file` or `--key-file`; never put secret values in commands, JSON, logs, or commits.

If sync is enabled, the sync server sees only encrypted vault blobs. It cannot see the decrypted host inventory, SSH passwords, or private keys; the actual SSH connection always starts from the current machine.

[中文](README.md) | [English](README.en.md)

## Current release: v2.0.2

The current GitHub latest Release is **v2.0.2**, so the one-line fresh install below gets v2.0.2. Existing v1.4.3/v1.4.4 users stay on major 1 when they run ordinary `ssm update`; only an explicitly reviewed `ssm update --major --yes` crosses to v2. See the [v1→v2 migration guide](docs/migration-v1-to-v2.md) for migration details and the [update-provenance runbook](docs/update-provenance-runbook.md) for source and attestation checks.

## 3-minute quick start

Run these in order. In the last command, replace `my-server` with the **complete alias** shown by the host list; do not guess from a similar name.

### 1. Install

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
```

### 2. Verify the version

```bash
sshctl --json --version
```

The version field should be `2.0.1`. If `sshctl` is not found, reopen the terminal or check that `/usr/local/bin` is on `PATH`.

### 3. Check status

```bash
sshctl --json status
```

This reports whether sync is configured, whether the state is fresh, and whether local changes are pending publication. If sync is not configured, the result says so explicitly. In the default local-first mode it also reports the outcome of the last sync and the cache age (`remote_state`, `last_sync_error`, `cache_age_seconds`, `inventory_stale`) and does not fail when the sync endpoint is unreachable; see "Sync modes".

### 4. List hosts

```bash
sshctl --json host list
```

Copy the exact alias you want, such as your own `my-server`. Search returns candidates only and never selects or connects automatically:

```bash
sshctl host search my --json
```

### 5. Run hostname on one exact alias

```bash
sshctl --json run my-server --argv hostname
```

`my-server` is an example name; replace it with an alias from the previous step. `--argv hostname` passes `hostname` as one explicit remote argument instead of assembling a local shell string.

If this is your first use and no host exists yet, follow “Add or change a host” below. If you see `host_key_unknown`, `host_key_mismatch`, or `host_key_type_changed`, verify the fingerprint through the host-key flow under “Check a connection” first.

## Six words to know

| Word | Plain-language meaning |
| --- | --- |
| **vault** | A local encrypted safe containing host data and protected references to passwords/keys; sync transfers encrypted data only. |
| **alias** | The exact name used to address one saved host. Search results are candidates; choose the complete alias before connecting. |
| **sync** | Pulling or pushing encrypted vault state between this machine and the sync endpoint; it is not the SSH connection. |
| **push** | Publishing a reviewed local mutation to the sync endpoint; it must name a transaction ID or a deliberately reviewed pending scope. |
| **request** | A version-1 JSON operation file for dynamic arguments, scripts, secret-file paths, transfers, or host changes. |
| **host key** | The SSH fingerprint used to confirm that a server is the expected machine. Inspect and verify it before explicitly accepting a new or changed key. |

## Commands by task

Each section says when to use the command, then shows the smallest useful form. Aliases are generic, and `203.0.113.10` is an RFC 5737 documentation address, not a real host.

### View or search hosts

Use this when you want to see saved connections or narrow down several candidates:

```bash
sshctl --json host list
sshctl host search my --json
sshctl host show my-server --json
```

`search` never chooses a candidate for you; checks and connections always use the exact alias.

### Check a connection

Use this before a change when you want to check local vault state, sync freshness, and SSH health:

```bash
sshctl check my-server --json
sshctl --json doctor my-server --deep
```

For a new or changed host key, or a changed key type, inspect and verify the full fingerprint first:

```bash
sshctl host-key inspect my-server --json
sshctl host-key accept my-server --fingerprint SHA256:REPLACE_WITH_VERIFIED_FINGERPRINT --yes --json
```

Replace the fingerprint only with the `observed_fingerprint` you verified through a trusted channel. Do not replace this process with automatic `ssh-keygen -R` plus `ssh-keyscan`.

sshctl negotiates the key type already recorded in `known_hosts` for the host first (for example ed25519), so a host you connected to with OpenSSH is not reported as changed just because the server also offers ECDSA. `host_key_mismatch` means the key of a recorded type changed; `host_key_type_changed` (inspect status `type_changed`) means the server no longer presents any recorded key type. `accept` replaces only the entry of the same key type: other key types of that host and lines of other hosts are left untouched.

### Run a command

Use this for one fixed, simple command on a selected host:

```bash
sshctl --json run my-server --argv hostname
sshctl --json run my-server --argv uname -sr
```

After the alias, `--argv`, `--`, or the first non-option word starts the remote command. Everything after it, including `-h`, `--help`, and `--json`, goes to the remote program untouched (`sshctl run my-server --argv df -h` runs `df -h`). `-h/--help` and `--json` are sshctl options only before that boundary. The same rule applies to `exec`, `plan`, and `map`, and script arguments after `--` in `-f`/`-s`/`--scripts` mode.

#### Local stdin forwarding

`sshctl run` follows explicit rules for forwarding local stdin to the remote command:

- `--stdin`: forward local stdin in every mode (human and `--json`) and close the remote stdin at EOF. `printf 'a\nb\n' | sshctl --json run my-server --stdin --argv cat` returns `"a\nb\n"` in `stdout`.
- `--no-stdin` (like `ssh -n`): do not forward.
- `--stdin-file <path>`: same as `< path`, in every mode; request JSON accepts it as `stdin_file`.
- With none of these: human mode forwards a non-terminal stdin directly (it no longer probes for ready data, so slow upstreams such as `pg_dump | sshctl run ...` are not dropped); `--json` still does not forward by default. When stdin is then a pipe or file (not a terminal or `/dev/null`), the JSON result carries `"stdin_forwarded": false` and a `warning` that points to `--stdin`; when forwarding happens it carries `"stdin_forwarded": true`.
- `SSM_FORWARD_STDIN=1` turns forwarding on by default (including `--json`) and `SSM_FORWARD_STDIN=0` is the same as `--no-stdin`; an explicit option beats the environment variable.
- The body of `-s`, `-f`, and `--scripts` already uses the remote stdin, so combining them with `--stdin`/`--stdin-file` fails with `invalid_arguments`; `map` and `run --stream` also reject `--stdin`/`--stdin-file`.

Because the probe is gone, a default human run whose stdin is a never-ending pipe (common when CI or an agent inherits stdin) waits forever if the remote command reads stdin; add `--no-stdin` or `</dev/null` in that case.

Inside loops such as `while read h; do ...; done < hosts.txt`, give every call `--no-stdin` (or `</dev/null`); otherwise the first call forwards the remaining input to the remote command:

```bash
while read -r h; do sshctl run "$h" --no-stdin --argv uptime; done < hosts.txt
```

For repeated simple commands, reuse one process and connection; send one JSON argv array per line:

```bash
sshctl run my-server --stream
["hostname"]
["uname","-sr"]
```

Online stream `--refresh` must be positive; `--refresh=0` is valid only with explicit global `--offline`. Use a request file for dynamic arguments, complex shell syntax, or secrets; do not put generated scripts inside `bash -c`.

#### Run a script (shell or Python)

`-f`/`-s` send the script over SSH stdin; nothing is written to the remote host. Without `--interpreter` the script's shebang picks the shell (`#!/bin/bash` and `#!/usr/bin/env bash` use bash); a script with no shebang runs with `sh`. A shebang that names a non-shell program such as python3 is refused with `invalid_arguments` and a hint to add `--interpreter`.

```bash
sshctl --json run my-server -f report.py --interpreter python3 -- a b   # sys.argv[1:] == ['a', 'b']
sshctl run my-server -f deploy.sh --shell bash
```

An explicit `--interpreter` is treated as confirmed and is not limited to the shell allowlist. The value is one program name, one absolute path, or `env <name>` (for example `--interpreter "env python3"`); interpreter arguments and shell metacharacters are rejected. Non-shell interpreters are started as `<interpreter> - <args...>` and must read the script from stdin when given `-` (python3, perl, and ruby do). A missing remote interpreter returns `interpreter_not_found` (exit 127). `--preflight` checks shell syntax only, so it is rejected together with a non-shell interpreter. `--shell` remains the shell-only option; `--interpreter bash` still works and means the same as `--shell bash`. A request file accepts the same value as `"interpreter"` next to `script_file`.

### Upload or download files

Use these for a regular file or directory tree:

```bash
sshctl put my-server ./notes.txt /tmp/notes.txt --sha256 --json
sshctl get my-server /tmp/notes.txt ./notes.txt --sha256 --timeout 30s --json
```

`--sha256` is for regular-file integrity verification. Directory transfers provide different guarantees; see [Advanced / for agents and automation](#advanced--for-agents-and-automation). The remote host is probed for `sha256sum`, then `shasum -a 256`, then `openssl dgst -sha256`; if none exists the result is `error:integrity_tool_unavailable` (retry without `--sha256`). Parent directories that `put` creates default to mode `0755`; override with `--dir-mode <octal>` (for example `--dir-mode 0750`). The file itself is still written through a private temporary file and renamed, so file permission semantics are unchanged. `get` accepts the same position-independent `--json`, `--timeout`, and `--sha256` as `put` (the download is hashed locally and compared with the remote digest; a mismatch fails and does not replace the destination). `get` does not support `--resume`.

### Add or change a host

Use this to add a host or change only selected fields. `--verify` checks the candidate before saving it:

```bash
sshctl host upsert my-server \
  --host 203.0.113.10 --port 22 --user demo \
  --key-file /secure/my-server.key --verify --json

sshctl host update my-server --port 2222 --verify --json
```

Private keys and passwords may only be referenced with `--key-file`, `--password-file`, or a saved `--key` name; they are never inline values. A changed result is saved locally as a pending mutation and returns a reviewable `transaction_id`. An idempotent no-op returns `changed:false`, `action:"unchanged"`, and no ID; do not publish it.

### Publish a reviewed change

After reviewing the result and deciding that the sync endpoint should receive it, publish only that transaction:

```bash
sshctl --json push --only <transaction-id>
```

Replace `<transaction-id>` with the exact ID returned by the mutation. Do not use bare `push`; use `sshctl --json push --all` only after reviewing every pending change in the invocation-start set.

## Safety boundaries

- Never put passwords, private keys, master passphrases, tokens, `cloud.json`, or decrypted vault data in command arguments, JSON, logs, Issues, PRs, or commits.
- Never auto-select an alias or treat a search suggestion as the target.
- On a first-use or changed host key, inspect it, verify the full SHA-256 fingerprint out of band, then explicitly accept it.
- Default local-first: read commands use the local inventory and the sync server does not stand in front of them. Using it is not silent: `status` reports `remote_state`, `last_sync_error`, and `cache_age_seconds`, and stale inventory adds `inventory_stale` and a stderr warning. Set `sync_mode: strict` when a refresh failure must fail the command.
- Publication always has an explicit scope. `push --only <transaction-id>` publishes one reviewed transaction and never silently widens it when dependencies are pending.

## Updates and rollback

Fresh installs follow GitHub latest, currently v2.0.2. Ordinary updates choose a newer release only within the installed major:

```bash
ssm update
```

For a v1.4.3/v1.4.4 installation that needs v2, first create the non-installing review:

```bash
ssm update --major
```

After the release notes, automated checks, external consumers, and rollback readiness pass, the only cross-major authorization path is:

```bash
ssm update --major --yes
```

`--major --yes` does not bypass SHA-256, exact-tag, keyless-provenance, or failure-recovery checks. A failed update preserves the old executable and recovery evidence. See the [migration guide](docs/migration-v1-to-v2.md) and [provenance runbook](docs/update-provenance-runbook.md).

## Development and verification

For everyday development run `go test ./...` with any recent Go. When the host is not the pinned toolchain, the `cmd/verify` subtests that assert the host is the pinned version report SKIP with the reason instead of failing. Set `SSM_VERIFY_REQUIRE_PINNED=1` (official CI does) to enforce them.

The formal gate is `go run ./cmd/verify ci`, which needs the exact pinned tools: Go 1.26.8 and golangci-lint 2.11.4. When one is missing or the wrong version, verify prints the acquisition command in its message:

```bash
# Pinned Go toolchain (downloaded by Go itself)
GOTOOLCHAIN=go1.26.8 go run ./cmd/verify ci

# Pinned golangci-lint
GOBIN=<dir> go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4
PATH=<dir>:$PATH GOTOOLCHAIN=go1.26.8 go run ./cmd/verify ci
```

## Advanced / for agents and automation

Read the [official Agent Skill](skills/agent-ssm/SKILL.md) and [version compatibility matrix](skills/agent-ssm/references/version-compatibility.md) first. They define the v1.4.3/v1.4.4 compatibility branch and the v2 branch shared by supported v2.0.0 and current v2.0.2, including the schema and fields each branch may use.

### Structured output and requests

Normal `--json` commands emit one JSON value; explicit `run --stream` emits line-oriented NDJSON. Agents should classify `ok`, `error`, `stage`, `exit`, and `hint`; a remote program can itself exit 255, so the exit code alone cannot identify an SSH transport failure.

#### Exit codes and transport errors

In `--json` mode, decide by the `error` field, not the process exit code: a remote program can exit with any code, including 1, 2, and 255, and you often lose the code through pipes such as `2>&1 | tail`.

| Exit | Meaning |
|---|---|
| 0 | Success. |
| 1 | An sshctl failure that is not an SSH transport failure: `internal`, vault, sync and update errors, every `host` and `host-key` subcommand failure (including `alias_not_found` there), `script_syntax_error`, and `put`/`get` transfer errors (`remote_write_failed`, `transfer_timeout`, `integrity_failed`, `partial_state_*`, `local_read_failed`); or a remote command that exited 1. Read `error`. |
| 2 | Invalid arguments or request (`invalid_arguments`, `invalid_request`), or a remote command that exited 2. |
| 127 | The remote script interpreter is missing (`interpreter_not_found`), or a remote command that exited 127. |
| 128 + signal | A local SIGINT/SIGTERM/SIGHUP stopped `run` (`interrupted`; 130, 143, 129). The signal was forwarded and the remote command may still be running. |
| 255 | An SSH transport failure in `run`, `map`, `check`, `doctor`, `put`, or `get`: `dial_timeout`, `dial_refused`, `dial_network`, `handshake_failed`, `host_key_unknown`/`host_key_mismatch`/`host_key_type_changed` (the connection was refused), `auth_failed`, `no_auth_configured`, `session_failed`, `connection_lost`; also `alias_not_found` from `run`, `map`, `check`, and `doctor`. A remote command can also exit 255. |
| any other | The remote command's own exit status, passed through unchanged. |

`map` exits with the first failed result's exit code; each result in the array carries its own `error`. A `put`/`get` whose connection breaks midway is `connection_lost` with exit 255, like `run`, because it is a transport failure rather than a transfer-specific error.

**Contract change.** A `put`/`get` whose connection breaks midway used to report `remote_write_failed` (or `remote_read_failed` for a download) with exit 1. It now reports `connection_lost` with exit 255 and `outcome:"unknown"`. sshctl's own `--timeout` abort of a file or directory `get`, or of a file `put`, is unchanged: `transfer_timeout`, exit 1, no `outcome`. The `host` subcommands' `alias_not_found` has JSON `exit` 255 but process exit 1; decide by `error`.

Whether a retry is safe depends on whether the command was sent:

- Safe to retry: `dial_timeout`, `dial_refused`, `dial_network`, and `handshake_failed` (`stage:handshake`: TCP connected but the SSH handshake failed, for example EOF, connection reset, or a protocol error, and no command was sent), and `session_failed` at `stage:session` when the session could not be opened, because the command was never sent. A deterministic handshake failure such as `no common algorithm` fails the same way every time, so retrying is pointless; fix the algorithm or server configuration instead. `auth_failed` and `host_key_*` keep their own codes and need a fix, not a retry.
- Not safe to retry: `connection_lost` (`stage:remote_execution`, plus `outcome:"unknown"`). The connection dropped after the command was sent, for example when the host rebooted or `sysupgrade` ran, so the remote command may still be running or may have finished. Check the process state on the host first.

`outcome` is an additive field that appears only on `connection_lost`.

Use schema version 1 for dynamic or untrusted arguments, scripts, secret-file paths, transfers, and host changes. The [v2 request-v1 schema](skills/agent-ssm/references/request-v1.schema.json) supports `op:get`:

```json
{
  "version": 1,
  "op": "run",
  "alias": "my-server",
  "argv": ["printf", "%s\\n", "literal value"]
}
```

```bash
sshctl request --file ./request.json
```

v1.4.3/v1.4.4 must use the [compatibility bridge schema](skills/agent-ssm/references/request-v1-bridge.schema.json) and must not assume v2-only fields.

Mistyped commands get a hint instead of being treated as an alias. A first word that is not a known subcommand still uses the `sshctl <alias> <command>` shorthand, and only when the alias does not exist is it checked as a command. Commands that exist only in `ssm` (such as `keys` or `login`) and spellings within one or two edits of a subcommand (such as `stauts` or `hostkey`) return `unknown_command` (exit 2) with a `hint` naming the right entrypoint or command and the close command names in `candidates`; the `ssm` entrypoint gives the same hints for sshctl-only commands and typos (in human mode a suggestion returns `unknown_command` with exit 2; without a suggestion the legacy `Unknown command` output and its exit code are unchanged). When an alias or redirect key is as close as the command, or closer, the word is treated as an alias and returns `alias_not_found`. Everything else stays `alias_not_found` (exit 255) with the nearest aliases in `candidates`, which are suggestions only and are never selected or executed. Unknown `run`/`exec`/`plan`/`map` options return `invalid_arguments` (exit 2) with a suggestion in `hint`: `--script-file` suggests `-f`, `--fetch` suggests `get`, and other options are matched by edit distance against the real option table.

### Transfer, resume, and public fields

In v2, branch on `direction` (`put`/`get`) and `kind` (`file`/`directory`). Regular-file results report only guarantees actually supplied by the protocol; directory transfers explicitly report `atomic:false`, `integrity:not_available`, and `resume:unsupported`, and directory get does not invent `bytes_received`. Regular-file resume is enabled only with explicit `--resume=v1`; incompatible or failed integrity state never replaces the destination. A directory upload whose remote tar fails (permissions, full disk, target not a directory) returns the remote error with `stage:remote_extract`; the destination may be partially written and there is no per-file retry. The per-file fallback is used only when no executable local `tar` exists. A directory download closes the other end as soon as either end fails and exits in bounded time. Request v1 gains additive `dir_mode` on `op:put` and `sha256`/`timeout` on `op:get`.

In strict mode an online refresh failure returns `error:sync_pull_failed` with `stage:sync_pull` and only explicit `--offline` reads cached state; in local_first (the default) `status` and read commands do not fail because of sync. A present malformed `cloud.json` returns `error:sync_config_error` in both modes. Non-capture human runs stream by default: stdout passes through byte for byte, including values the remote command echoes, as the success-output contract requires; on stderr, explicit `--secret` values become `***` and credential-shaped content is sanitized line by line. There is no size limit and no temporary file, so byte pipes such as `tar -czf - dir | tar -xzf -` and long-running commands work. On SIGINT, SIGTERM, or SIGHUP, sshctl forwards the signal to the remote command, flushes output, and exits with `error:interrupted` and 128 plus the signal number. `--json` holds the complete stdout and stderr in memory before emitting one JSON value and sanitizes failed results as a whole; use human mode or `get` for large output. Set `SSM_RUN_OUTPUT=buffered` to restore the v2.0.2 replay mode: output appears once the outcome is known, failures are sanitized as a whole, each stream is limited to 8 MiB, and overflow returns `error:internal`. Streamed output no longer masks the lines of an `-s`/`-f` script body (that would blank `set -x` traces) and no longer sanitizes stdout after a failure; pass credentials with `--secret`. Signals ignored at startup (for example under `nohup`) stay ignored, and `--json` runs do not forward signals. The buffered mode and directory/file transfer diagnostics still keep raw bytes in private 0600 temporary files that are removed after replay; files left by a killed process are swept by a later run after 24 hours.

The concrete reason for a sync failure is kept in the error chain: the `--json` result of `sync_pull_failed` (and of push and host sync failures) gains an additive top-level `cause` field that appears only on sync failures, `message` carries the redacted underlying error, and human output appends `cause=<value>` to the `ssm: error=... stage=...` line. `cause` is a stable enumeration: `dns` (name did not resolve), `connect_refused`, `timeout`, `tls` (certificate verification failed), `auth` (HTTP 401/403, token rejected), `http_5xx` (server error), `missing_token` (no token in configuration), `network` (any other transport error), and `unknown` (everything else, including other HTTP statuses). `hint` follows `cause`: `auth` and `missing_token` require `ssm login` and a retry and never suggest `--offline`; `tls` needs a human to inspect the certificate and must not be bypassed; `dns`, `connect_refused`, `timeout`, `http_5xx`, and `network` may be retried later or, only when stale inventory is explicitly acceptable, run with explicit `--offline`.

### Explicit publication scope and empty ledgers

`push --only <transaction-id>` publishes one reviewed transaction. `push --all` fixes the invocation-start pending-ID set and publishes only that set. An empty set never overwrites the complete local blob: identical identities return `action:"noop"`, while missing or divergent identities return `error:"sync_conflict"`; follow the guarded [empty-ledger recovery guidance](skills/agent-ssm/references/import-json.md) for pull, reviewed `--merge`, and a new `push --only <transaction-id>`.

### Sync modes: local-first (default) and strict

The central server is only for synchronization: it never stands in front of every command, and the tool works offline. With the default `sync_mode: local_first`, read commands (`run`, `map`, `get`, `put`, `check`, `doctor`, `list`, `host list|show`, `host-key`, `keys`, `status`) read only the local vault and send no sync request in the foreground. When automatic sync is due, the command atomically claims the attempt in `sync-state.json` and starts one detached background process, `sshctl sync --background` (a hidden option). It makes a short-timeout "pull only if changed" check, pulls only when the remote changed, never pushes automatically, and never overwrites a diverged local vault; it replaces the vault only under the short vault write lock shared with local mutations, so it cannot overwrite a mutation. After a success it waits at least `sync_interval` (default `10m`); failures are recorded with exponential backoff from 30 seconds, doubling, capped at one hour, and commands inside the backoff window do not try again. A sync failure never fails a read command.

Visible, not blocking: in local_first mode `status` never fails because of sync and reports `remote_state` (`checked`, `unreachable`, `not_checked`, `not_configured`, `auto_sync_disabled`), `last_successful_sync`, `last_sync_error` (`cause`, redacted `message`, `at`; `cause` is `conflict` on divergence), `next_sync_attempt`, `cache_age_seconds`, and `inventory_stale` (all additive). When the cache is older than `stale_after` (default `7d`, measured from the newest confirmed pull, push, or successful background check), `run` JSON results carry `inventory_stale:true` and human read commands print one warning line on stderr; stdout is unchanged.

Settings in `settings.json`: `sync_mode` (`local_first` or `strict`), `sync_interval`, and `stale_after` (a Go duration, or an integer plus `d` for days); the `SSM_SYNC_MODE` environment variable overrides `sync_mode` for one process. `auto_sync:false` disables automatic sync in both modes. `--offline` and `SSM_OFFLINE=1` are equivalent: they skip sync configuration parsing and network access and never start a background sync.

Explicit `sync`, `pull`, and `push` keep strict semantics in both modes (failure is failure) and record their outcome in `sync-state.json`. Writes and publication are unchanged: changes stay pending until `push --only <transaction-id>` or `push --all`, and divergence detection stays fail-closed. In local_first mode, a due `run --stream --refresh` reloads its snapshot when the vault was updated in the background, and sync failures never stop the stream. On a new machine, run `sshctl sync` once after `login` to pull the vault.

To get the v2.0.2 behavior (refresh online before every read, a refresh failure fails the command), set `"sync_mode": "strict"` in `settings.json` or `SSM_SYNC_MODE=strict` for one process. Compared with v2.0.2, the default changes in that read commands no longer fail when the sync endpoint is unreachable and no longer pay one `HEAD` request per command.

### Optional sync server

You can run your own sync endpoint; it stores encrypted vault blobs only:

```bash
ssm register --server <sync-server-url> --email <email> --password-file <sync-password-file>
ssm login --server <sync-server-url> --email <email> --password-file <sync-password-file>
sshctl sync
```

Example local server:

```bash
ssm server --listen 127.0.0.1:18787 --data-dir /srv/ssm-sync
```

The sync server is not an SSH jump host; SSH still connects from the current machine.

### Minimal prompt for another agent

```text
Install SSM from Cd1s/ssm:
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
Run sshctl --json --version first, then sshctl --json status and sshctl --json host list.
Use only an exact alias; use sshctl --json run <alias> --argv ... for fixed simple commands.
Reference passwords and private keys only through restricted file paths; verify host changes and publish only the returned transaction_id.
```
