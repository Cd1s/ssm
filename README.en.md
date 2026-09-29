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

This reports whether sync is configured, whether the state is fresh, and whether local changes are pending publication. If sync is not configured, the result says so explicitly; it does not silently use an old cache.

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

For repeated simple commands, reuse one process and connection; send one JSON argv array per line:

```bash
sshctl run my-server --stream
["hostname"]
["uname","-sr"]
```

Online stream `--refresh` must be positive; `--refresh=0` is valid only with explicit global `--offline`. Use a request file for dynamic arguments, complex shell syntax, or secrets; do not put generated scripts inside `bash -c`.

### Upload or download files

Use these for a regular file or directory tree:

```bash
sshctl put my-server ./notes.txt /tmp/notes.txt --sha256 --json
sshctl get my-server /tmp/notes.txt ./notes.txt
```

`--sha256` is for regular-file integrity verification. Directory transfers provide different guarantees; see [Advanced / for agents and automation](#advanced--for-agents-and-automation).

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
- Online sync failures never silently switch to cached inventory; use `--offline` only when stale data is explicitly acceptable.
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

### Transfer, resume, and public fields

In v2, branch on `direction` (`put`/`get`) and `kind` (`file`/`directory`). Regular-file results report only guarantees actually supplied by the protocol; directory transfers explicitly report `atomic:false`, `integrity:not_available`, and `resume:unsupported`, and directory get does not invent `bytes_received`. Regular-file resume is enabled only with explicit `--resume=v1`; incompatible or failed integrity state never replaces the destination.

An online refresh failure returns `error:sync_pull_failed` with `stage:sync_pull`; a present malformed `cloud.json` returns `error:sync_config_error`. Only explicit `--offline` reads cached state. Non-capture human runs stream by default: stdout passes through byte for byte, including values the remote command echoes, as the success-output contract requires; on stderr, explicit `--secret` values become `***` and credential-shaped content is sanitized line by line. There is no size limit and no temporary file, so byte pipes such as `tar -czf - dir | tar -xzf -` and long-running commands work. On SIGINT, SIGTERM, or SIGHUP, sshctl forwards the signal to the remote command, flushes output, and exits with `error:interrupted` and 128 plus the signal number. `--json` holds the complete stdout and stderr in memory before emitting one JSON value and sanitizes failed results as a whole; use human mode or `get` for large output. Set `SSM_RUN_OUTPUT=buffered` to restore the v2.0.2 replay mode: output appears once the outcome is known, failures are sanitized as a whole, each stream is limited to 8 MiB, and overflow returns `error:internal`. Streamed output no longer masks the lines of an `-s`/`-f` script body (that would blank `set -x` traces) and no longer sanitizes stdout after a failure; pass credentials with `--secret`. Signals ignored at startup (for example under `nohup`) stay ignored, and `--json` runs do not forward signals. The buffered mode and directory/file transfer diagnostics still keep raw bytes in private 0600 temporary files that are removed after replay; files left by a killed process are swept by a later run after 24 hours.

The concrete reason for a sync failure is kept in the error chain: the `--json` result of `sync_pull_failed` (and of push and host sync failures) gains an additive top-level `cause` field that appears only on sync failures, `message` carries the redacted underlying error, and human output appends `cause=<value>` to the `ssm: error=... stage=...` line. `cause` is a stable enumeration: `dns` (name did not resolve), `connect_refused`, `timeout`, `tls` (certificate verification failed), `auth` (HTTP 401/403, token rejected), `http_5xx` (server error), `missing_token` (no token in configuration), `network` (any other transport error), and `unknown` (everything else, including other HTTP statuses). `hint` follows `cause`: `auth` and `missing_token` require `ssm login` and a retry and never suggest `--offline`; `tls` needs a human to inspect the certificate and must not be bypassed; `dns`, `connect_refused`, `timeout`, `http_5xx`, and `network` may be retried later or, only when stale inventory is explicitly acceptable, run with explicit `--offline`.

### Explicit publication scope and empty ledgers

`push --only <transaction-id>` publishes one reviewed transaction. `push --all` fixes the invocation-start pending-ID set and publishes only that set. An empty set never overwrites the complete local blob: identical identities return `action:"noop"`, while missing or divergent identities return `error:"sync_conflict"`; follow the guarded [empty-ledger recovery guidance](skills/agent-ssm/references/import-json.md) for pull, reviewed `--merge`, and a new `push --only <transaction-id>`.

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
