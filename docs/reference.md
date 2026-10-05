# ssm reference

The complete reference for `ssm` and `sshctl` v2.1.0: every command and option, the configuration files, environment variables, error codes, and exit statuses. For a short introduction and the quick start, see the [README](../README.md).

Commands marked **unreleased** are merged on `main` but not part of the latest release.

## Contents

- [Concepts](#concepts)
  - [Glossary](#glossary)
- [Installation details](#installation-details)
  - [Installer variables](#installer-variables)
  - [Windows](#windows)
  - [Build from source](#build-from-source)
- [Hosts and host keys](#hosts-and-host-keys)
  - [View or search hosts](#view-or-search-hosts)
  - [Add or change a host](#add-or-change-a-host)
  - [Reaching a host through a jump host (ProxyJump)](#reaching-a-host-through-a-jump-host-proxyjump)
  - [Check a connection](#check-a-connection)
- [Running commands](#running-commands)
  - [Run a command](#run-a-command)
  - [Wait for a host (`wait`) and retry dialing (`--retry-dial`)](#wait-for-a-host-wait-and-retry-dialing---retry-dial)
  - [Timeouts and keepalive](#timeouts-and-keepalive)
  - [Option reference](#option-reference)
- [File transfer](#file-transfer)
  - [Upload or download files](#upload-or-download-files)
  - [Transfer, resume, and public fields](#transfer-resume-and-public-fields)
- [Sync and publication](#sync-and-publication)
  - [Sync modes: local-first (default) and strict](#sync-modes-local-first-default-and-strict)
  - [Optional sync server](#optional-sync-server)
  - [Publish a reviewed change](#publish-a-reviewed-change)
  - [Explicit publication scope and empty ledgers](#explicit-publication-scope-and-empty-ledgers)
- [Automation and AI agents](#automation-and-ai-agents)
  - [Structured output and requests](#structured-output-and-requests)
  - [Exit codes and transport errors](#exit-codes-and-transport-errors)
  - [Output handling, signals, and sync failure causes](#output-handling-signals-and-sync-failure-causes)
  - [Minimal prompt for another agent](#minimal-prompt-for-another-agent)
- [Configuration](#configuration)
  - [Configuration directory](#configuration-directory)
  - [settings.json](#settingsjson)
  - [Environment variables](#environment-variables)
- [Safety boundaries](#safety-boundaries)
- [Updates and rollback](#updates-and-rollback)
- [Troubleshooting](#troubleshooting)
- [Development and verification](#development-and-verification)

## Concepts

`ssm` is a non-interactive SSH management tool for agents, scripts, and automation. It helps you keep host records, check connections, run commands, and transfer files without opening a TUI, an interactive shell, or a prompt on the remote machine. It is a good fit when SSH work needs to be safe and repeatable.

`ssm` and `sshctl` are the same binary under two command names. The installer normally creates `/usr/local/bin/ssm` and `/usr/local/bin/sshctl -> /usr/local/bin/ssm`; the examples below use the agent-oriented `sshctl` name.

Passwords and private keys are never printed. The master passphrase is read from the local `~/.config/ssm/master.pass` by default; host passwords, private keys, and host records live in the local encrypted vault. When adding or changing a host, pass only restricted file paths such as `--password-file` or `--key-file`; never put secret values in commands, JSON, logs, or commits.

If sync is enabled, the sync server sees only encrypted vault blobs. It cannot see the decrypted host inventory, SSH passwords, or private keys; the actual SSH connection always starts from the current machine.

### Glossary

| Word | Plain-language meaning |
| --- | --- |
| **vault** | A local encrypted safe containing host data and protected references to passwords/keys; sync transfers encrypted data only. |
| **alias** | The exact name used to address one saved host. Search results are candidates; choose the complete alias before connecting. |
| **sync** | Pulling or pushing encrypted vault state between this machine and the sync endpoint; it is not the SSH connection. |
| **push** | Publishing a reviewed local mutation to the sync endpoint; it must name a transaction ID or a deliberately reviewed pending scope. |
| **request** | A version-1 JSON operation file for dynamic arguments, scripts, secret-file paths, transfers, or host changes. |
| **host key** | The SSH fingerprint used to confirm that a server is the expected machine. Inspect and verify it before explicitly accepting a new or changed key. |

## Installation details

`install.sh` needs `sh`, `curl`, `jq`, `head`, `wc`, `sha256sum` or `shasum`, and the GitHub CLI (`gh`) with `gh attestation verify`. It downloads the release for your platform, checks the SHA-256 digest against `checksums.txt`, verifies the Sigstore provenance bundle against the exact release tag, and only then installs. It supports Linux and macOS on `amd64` and `arm64`.

It installs `ssm` and a `sshctl` symlink to it into the prefix directory, creates the configuration directory with mode `0700`, writes `update_repo` there, and creates `settings.json` if it is missing. Then it runs `ssm --version`. Afterwards `sshctl --json --version` should report the version field (`2.1.0` for the current release); if `sshctl` is not found, open a new terminal or put the prefix directory on `PATH`.

### Installer variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `SSM_RELEASE_TAG` | latest release | Install one exact stable tag such as `v2.1.0`; other forms are rejected. |
| `SSM_PREFIX` | `/usr/local/bin` | Directory that receives `ssm` and the `sshctl` symlink. |
| `SSM_CONFIG_DIR` | `~/.config/ssm` | Configuration directory the installer prepares. |
| `SSM_REPO` | `Cd1s/ssm` | GitHub repository the installer downloads from. Provenance still verifies the `Cd1s/ssm` release workflow identity. |

### Windows

Download `ssm-windows-amd64.exe` (or `ssm-windows-arm64.exe`) and its `.sigstore.json` bundle from the [latest release](https://github.com/Cd1s/ssm/releases/latest) together with `checksums.txt`. Compare the SHA-256 of the executable with its entry in `checksums.txt`, then verify the provenance with `gh attestation verify`, passing the executable, its `.sigstore.json` bundle, and the `Cd1s/ssm` repository. The exact verification rules, including the pinned release workflow identity, are in the [update provenance runbook](update-provenance-runbook.md).

### Build from source

```bash
go build ./cmd/ssm
```

Use Go 1.26.8. Source builds are for development; release binaries are built and attested by the release workflow.

## Hosts and host keys

### View or search hosts

Use this when you want to see saved connections or narrow down several candidates:

```bash
sshctl --json host list
sshctl host search my --json
sshctl host show my-server --json
```

`search` never chooses a candidate for you; checks and connections always use the exact alias.

### Add or change a host

Use this to add a host or change only selected fields. `--verify` checks the candidate before saving it:

```bash
sshctl host upsert my-server \
  --host 203.0.113.10 --port 22 --user demo \
  --key-file /secure/my-server.key --verify --json

sshctl host update my-server --port 2222 --verify --json
```

`--transfer auto|shell|sftp` (`host.transfer` in request v1) sets the protocol `put`/`get` use for that host; the default `auto` is not stored in the vault. See [Upload or download files](#upload-or-download-files).

`--proxy-jump <alias>` (`host.proxy_jump` in request v1, an empty value clears it) makes the host reached through another alias; see [Reaching a host through a jump host](#reaching-a-host-through-a-jump-host-proxyjump).

Private keys and passwords may only be referenced with `--key-file`, `--password-file`, or a saved `--key` name; they are never inline values. A changed result is saved locally as a pending mutation and returns a reviewable `transaction_id`. An idempotent no-op returns `changed:false`, `action:"unchanged"`, and no ID; do not publish it.

### Reaching a host through a jump host (ProxyJump)

Point a host at another alias to be reached through it:

```bash
sshctl host update inner --proxy-jump bastion --offline --json     # another alias; chains may be several levels deep
sshctl host update inner --proxy-jump "" --offline --json          # an empty value clears it
sshctl run inner --argv hostname                                   # run/map/put/get/check/doctor/cp/host-key all work
```

- Connections are made hop by hop: the first hop uses the ordinary dial (host-key verification, authentication, the handshake deadline, keepalive); every later hop does its SSH handshake over a `direct-tcpip` channel opened on the previous hop, **verifying its own host key against the local `known_hosts` and authenticating with its own credentials**. No credential is ever sent to a jump host, agent forwarding is not enabled, and no hop's host-key verification is relaxed.
- Validated at resolve time: no cycles, at most 5 jump hosts, and every referenced alias must exist (redirects apply). Otherwise the result is `error:proxy_jump_invalid` (`stage:validate`, exit 2) and no connection is made.
- Failures gain an optional `via` field: the alias of the hop that failed (a jump host or the target itself). Classification keeps the existing `dial_*`, `handshake_failed`, `auth_failed`, and `host_key_*` codes, `stage` is unchanged, and a host-key `hint` names that hop's alias. When a hop's host key is untrusted the chain stops there: later hosts are never contacted and never see an authentication attempt.
- `host-key inspect|accept <target-alias>` examines and records the **target's** host key; every jump host must already be trusted (run `host-key inspect`/`accept` on the jump alias first), otherwise it fails and `via` names the jump alias.
- **Compatibility**: clients up to v2.0.2 ignore `proxy_jump` and drop it when they re-save a synced vault, turning the host into a direct dial (it fails closed through host-key verification, but the setting is lost). Upgrade every client before using `proxy_jump`.
- Each target behind a jump host opens its own jump connection (they are not shared).
- The connection pool is keyed by the whole chain; closing or evicting the target also closes the jump connections it owns. Request v1 uses `host.proxy_jump` (an empty string clears it).

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

## Running commands

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

To bound a command, use `--exec-timeout 2m` (SIGTERM at the deadline, then `exec_timeout` with exit 124 and the output received so far); `--connect-timeout` and its alias `--timeout` only bound connecting. See [Timeouts and keepalive](#timeouts-and-keepalive).

Online stream `--refresh` must be positive; `--refresh=0` is valid only with explicit global `--offline`. Use a request file for dynamic arguments, complex shell syntax, or secrets; do not put generated scripts inside `bash -c`.

#### Run a script (shell or Python)

`-f`/`-s` send the script over SSH stdin; nothing is written to the remote host. Without `--interpreter` the script's shebang picks the shell (`#!/bin/bash` and `#!/usr/bin/env bash` use bash); a script with no shebang runs with `sh`. A shebang that names a non-shell program such as python3 is refused with `invalid_arguments` and a hint to add `--interpreter`.

```bash
sshctl --json run my-server -f report.py --interpreter python3 -- a b   # sys.argv[1:] == ['a', 'b']
sshctl run my-server -f deploy.sh --shell bash
```

An explicit `--interpreter` is treated as confirmed and is not limited to the shell allowlist. The value is one program name, one absolute path, or `env <name>` (for example `--interpreter "env python3"`); interpreter arguments and shell metacharacters are rejected. Non-shell interpreters are started as `<interpreter> - <args...>` and must read the script from stdin when given `-` (python3, perl, and ruby do). A missing remote interpreter returns `interpreter_not_found` (exit 127). `--preflight` checks shell syntax only, so it is rejected together with a non-shell interpreter. `--shell` remains the shell-only option; `--interpreter bash` still works and means the same as `--shell bash`. A request file accepts the same value as `"interpreter"` next to `script_file`.

### Wait for a host (`wait`) and retry dialing (`--retry-dial`)

When a host is rebooting or a route is flapping, use `wait` instead of an external sleep loop:

```bash
sshctl --json wait my-server --timeout 5m --interval 5s
sshctl --json wait my-server --until tcp
sshctl --json run my-server --retry-dial 3:500ms --argv hostname
```

- `wait` keeps waiting only while the transport is "not reachable yet": refused, timed-out or unroutable dials, and handshake failures (EOF, reset, timeout) that happen before the server's host key arrives. A drop or timeout after that point may have happened mid-authentication and is reported, never retried. The default `--until ssh` makes exactly one real SSH connection per attempt (no separate banner-only probe, which sshd logs as a pre-auth failure that fail2ban can count).
- **`wait` and `--retry-dial` never retry authentication or host-key failures.** `auth_failed`, `host_key_unknown`/`host_key_mismatch`/`host_key_type_changed`, missing credentials, and alias or configuration errors stop immediately with the real error, because repeated logins against a host running fail2ban get the client banned quickly.
- `--interval` must be at least `1s`; delays grow exponentially with jitter up to a 30 second cap, every attempt is time-bounded so the total does not noticeably overshoot `--timeout`. A timeout returns `error:wait_timeout` (`stage:wait`, exit 1) whose `message` carries the last observed cause. `--until tcp` checks TCP only and never authenticates. Success prints `{"ok":true,"alias":...,"attempts":N,"elapsed_ms":...}`.
- `--retry-dial N[:backoff]` (N at most 10, `backoff` defaults to 250ms, exponential with jitter) retries only pre-command transport failures (`dial_*`, and handshake failures before the server's host key arrives); it never retries `auth_failed`, `host_key_*`, `connection_lost`, or anything after the session is open. `dial_attempts` appears in the JSON only when `--retry-dial` was given or a retry happened.
- Through a `proxy_jump` alias the rule applies per hop: a transport failure before the failing hop's OWN host key arrived (for example the target behind the jump is down or refuses the connection) keeps `wait`/`--retry-dial` going, and each retry only logs in to the earlier hops successfully; an authentication failure at any hop, or any failure after a hop's host key arrived, is never retried. `wait --until tcp` is not supported for a `proxy_jump` alias (the target is only reachable through its jump host).
- `--until cmd:<...>` from the original proposal is not implemented (deferred).

### Timeouts and keepalive

Each timeout governs a different phase; do not mix them up:

| Option | What it bounds | Default |
|---|---|---|
| `--connect-timeout <duration>` | TCP connect **plus** the SSH handshake (including authentication), as one budget. Expiry is `handshake_failed` (`stage:handshake`; no command was sent, so retrying is safe; the hint suggests raising `--connect-timeout`). A TCP connect that never completes is still `dial_timeout`. | 15s |
| `--timeout <duration>` (`run`/`exec`/`plan`/`map`, deprecated) | Compatible alias of `--connect-timeout`. It is a connection timeout, not an execution timeout. Both flags set one value: the last one on the command line wins, and either beats an inherited `SSM_CONNECT_TIMEOUT`/`SSM_TIMEOUT`. | 15s |
| `--exec-timeout <duration>` | How long the remote command may run (`run`/`exec`/`plan`, `map`, and every line of `run --stream`; `exec_timeout` in a request). At the deadline sshctl sends `SIGTERM`, closes the session after a 5s grace period, and returns `exec_timeout` (once SIGTERM has been sent the result is `exec_timeout` even if the command traps TERM and exits 0 during the grace period; a command that finished before the signal was sent keeps its real result) with exit 124, `timed_out:true`, and the `stdout`/`stderr` received so far. Human mode keeps what was already streamed and prints a classification line last. | none |
| `--timeout` of `put`/`get` | The file-transfer timeout (`transfer_timeout`). Unchanged. | none |

The environment variable `SSM_CONNECT_TIMEOUT` is equivalent to `--connect-timeout` (`SSM_TIMEOUT` is the old alias). The handshake deadline applies even with no option, using the 15s default.

**Contract change.** `--timeout` used to limit only the TCP connect, so a stalled handshake could hang forever; it now covers TCP connect plus the handshake. This tightens a hang: connections that handshake normally are unaffected, and a stalled handshake now fails within the limit with `handshake_failed` instead of waiting indefinitely. A handshake that times out after TCP connected is `handshake_failed`, not `dial_timeout`, because no command was sent (retry is safe) and the stall is the server's (rate limiting, OOM, half-open), not an unreachable network.

**Keepalive.** On by default: every 15 seconds each SSH connection gets a `keepalive@openssh.com` request that wants a reply; after 3 consecutive unanswered probes the connection is closed and a running command fails as `connection_lost` (`outcome:"unknown"`). Pooled, reused connections benefit too. `SSM_KEEPALIVE=0` turns it off; an unparseable value falls back to the 15 second default; `SSM_KEEPALIVE=<duration>` (for example `5s`) sets the interval. The EOF that follows sshctl closing its own session after `--exec-timeout` is never reported as `connection_lost`.

### Option reference

`run`/`exec`/`plan`/`map` options go after the alias (the target list for
`map`) and before the remote-command boundary:

| Option | Meaning |
|---|---|
| `--argv` | Everything after it is the remote argv, passed word by word with no local shell joining. |
| `--raw` | Join the words with single spaces and never quote them; the remote shell parses the result. Compatibility only, with quoting and expansion risk. Cannot be combined with `--argv` or a script option. |
| `--plan`, `--dry-run` | Resolve and show `remote_command` and the risk without connecting or running; the `plan` command is the same as `run --plan`. |
| `-j`, `--jobs`, `--parallel <n>` | Worker count for `map` (default 8); a single-host `run` does not use it. |
| `--trace`, `-v` | Same as `SSM_TRACE=1`, see above. |
| `--no-reuse` | Do not use the connection pool for this call; same as `SSM_REUSE=0`. |
| `-f`, `--file <path>` (repeatable), `--scripts a.sh,b.sh`, `-s`, `--script` | Script sources: `-f`/`--scripts` read local files, `-s`/`--script` read the script from local stdin; the script body travels to the remote over stdin. `map --scripts` runs every script on every host in parallel. |
| `--shell <name>`, `--interpreter <program>` | Pick the shell or non-shell interpreter that runs a script, see "Run a script". |
| `--preflight`, `--no-preflight` | Check shell syntax first; `--no-preflight` turns it off again and the last one wins. |
| `--secret`, `-e NAME=@file` | Set `NAME` in the remote command's environment from a file (`NAME=value` is accepted, but then the value sits on the command line, so avoid it); the value is redacted from output. |
| `--retry-dial N[:backoff]` | Dial retries; rules are in "Wait for a host (`wait`) and retry dialing (`--retry-dial`)". |
| `--connect-timeout`, `--exec-timeout`, `--timeout` | See "Timeouts and keepalive". |
| `--stdin`, `--no-stdin`, `--stdin-file` | See "Local stdin forwarding". |
| `--stream`, `--refresh <duration>` | The long-lived argv stream of `run <alias> --stream` and its online refresh interval. |

Options of other commands:

- Global: `--json`, `--offline` (deprecated for reads; it only suppresses background sync), `--master-pass-file <path>`, `--version`.
- `host add|update|upsert`: `--host`, `--port`, `--user`, `--group`, `--transfer auto|shell|sftp`, `--proxy-jump <alias>`, exactly one of the auth options `--key <name>` / `--key-file <path>` (optionally with `--key-name <name>` to name the new key) / `--password-file <path>`, plus `--verify` (connect and verify before saving; a failed verification saves nothing) and `--push` (requires `--verify`; publishes the resulting transaction right after saving). `host search` accepts `--filter <query>` instead of the positional query; `host remove` needs `--yes`, and `--prune-key` also deletes saved keys nothing references any more.
- `import-json <path>`: `--merge` or `--replace --yes`; `--manifest <path>` supplies aliases for entries that have none; `--expect-count <n>` fails when the file does not yield exactly n hosts (0 disables the check).
- `wait <alias>`: `--timeout`, `--interval`, and `--until ssh|tcp` are described in "Wait for a host (`wait`) and retry dialing (`--retry-dial`)".
- `put`/`get`/`cp`: see "Upload or download files". `--dir-mode` must be an octal permission of at most `0777` that keeps owner write and execute (it includes `0300`, for example `0700`, `0750`, `0755`); values such as `0500` or `0644`, which would make creating nested directories fail, are rejected before connecting.
- Sync service: `ssm login`/`register` use `--server`, `--email`, `--password-file`; `ssm server` uses `--listen`, `--data-dir`.
- `ssm update [--major [--yes]]`: see "Updates and rollback".

## File transfer

### Upload or download files

Use these for a regular file or directory tree:

```bash
sshctl put my-server ./notes.txt /tmp/notes.txt --sha256 --json
sshctl get my-server /tmp/notes.txt ./notes.txt --sha256 --timeout 30s --json
```

`--sha256` is for regular-file integrity verification. Directory transfers provide different guarantees; see [Transfer, resume, and public fields](#transfer-resume-and-public-fields). The remote host is probed for `sha256sum`, then `shasum -a 256`, then `openssl dgst -sha256`; if none exists the result is `error:integrity_tool_unavailable` (retry without `--sha256`). Parent directories that `put` creates default to mode `0755`; override with `--dir-mode <octal>` (for example `--dir-mode 0750`; the mode must be at most `0777` and keep owner write and execute, i.e. include `0300`, or it is rejected before connecting). The file itself is still written through a private temporary file and renamed, so file permission semantics are unchanged. `get` accepts the same position-independent `--json`, `--timeout`, and `--sha256` as `put` (the download is hashed locally and compared with the remote digest; a mismatch fails and does not replace the destination). `get` does not support `--resume`.

#### Targets without a POSIX shell (SFTP)

By default (host `transfer: auto`) transfers go through the remote POSIX shell. `get` returns `error:remote_shell_unsupported` (`stage:discovery`) when the path probe output is unparseable (not `DIR`/`FILE`/`MISSING`), the shell reports an error, or exec is refused, instead of misreporting the path as missing; `put` returns it only when exec is refused. Use the SFTP subsystem instead (same SSH connection, no remote command is run): add `--sftp` for one transfer, or set the host to `sftp`:

```bash
sshctl put win-box ./notes.txt C:/temp/notes.txt --sftp --sha256 --json
sshctl host update win-box --transfer sftp --offline --json   # auto|shell|sftp, default auto
```

Request v1 sets the host field with `host.transfer`; `put`/`get` requests accept a top-level `transfer`: `shell` or `sftp` overrides the host setting for that one operation, while `auto` (or omitting it) keeps the host setting, so `auto` cannot override a host set to `sftp`. SFTP currently supports single regular files only: directories and `put --resume` return `error:unsupported_transfer_option`, and a server without the sftp subsystem returns `error:sftp_unavailable`. SFTP guarantees differ from the shell path, and the result fields report exactly what was provided:

- `get`: `Stat` decides the type, then the file streams into a local staging file that is published atomically (`atomic:true`). SFTP has no remote digest command, so `--sha256` hashes the received stream, checks it against the size the server reported and against the staged file, and `remote_sha256` is that stream digest; without `--sha256` the result is `integrity:not_checked`.
- `put`: the file is written to a private temporary sibling and renamed. A server with `posix-rename@openssh.com` replaces the destination atomically (`atomic:true`); otherwise the previous destination is moved aside and restored if the rename fails, but the result says `atomic:false`. `--sha256` reads the temporary file back over SFTP and compares digests locally (`integrity:sha256_verified`); if the server does not allow reading it back the result is `integrity_tool_unavailable` (`stage:capability`, as on the shell path; `integrity:not_available`) and nothing is published. Without `--sha256` only the size is checked (`size_verified`). `--dir-mode` applies to newly created parent directories as well. A destination that is already a directory is rejected untouched. A timed-out or dropped SFTP `put` may leave a `<destination>.ssm-upload.<hex>` temporary file: cleanup is retried on a fresh SFTP session, and if it still fails the error message names the leftover path.

#### Host-to-host copy (`cp`)

`sshctl cp <alias-a>:<path> <alias-b>:<path>` copies one regular file from A to B, streamed through this machine and **never touching the local disk**:

```bash
sshctl cp web1:/srv/app.tgz web2:/srv/app.tgz --timeout 5m --json
# A pushes straight to B (explicit confirmation required, see --direct below)
sshctl cp web1:/srv/app.tgz web2:/srv/app.tgz --direct --yes
```

- A is read with the `get` path (`cat` over SSH) and B is written with the `put` path (private temporary file, verified, then renamed), so B never holds a partial file; on failure or a digest mismatch B's previous destination is left untouched.
- This machine hashes the bytes that pass through and compares three SHA-256 values: the source digest reported by A, the local one, and B's digest of its temporary file before the rename. Only if all three agree does the copy succeed. The JSON result has `direction:"cp"`, `route:"local_relay"`, `source`/`destination` (`alias`, `path`), `bytes`, `source_sha256`, `local_sha256`, `destination_sha256`, `atomic:true`, and `integrity:"sha256_verified"`; failures carry the usual `error`/`stage`/`exit`/`hint` (a digest mismatch is `integrity_failed` with `integrity:"mismatch"`).
- Both hosts need a POSIX shell and one of `sha256sum`/`shasum`/`openssl` (otherwise `integrity_tool_unavailable`). Only single regular files are supported; a directory returns `unsupported_transfer_option` (use `get`/`put`, or archive it on the source first); hosts with `transfer: sftp` are not supported. The source's permission bits are kept when A has `stat`, otherwise `0600`.
- `--json` prints the machine result; `--timeout <duration>` bounds the digest probe and the transfer after connecting (connection setup follows the connect timeout) and returns `transfer_timeout`. A source and destination that resolve to the same alias and path are refused (`invalid_arguments`). Either host may itself be reached through `proxy_jump`.
- **`--direct --yes` (A pushes straight to B).** *Unreleased: merged on `main`, not part of v2.1.0.* `sshctl cp web1:/srv/app.tgz web2:/srv/app.tgz --direct --yes` streams the file from A to B over A's own network path instead of through this machine. Without `--yes` it fails with `confirmation_required` (exit 2) before any connection, in human and `--json` mode, because it has a real exposure:
  - A has to authenticate to B, so sshctl starts an in-process SSH agent that holds **only B's vault key** and forwards it to A for this one session (`auth-agent@openssh.com`); it is emptied and closed when the copy ends. This machine's own `SSH_AUTH_SOCK`, every other key and B's password stay local. **While the copy runs, A, and anyone who controls A, can use B's key for other connections to B (or any host that accepts that key); they cannot extract the key.**
  - A runs `ssh -F /dev/null -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<private temp file> -o GlobalKnownHostsFile=/dev/null ... <user>@<host>` with the same temporary-file, digest-check and rename script `put` uses. **A's `ssh_config` (user and system, including `Include`s, ProxyCommand/ProxyJump, LocalCommand, ControlMaster) and A's own keys (`~/.ssh/id_*`) are ignored**: that ssh uses only the forwarded agent (`IdentityFile=/dev/null`; ssh finds the forwarded socket through `SSH_AUTH_SOCK`), with password, keyboard-interactive and host-based authentication and all forwardings disabled. The temp file (mode 0600, removed on exit) contains only B's host key as already trusted on this machine, written for the exact `host[:port]` A uses; A's own known_hosts is neither used nor changed. If B's key is not trusted locally, `host_key_unknown` is returned before A is contacted.
  - Requirements and refusals. Refused before A is contacted (`unsupported_transfer_option`, `stage:validate`, exit 1): password-only B or a B that does not accept its vault key (checked with a key-only login from this machine); B with `proxy_jump` (A itself is reached through a chain as usual); `transfer: sftp` on either host; an unusable vault key. B's untrusted host key is `host_key_unknown` (`stage:dial`, exit 255), also before A is contacted. Refused after connecting to A: a directory source (`unsupported_transfer_option`, `stage:validate`, exit 1, like plain `cp`); an A without an `ssh` client (`remote_tool_unavailable`, `stage:capability`, exit 1); an A whose sshd does not provide the forwarded agent (`unsupported_transfer_option`, `stage:capability`, exit 1, needs `AllowAgentForwarding`). A's ssh uses `BatchMode` and `ConnectTimeout`, so it never prompts.
  - Time bound: the transfer runs under `--timeout`. When it is set, A's ssh also runs under GNU-style `timeout` if A has it (detected with `timeout --version`; BusyBox and others get no wrapper), and an expired limit is `transfer_timeout`. At the deadline sshctl always empties the agent and closes the connection to A that carries the agent channel, so B's key can no longer be used through the agent. Without the `timeout` wrapper, however, an ssh on A that is already authenticated may keep running until it finishes or fails (the session close sends no SIGHUP without a pty, and the `signal` request is only honoured by OpenSSH 7.9+ and reaches the login shell, not ssh). **Without `--timeout` there is no limit** (the same as plain `cp`); pass `--timeout` with `--direct`.
  - Integrity: sshctl reads A's source digest first, B verifies its temporary file against it before the rename, and sshctl reads B's digest afterwards over its own connection; success needs them to be equal. The JSON result has `route:"direct"`, `source_sha256`, `destination_sha256`, `bytes`, `integrity:"sha256_verified"` and no `local_sha256`, because nothing is relayed locally. Request v1 has no `direct` field.

### Transfer, resume, and public fields

In v2, branch on `direction` (`put`/`get`) and `kind` (`file`/`directory`). Regular-file results report only guarantees actually supplied by the protocol; directory transfers explicitly report `atomic:false`, `integrity:not_available`, and `resume:unsupported`, and directory get does not invent `bytes_received`. Regular-file resume is enabled only with explicit `--resume=v1`; incompatible or failed integrity state never replaces the destination. A directory upload whose remote tar fails (permissions, full disk, target not a directory) returns the remote error with `stage:remote_extract`; the destination may be partially written and there is no per-file retry. The per-file fallback is used only when no executable local `tar` exists. A directory download closes the other end as soon as either end fails and exits in bounded time. Request v1 gains additive `dir_mode` on `op:put` and `sha256`/`timeout` on `op:get`.

## Sync and publication

### Sync modes: local-first (default) and strict

The central server is only for synchronization: it never stands in front of every command, and the tool works offline. With the default `sync_mode: local_first`, read commands (`run`, `map`, `get`, `put`, `check`, `doctor`, `list`, `host list|show`, `host-key`, `keys`, `status`) read only the local vault and send no sync request in the foreground. When automatic sync is due, the command atomically claims the attempt in `sync-state.json` and starts one detached background process, `sshctl sync --background` (a hidden option). It makes a short-timeout "pull only if changed" check, pulls only when the remote changed, never pushes automatically, and never overwrites a diverged local vault; it replaces the vault only under the short vault write lock shared with local mutations, so it cannot overwrite a mutation. After a success it waits at least `sync_interval` (default `10m`); failures are recorded with exponential backoff from 30 seconds, doubling, capped at one hour, and commands inside the backoff window do not try again. A sync failure never fails a read command.

Visible, not blocking: in local_first mode `status` never fails because of sync and reports `remote_state` (`checked`, `unreachable`, `not_checked`, `not_configured`, `auto_sync_disabled`), `last_successful_sync`, `last_sync_error` (`cause`, redacted `message`, `at`; `cause` is `conflict` on divergence), `next_sync_attempt`, `cache_age_seconds`, `inventory_stale`, and `inventory_unsynced` (true when sync is configured but has never confirmed the inventory; human reads also print one stderr line; all additive). When the cache is older than `stale_after` (default `7d`, measured from the newest confirmed pull, push, or successful background check), `run` JSON results carry `inventory_stale:true` and human read commands print one warning line on stderr; stdout is unchanged.

Settings in `settings.json`: `sync_mode` (`local_first` or `strict`), `sync_interval`, and `stale_after` (a Go duration, or an integer plus `d` for days); the `SSM_SYNC_MODE` environment variable overrides `sync_mode` for one process. `auto_sync:false` disables automatic sync in both modes. `--offline` and `SSM_OFFLINE=1` are equivalent: they skip sync configuration parsing and network access and never start a background sync.

Explicit `sync`, `pull`, and `push` keep strict semantics in both modes (failure is failure) and record their outcome in `sync-state.json`. Writes and publication are unchanged: changes stay pending until `push --only <transaction-id>` or `push --all`, and divergence detection stays fail-closed. In local_first mode, a due `run --stream --refresh` reloads its snapshot when the vault was updated in the background, and sync failures never stop the stream. `login` fetches the inventory right after authenticating, through exactly the path of an explicit `sshctl sync` (strict semantics, vault write lock, conflict evidence on divergence); run `sshctl sync` yourself only if that initial fetch failed (login still succeeds, and stderr gives the `cause` and says to run `sshctl sync`).

`--offline` is deprecated for read commands: it is accepted for compatibility, reads are local by default, and it now only suppresses background sync (in `strict` mode it still skips the online refresh). `run` JSON results also carry `inventory_unsynced:true` when sync is configured but has never confirmed the inventory, and `inventory_sync_error:"<cause>"` when the most recent sync attempt failed (`cause` uses the same values as above, for example `http_5xx`; additive, and human mode prints no warning for it so offline use stays quiet). In `strict` mode and for explicit `sync`/`pull`, a concurrent local writer holding the short vault write lock can make the command fail with "vault is busy"; retry it. `pull --adopt-remote <sha256> --yes` runs only if the local vault has not changed since the conflict evidence was recorded; otherwise it is refused, the local changes are kept, and you should re-check the conflict.

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

### Publish a reviewed change

After reviewing the result and deciding that the sync endpoint should receive it, publish only that transaction:

```bash
sshctl --json push --only <transaction-id>
```

Replace `<transaction-id>` with the exact ID returned by the mutation. Do not use bare `push`; use `sshctl --json push --all` only after reviewing every pending change in the invocation-start set.

### Explicit publication scope and empty ledgers

`push --only <transaction-id>` publishes one reviewed transaction. `push --all` fixes the invocation-start pending-ID set and publishes only that set. An empty set never overwrites the complete local blob: identical identities return `action:"noop"`, while missing or divergent identities return `error:"sync_conflict"`; follow the guarded [empty-ledger recovery guidance](../skills/agent-ssm/references/import-json.md) for pull, reviewed `--merge`, and a new `push --only <transaction-id>`.

## Automation and AI agents

Read the [official Agent Skill](../skills/agent-ssm/SKILL.md) and [version compatibility matrix](../skills/agent-ssm/references/version-compatibility.md) first. They define the v1.4.3/v1.4.4 compatibility branch and the v2 branch shared by supported v2.0.0 and current v2.1.0, including the schema and fields each branch may use.

### Structured output and requests

Normal `--json` commands emit one JSON value; explicit `run --stream` emits line-oriented NDJSON. Agents should classify `ok`, `error`, `stage`, `exit`, and `hint`; a remote program can itself exit 255, so the exit code alone cannot identify an SSH transport failure.

Use schema version 1 for dynamic or untrusted arguments, scripts, secret-file paths, transfers, and host changes. The [v2 request-v1 schema](../skills/agent-ssm/references/request-v1.schema.json) supports `op:get`:

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

v1.4.3/v1.4.4 must use the [compatibility bridge schema](../skills/agent-ssm/references/request-v1-bridge.schema.json) and must not assume v2-only fields.

Mistyped commands get a hint instead of being treated as an alias. A first word that is not a known subcommand still uses the `sshctl <alias> <command>` shorthand, and only when the alias does not exist is it checked as a command. Commands that exist only in `ssm` (such as `keys` or `login`) and spellings within one or two edits of a subcommand (such as `stauts` or `hostkey`) return `unknown_command` (exit 2) with a `hint` naming the right entrypoint or command and the close command names in `candidates`; the `ssm` entrypoint gives the same hints for sshctl-only commands and typos (in human mode a suggestion returns `unknown_command` with exit 2; without a suggestion the legacy `Unknown command` output and its exit code are unchanged). When an alias or redirect key is as close as the command, or closer, the word is treated as an alias and returns `alias_not_found`. Everything else stays `alias_not_found` (exit 255) with the nearest aliases in `candidates`, which are suggestions only and are never selected or executed. Unknown `run`/`exec`/`plan`/`map` options return `invalid_arguments` (exit 2) with a suggestion in `hint`: `--script-file` suggests `-f`, `--fetch` suggests `get`, and other options are matched by edit distance against the real option table.

### Exit codes and transport errors

In `--json` mode, decide by the `error` field, not the process exit code: a remote program can exit with any code, including 1, 2, and 255, and you often lose the code through pipes such as `2>&1 | tail`.

| Exit | Meaning |
|---|---|
| 0 | Success. |
| 1 | An sshctl failure that is not an SSH transport failure: `internal`, vault, sync and update errors, every `host` and `host-key` subcommand failure (including `alias_not_found` there), `script_syntax_error`, and `put`/`get` transfer errors (`remote_write_failed`, `transfer_timeout`, `integrity_failed`, `partial_state_*`, `local_read_failed`); or a remote command that exited 1. Read `error`. |
| 2 | Invalid arguments or request (`invalid_arguments`, `invalid_request`), `proxy_jump_invalid` (a jump chain with a missing alias, a cycle, or more than 5 jump hosts; nothing was dialed), or a remote command that exited 2. |
| 124 | `--exec-timeout` expired in `run` or `map` (`exec_timeout`): sshctl sent SIGTERM to the remote command and closed the session after a grace period. Same status as GNU `timeout`; a remote command can also exit 124, so read `error`. |
| 127 | The remote script interpreter is missing (`interpreter_not_found`), or a remote command that exited 127. |
| 128 + signal | A local SIGINT/SIGTERM/SIGHUP stopped `run` (`interrupted`; 130, 143, 129). The signal was forwarded and the remote command may still be running. |
| 255 | An SSH transport failure in `run`, `map`, `check`, `doctor`, `put`, or `get`: `dial_timeout`, `dial_refused`, `dial_network`, `handshake_failed`, `host_key_unknown`/`host_key_mismatch`/`host_key_type_changed` (the connection was refused), `auth_failed`, `no_auth_configured`, `session_failed`, `session_limit`, `connection_lost`; also `alias_not_found` from `run`, `map`, `check`, and `doctor`. A remote command can also exit 255. |
| any other | The remote command's own exit status, passed through unchanged. |

`map` exits with the first failed result's exit code; each result in the array carries its own `error`. A `put`/`get` whose connection breaks midway is `connection_lost` with exit 255, like `run`, because it is a transport failure rather than a transfer-specific error.

**Contract change.** A `put`/`get` whose connection breaks midway used to report `remote_write_failed` (or `remote_read_failed` for a download) with exit 1. It now reports `connection_lost` with exit 255 and `outcome:"unknown"`. sshctl's own `--timeout` abort of a file or directory `get`, or of a file `put`, is unchanged: `transfer_timeout`, exit 1, no `outcome`. The `host` subcommands' `alias_not_found` has JSON `exit` 255 but process exit 1; decide by `error`.

Whether a retry is safe depends on whether the command was sent:

- Safe to retry: `dial_timeout`, `dial_refused`, `dial_network`, and `handshake_failed` (`stage:handshake`: TCP connected but the SSH handshake failed, for example EOF, connection reset, or a protocol error, and no command was sent), and `session_failed` or `session_limit` at `stage:session` when the session could not be opened, because the command was never sent. `session_limit` means the server's per-connection session cap (sshd `MaxSessions`) stayed full: sshctl backs off for a free slot within the connection timeout without closing the shared connection or interrupting running sessions, and returns this only when none frees; lower `-j` or raise sshd `MaxSessions`. A deterministic handshake failure such as `no common algorithm` fails the same way every time, so retrying is pointless; fix the algorithm or server configuration instead. `auth_failed` and `host_key_*` keep their own codes and need a fix, not a retry.
- Do not retry blindly: `exec_timeout` (`stage:remote_execution`, with `timed_out:true`). The command was sent and ran until `--exec-timeout`; sshctl sent SIGTERM and closed the session after the grace period, but the remote process may still be running. Check the host, then decide whether to rerun with a larger `--exec-timeout`.
- Not safe to retry: `connection_lost` (`stage:remote_execution`, plus `outcome:"unknown"`). The connection dropped after the command was sent, for example when the host rebooted or `sysupgrade` ran, so the remote command may still be running or may have finished. Check the process state on the host first.

`outcome` is an additive field that appears only on `connection_lost`.

### Output handling, signals, and sync failure causes

In strict mode an online refresh failure returns `error:sync_pull_failed` with `stage:sync_pull` and only explicit `--offline` reads cached state; in local_first (the default) `status` and read commands do not fail because of sync. A present malformed `cloud.json` returns `error:sync_config_error` in both modes. Non-capture human runs stream by default: stdout passes through byte for byte, including values the remote command echoes, as the success-output contract requires; on stderr, explicit `--secret` values become `***` and credential-shaped content is sanitized line by line. There is no size limit and no temporary file, so byte pipes such as `tar -czf - dir | tar -xzf -` and long-running commands work. On SIGINT, SIGTERM, or SIGHUP, sshctl forwards the signal to the remote command, flushes output, and exits with `error:interrupted` and 128 plus the signal number. `--json` holds the complete stdout and stderr in memory before emitting one JSON value and sanitizes failed results as a whole; use human mode or `get` for large output. Set `SSM_RUN_OUTPUT=buffered` to restore the v2.0.2 replay mode: output appears once the outcome is known, failures are sanitized as a whole, each stream is limited to 8 MiB, and overflow returns `error:internal`. Streamed output no longer masks the lines of an `-s`/`-f` script body (that would blank `set -x` traces) and no longer sanitizes stdout after a failure; pass credentials with `--secret`. Signals ignored at startup (for example under `nohup`) stay ignored, and `--json` runs do not forward signals. The buffered mode and directory/file transfer diagnostics still keep raw bytes in private 0600 temporary files that are removed after replay; files left by a killed process are swept by a later run after 24 hours.

The concrete reason for a sync failure is kept in the error chain: the `--json` result of `sync_pull_failed` (and of push and host sync failures) gains an additive top-level `cause` field that appears only on sync failures, `message` carries the redacted underlying error, and human output appends `cause=<value>` to the `ssm: error=... stage=...` line. `cause` is a stable enumeration: `dns` (name did not resolve), `connect_refused`, `timeout`, `tls` (certificate verification failed), `auth` (HTTP 401/403, token rejected), `http_5xx` (server error), `missing_token` (no token in configuration), `network` (any other transport error), and `unknown` (everything else, including other HTTP statuses). `hint` follows `cause`: `auth` and `missing_token` require `ssm login` and a retry and never suggest `--offline`; `tls` needs a human to inspect the certificate and must not be bypassed; `dns`, `connect_refused`, `timeout`, `http_5xx`, and `network` may be retried later or, only when stale inventory is explicitly acceptable, run with explicit `--offline`.

### Minimal prompt for another agent

```text
Install SSM from Cd1s/ssm:
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
Run sshctl --json --version first, then sshctl --json status and sshctl --json host list.
Use only an exact alias; use sshctl --json run <alias> --argv ... for fixed simple commands.
Reference passwords and private keys only through restricted file paths; verify host changes and publish only the returned transaction_id.
```

## Configuration

### Configuration directory

Everything lives in one directory: `~/.config/ssm`, or the directory named by `SSM_CONFIG_DIR`.

| File | Purpose |
| --- | --- |
| `connections.enc` | The encrypted vault: hosts, saved keys, and protected password references. |
| `master.pass` | Optional master password file. When it exists it is used automatically, and a missing vault is created with it; `--master-pass-file` and `SSM_MASTER_PASS_FILE` select another file. Keep it private. |
| `settings.json` | Settings, described below. |
| `cloud.json` | Sync server and credentials written by `ssm login`. |
| `sync-state.json` | Outcome and schedule of automatic sync attempts (see [Sync modes](#sync-modes-local-first-default-and-strict)). |
| `redirects.json` | Alias redirects managed with `sshctl redirect`. |
| `update_repo` | GitHub repository `ssm update` reads releases from; the installer writes `Cd1s/ssm`. |

Host keys are checked against the standard OpenSSH `~/.ssh/known_hosts`.

### settings.json

| Key | Default | Meaning |
| --- | --- | --- |
| `sync_mode` | `local_first` | `local_first` or `strict`; the `SSM_SYNC_MODE` environment variable overrides it for one process. |
| `sync_interval` | `10m` | Minimum spacing between successful background syncs. |
| `stale_after` | `7d` | Cache age after which inventory is reported as stale. A Go duration or a whole number plus `d`. |
| `auto_sync` | `true` | `false` turns automatic sync off in both modes. |
| `auto_update` | `true` | Online commands check for a newer stable release of the installed major at most every 6 hours and install it after the usual checksum and provenance checks. `--offline` skips the check; `false` turns it off. |
| `update_repo` | `Cd1s/ssm` | Release repository; see `SSM_UPDATE_REPO` below for the precedence. |
| `password_cache` | ignored | Legacy setting is ignored; the session password cache is no longer provided. |
| `vim_keys` | ignored | Legacy setting is ignored; no current command reads it. |
| `last_push`, `last_pull` | empty | Timestamps maintained by `ssm`; do not edit. |

An empty, unparseable, or non-positive `sync_interval` or `stale_after` falls back to the default. An unrecognized `sync_mode` is treated as `local_first`.

### Environment variables

| Variable | Meaning |
| --- | --- |
| `SSM_CONFIG_DIR` | Configuration directory (default `~/.config/ssm`). |
| `SSM_MASTER_PASS_FILE` | Protected master password file; the same as the global `--master-pass-file <path>`. |
| `SSM_CONNECT_TIMEOUT` | Same as `--connect-timeout`: TCP connect plus SSH handshake, not remote execution. |
| `SSM_TIMEOUT` | Deprecated alias of `SSM_CONNECT_TIMEOUT`; ranks below it. |
| `SSM_DIAL_TIMEOUT` | Older name with the same effect, read last. |
| `SSM_KEEPALIVE` | `0` turns keepalive off; a duration such as `5s` sets the interval; an invalid value falls back to 15s. |
| `SSM_REUSE` | `0`, `off`, `false`, or `no` disables the connection pool. Reuse is always process-local (`status` reports `reuse_scope=process`). |
| `SSM_FORWARD_STDIN` | `1` forwards local stdin by default (including `--json`); `0` is the same as `--no-stdin`. |
| `SSM_RUN_OUTPUT` | `buffered` restores the v2.0.2 buffered output mode. |
| `SSM_NO_PERMISSION_WARNING` | Set to `1` to suppress warnings for credential files readable by other users. |
| `SSM_TRACE` | `1` (also `true`, `yes`, `on`) is the same as `--trace`/`-v`. |
| `SSM_OFFLINE` | `1` is the same as `--offline`. |
| `SSM_SYNC_MODE` | `strict` or `local_first`; overrides `sync_mode` for one process. |
| `SSM_UPDATE_REPO` | Release repository for `ssm update`, or `off`; see below. |
| `SSM_VERIFY_REQUIRE_PINNED` | Repository tooling only: `1` makes the `cmd/verify` subtests that assert the pinned toolchain fail instead of skipping. |

`SSM_UPDATE_REPO=<owner/repo>|off` chooses the GitHub repository `ssm update`
reads releases from. The default is `Cd1s/ssm`; the variable exists for tests
and for forks that publish their own releases. It ranks above the `update_repo`
file in the config directory and the `update_repo` key of `settings.json`;
`off`, `none`, and `disabled` turn updates off. It does not bypass the SHA-256
or provenance checks: provenance always verifies the `Cd1s/ssm` release
workflow identity, so a release from another repository cannot be installed
without a credential issued for `Cd1s/ssm`. It does decide where versions are
looked up, so set it only in a trusted environment (someone who can change it
can make update checks fail or stall on an older version) and never use it as a
way to install third-party builds.

## Safety boundaries

- Never put passwords, private keys, master passphrases, tokens, `cloud.json`, or decrypted vault data in command arguments, JSON, logs, Issues, PRs, or commits.
- Never auto-select an alias or treat a search suggestion as the target.
- On a first-use or changed host key, inspect it, verify the full SHA-256 fingerprint out of band, then explicitly accept it.
- Default local-first: read commands use the local inventory and the sync server does not stand in front of them. Using it is not silent: `status` reports `remote_state`, `last_sync_error`, and `cache_age_seconds`, and stale inventory adds `inventory_stale` and a stderr warning. Set `sync_mode: strict` when a refresh failure must fail the command.
- Publication always has an explicit scope. `push --only <transaction-id>` publishes one reviewed transaction and never silently widens it when dependencies are pending.

## Updates and rollback

Fresh installs follow GitHub latest, currently v2.1.0. Ordinary updates choose a newer release only within the installed major: the highest stable release of that major, regardless of the GitHub latest flag (a v2.0.2 install updated to v2.1.0 before the latest flag moved):

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

`--major --yes` does not bypass SHA-256, exact-tag, keyless-provenance, or failure-recovery checks. A failed update preserves the old executable and recovery evidence. See the [migration guide](migration-v1-to-v2.md) and [provenance runbook](update-provenance-runbook.md).

## Troubleshooting

| Symptom (`error`) | What it means | What to do |
| --- | --- | --- |
| `host_key_unknown` | The host's key is not in `known_hosts` yet. | Run `sshctl host-key inspect <alias>`, verify the full SHA-256 fingerprint out of band, then `host-key accept <alias> --fingerprint ... --yes`. |
| `host_key_mismatch` | A key of an already recorded type changed. | Treat it as a possible impersonation or a reinstalled server. Verify the new fingerprint out of band, then accept it. Do not replace the process with `ssh-keygen -R` plus `ssh-keyscan`. |
| `host_key_type_changed` | The server no longer presents any recorded key type. | Same as above: inspect, verify, accept. |
| `auth_failed` | The server rejected the credentials. Never retried. | Check the key or password file with `host update`. Do not loop: repeated logins get banned by fail2ban. |
| `dial_refused`, `dial_timeout`, `dial_network` | The host is unreachable. | Safe to retry: use `sshctl wait <alias>` or `--retry-dial`. Check the address, port, and firewall. |
| `handshake_failed` | TCP connected but the SSH handshake failed or `--connect-timeout` expired. No command was sent. | Safe to retry; raise `--connect-timeout`. A deterministic failure such as `no common algorithm` needs a server or algorithm fix. |
| `connection_lost` | The connection dropped after the command was sent (`outcome:"unknown"`). | Not safe to retry blindly: check the process state on the host first. |
| `session_limit` | The server's per-connection session cap (sshd `MaxSessions`) stayed full. | Lower `-j` or raise `MaxSessions`. |
| `exec_timeout` | `--exec-timeout` expired (exit 124); the remote process may still run. | Check the host, then rerun with a larger `--exec-timeout` if appropriate. |
| `remote_shell_unsupported` | The target has no usable POSIX shell for `put`/`get`. | Add `--sftp`, or set `host update <alias> --transfer sftp`. |
| `integrity_tool_unavailable` | The remote host has no `sha256sum`, `shasum`, or `openssl`. | Retry without `--sha256`. |
| `sync_pull_failed` and other sync errors | See the `cause` field. | `auth` and `missing_token`: run `ssm login`. `tls`: inspect the certificate, never bypass it. Others: retry later, or use `--offline` only when stale inventory is acceptable. |
| `sync_conflict` | The local and remote vaults diverged, or the remote returned to a version this machine already replaced (possible rollback or backup restore). | Follow the [empty-ledger recovery guidance](../skills/agent-ssm/references/import-json.md) or review the conflict before using `pull --adopt-remote`. |
| `vault is busy` | Another local writer holds the short vault write lock. | Retry the command. |
| `alias_not_found` | The alias does not exist. `candidates` are suggestions only. | Use the exact alias from `sshctl host list`. |
| `confirmation_required` | `cp --direct` needs `--yes`. | Read the exposure notes, then add `--yes` only if you accept them. |

### Restoring the sync server from backup

After an administrator restores the sync server from backup, clients that previously accepted and replaced the restored
identity refuse it as `sync_conflict` and keep their local vault. Review the conflict, then run
`sshctl pull --adopt-remote <sha> --yes` on each affected machine, using the restored remote identity.
Alternatively, one machine can adopt the restored version and publish a new version for the other clients to pull.

The client-local `sync-superseded.json` ledger retains at most 64 replaced identities and is neither uploaded nor part
of the vault. It cannot detect older versions this machine never accepted, evicted identities, or replay when ledger
metadata is missing or unreadable. Login, logout, and registration reset the ledger.

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
