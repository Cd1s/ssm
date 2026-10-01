# ssm

**English** | [简体中文](README.zh-CN.md)

[![CI](https://github.com/Cd1s/ssm/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Cd1s/ssm/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Cd1s/ssm)](https://github.com/Cd1s/ssm/releases/latest)
[![Go](https://img.shields.io/github/go-mod/go-version/Cd1s/ssm)](go.mod)

Save your SSH servers once, then run commands and copy files on them by name,
from scripts, CI jobs, or AI agents, without ever opening an interactive shell.

`ssm` and `sshctl` are the same program under two names. The examples below use
`sshctl` for working with servers and `ssm` for installing, updating, and sync.

## Why ssm

- **One encrypted vault.** Hosts, passwords, and private keys live in a local
  encrypted file. Secrets are never printed, and you add them by file path, not
  inline.
- **Run commands by name.** `sshctl run web-1 --argv uptime` needs no prompt and
  no TUI, and it never guesses a similar-looking name.
- **Made for scripts and AI agents.** Add `--json` and every result is one JSON
  document with a stable `error` code and exit status.
- **Safe file copies.** Upload, download, and server-to-server copies are
  checked with SHA-256 and never leave a half-written file behind.
- **Jump hosts and slow networks.** Reach servers through a bastion, wait for a
  rebooting server, and retry only the failures that are safe to retry.
- **Verified updates.** `ssm update` checks the release checksum and its
  Sigstore provenance before it replaces the program.

## Install

You need macOS or Linux, plus `curl`, `jq`, `sha256sum` or `shasum`, and the
[GitHub CLI](https://cli.github.com/) (`gh`), which the installer uses to verify
the release provenance.

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
ssm --version
```

A fresh install gets the GitHub latest release, currently **v2.1.0**. To pin a
version, run the same command with `SSM_RELEASE_TAG=v2.1.0` set for `sh`:

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | SSM_RELEASE_TAG=v2.1.0 sh
```

The installer puts `ssm` and a `sshctl` link next to it in `/usr/local/bin`
(change it with `SSM_PREFIX`) and uses `~/.config/ssm` for your data (change it
with `SSM_CONFIG_DIR`).

On Windows, download `ssm-windows-amd64.exe` (or `ssm-windows-arm64.exe`) from
the [latest release](https://github.com/Cd1s/ssm/releases/latest) and verify it
as described in the [provenance runbook](docs/update-provenance-runbook.md).

## Quick start

The examples use the made-up server `web-1` at `203.0.113.10`, a documentation
address.

1. **Add a server.** The first command creates a private master password file,
   and the vault is created the first time you use it. Keep the password file
   private and never commit it.

   ```bash
   mkdir -p ~/.config/ssm
   (umask 077; head -c 32 /dev/urandom | base64 > ~/.config/ssm/master.pass)
   sshctl host upsert web-1 --host 203.0.113.10 --user deploy \
     --key-file ~/.ssh/id_ed25519 --json
   ```

2. **Trust its host key.** Look at the fingerprint, check it against a source
   you trust, and then accept exactly that fingerprint.

   ```bash
   sshctl host-key inspect web-1 --json
   sshctl host-key accept web-1 --fingerprint SHA256:REPLACE_WITH_VERIFIED_FINGERPRINT --yes --json
   ```

3. **Run a command.** `--argv` sends each word to the server as is.

   ```bash
   sshctl run web-1 --argv hostname
   ```

4. **Copy a file up and down.** `--sha256` checks the copy.

   ```bash
   sshctl put web-1 ./notes.txt /tmp/notes.txt --sha256
   sshctl get web-1 /tmp/notes.txt ./notes-copy.txt --sha256
   ```

5. **Get JSON for scripts.**

   ```bash
   sshctl --json run web-1 --argv hostname
   ```

   ```json
   {"ok":true,"alias":"web-1","exit":0,"stdout":"web-1\n"}
   ```

   The real result carries a few more fields, such as `host`, `user`, and
   `latency_ms`. When something goes wrong, `ok` is `false` and `error` names
   the problem. See [Automation and AI agents](docs/reference.md#automation-and-ai-agents).

## Common tasks

| I want to...                    | Command                                                              |
| ------------------------------- | -------------------------------------------------------------------- |
| List my servers                 | `sshctl host list`                                                   |
| Run a script                    | `sshctl run web-1 -f deploy.sh`                                      |
| Run a Python script             | `sshctl run web-1 -f report.py --interpreter python3`                |
| Run a command on many servers   | `sshctl map 'web-*' -j 8 hostname`                                   |
| Upload a file                   | `sshctl put web-1 ./a.txt /tmp/a.txt`                                |
| Download a file                 | `sshctl get web-1 /tmp/a.txt ./a.txt`                                |
| Copy between two servers        | `sshctl cp web-1:/srv/app.tgz web-2:/srv/app.tgz`                    |
| Reach a server through a bastion | `sshctl host update db --proxy-jump bastion`                        |
| Wait for a server to come back  | `sshctl wait web-1 --timeout 5m`                                     |
| Share the vault between computers | `ssm login --server <url> --email <you> --password-file <file>`, then `sshctl sync` |
| Update ssm                      | `ssm update`                                                         |

## Update

```bash
ssm update
```

`ssm update` installs the newest stable release of the major version you have,
after checking its checksum and provenance. ssm also checks for such updates
by itself at most every 6 hours; set `"auto_update": false` in
`~/.config/ssm/settings.json` to turn that off. Moving from v1 to v2 is a separate,
deliberate step: read the [migration guide](docs/migration-v1-to-v2.md), then
run `ssm update --major --yes`.

## More documentation

- [Reference](docs/reference.md): every command, option, setting, environment
  variable, error code, and exit status.
- [Security policy](SECURITY.md) and the
  [update provenance runbook](docs/update-provenance-runbook.md).
- [Release notes](RELEASE_NOTES.md) and the
  [v1 to v2 migration guide](docs/migration-v1-to-v2.md).
- [AI agent skill](skills/agent-ssm/README.md) for Codex, Hermes, and similar
  agents.

## Development

Use Go 1.26.8. Run `go test ./...` for everyday checks and
`go run ./cmd/verify fast` before sending changes. Open pull requests against
`main`; see [AGENTS.md](AGENTS.md) and the
[development notes](docs/reference.md#development-and-verification).
