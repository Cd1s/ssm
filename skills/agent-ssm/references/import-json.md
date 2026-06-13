# SSM import-json and server modification details

This reference records the verified headless workflow for adding, editing, testing, and removing SSM servers.

## Non-interactive add/edit command

Use this shape for one-host add/edit operations:

```bash
ssm --master-pass-file ~/.config/ssm/master.pass import-json "$json" --merge --expect-count 1
```

Why:

- `--master-pass-file` avoids `/dev/tty` unlock failures in agent/non-TTY sessions.
- `--merge` prevents replacing the entire vault.
- `--expect-count 1` fails early if the JSON did not decode exactly one connection.

## Private key add example

```bash
alias='new-server'
host='203.0.113.10'
key='/root/new-server.key'
chmod 600 "$key"

json=$(mktemp)
cat > "$json" <<JSON
{
  "servers": [
    {
      "alias": "$alias",
      "host": "$host",
      "port": 22,
      "user": "root",
      "private_key_path": "$key"
    }
  ]
}
JSON

ssm --master-pass-file ~/.config/ssm/master.pass import-json "$json" --merge --expect-count 1
rm -f "$json"
sshctl list | grep -Ei "$alias|$host"
sshctl run "$alias" 'hostname; uname -sr'
sshctl push
```

Do not print the private key. If the chat/platform redacts a pasted private key, ask the user to save it to a local file and give the path. Verify with:

```bash
stat -c 'key_file=%n mode=%a size=%s' /path/to/private.key
```

## Password auth example

```json
{
  "servers": [
    {
      "alias": "new-server",
      "host": "203.0.113.10",
      "port": 22,
      "user": "root",
      "auth_type": "password",
      "password": "..."
    }
  ]
}
```

## Modify an existing server

Import the same `alias` with updated fields and `--merge`:

```bash
alias='existing-server'
json=$(mktemp)
cat > "$json" <<'JSON'
{
  "servers": [
    {
      "alias": "existing-server",
      "host": "203.0.113.20",
      "port": 2222,
      "user": "root",
      "private_key_path": "/root/existing-server.key"
    }
  ]
}
JSON
ssm --master-pass-file ~/.config/ssm/master.pass import-json "$json" --merge --expect-count 1
rm -f "$json"
sshctl list | grep -Ei 'existing-server|203\.0\.113\.20'
sshctl run "$alias" 'hostname; uname -sr'
sshctl push
```

Merge behavior from source: connections are keyed by `Connection.Name`; keys are keyed by `SSHKey.Name`. Imported same-name entries replace existing ones; other entries are preserved.

## Remove a server

```bash
alias='server-to-remove'
ssm --master-pass-file ~/.config/ssm/master.pass remove "$alias"
```

If the server was added by one-host import-json with a private key, the generated key name is normally the alias; remove it too if present:

```bash
if ssm --master-pass-file ~/.config/ssm/master.pass keys | grep -F "  $alias " >/dev/null; then
  ssm --master-pass-file ~/.config/ssm/master.pass keys remove "$alias"
fi
sshctl list | grep -F "$alias" && echo 'ERROR still present' || echo 'removed'
sshctl push
```

## Temporary test-add-cleanup pattern

Use a clearly disposable alias:

```bash
alias='zz-ssm-skill-test-greencloud'
host='203.0.113.50'
key='/root/greencloud'

chmod 600 "$key"
backup="/tmp/ssm-vault-before-test-$(date +%s).enc"
cp /root/.config/ssm/connections.enc "$backup"
chmod 600 "$backup"

json=$(mktemp)
cat > "$json" <<JSON
{
  "servers": [
    {
      "alias": "$alias",
      "host": "$host",
      "port": 22,
      "user": "root",
      "private_key_path": "$key"
    }
  ]
}
JSON
ssm --master-pass-file ~/.config/ssm/master.pass import-json "$json" --merge --expect-count 1
rm -f "$json"
sshctl list | grep -Ei "$alias|$host"
sshctl run "$alias" 'hostname; uname -sr'
sshctl push

ssm --master-pass-file ~/.config/ssm/master.pass remove "$alias"
if ssm --master-pass-file ~/.config/ssm/master.pass keys | grep -F "  $alias " >/dev/null; then
  ssm --master-pass-file ~/.config/ssm/master.pass keys remove "$alias"
fi
sshctl list | grep -F "$alias" && echo 'ERROR still present' || echo 'removed'
sshctl push
sshctl status
```

The backup is only for emergency local restore; normal cleanup should use `ssm remove` + `ssm keys remove` and push.

## Accepted import JSON shapes

`import-json` accepts:

1. Array of server objects.
2. Object with `servers` array.
3. Object with `servers` map; map key becomes alias if item lacks alias.
4. Raw map; map key becomes alias if item lacks alias.

## Supported import fields

- `alias`, `host_alias`, `name`: connection name priority is alias → host_alias → name.
- `host`: required.
- `port`: integer or numeric string; default 22.
- `user`: required.
- `auth_type`: use `password` for password auth.
- `password`: password material.
- `private_key`: inline key material; avoid in chat/logs.
- `private_key_path` / `key_path`: local private key file path; preferred.
- `notes`: parsed but current vault schema does not store it.

## Pitfalls

- Bare `ssm import-json file.json` defaults to replace. Fucking dangerous for one-host changes.
- `SSM_MASTER_PASS=...` is fine for older `sshctl` compatibility but not the right way for `ssm import-json`; use `--master-pass-file`.
- `sshctl sync` is pull. After local changes use `sshctl push`.
- Removing a connection does not necessarily remove its saved SSH key; remove same-name key when it was created only for the deleted connection.
