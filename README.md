# ssm

Headless SSH manager for agents. SSH hosts live in a local encrypted vault, sync moves only encrypted bytes through a self-hosted server, and SSH connections always start from the local machine.

[中文](#中文) | [English](#english)

<a id="中文"></a>
<details open>
<summary>中文</summary>

## 安装

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
```

安装脚本会从 `Cd1s/ssm` 下载当前系统匹配的 `ssm-<os>-<arch>`，安装到 `/usr/local/bin/ssm`，并创建 `/usr/local/bin/sshctl -> /usr/local/bin/ssm`。`sshctl` 不是额外脚本，它和 `ssm` 是同一个二进制。

## 常用命令

```bash
sshctl status
sshctl list
sshctl sync
sshctl run <alias> 'hostname; uname -s'
sshctl shell <alias>
sshctl put <alias> ./local-file /remote/file
sshctl push
```

## 同步

本机私有文件：

```text
/root/.config/ssm/connections.enc
/root/.config/ssm/master.pass
/root/.config/ssm/cloud.json
/root/.config/ssm/settings.json
/root/.config/ssm/update_repo
```

同步服务器地址属于私有配置，不要写进公开仓库。注册或登录时使用占位参数：

```bash
ssm register --server <sync-server-url> --email <email> --password-file <sync-password-file>
ssm login --server <sync-server-url> --email <email> --password-file <sync-password-file>
sshctl sync
```

中心服务器只保存加密 vault blob，不解密 SSH 密码或私钥。`sshctl list/run/shell/status` 和 `ssm list/exec/shell` 会在读取 vault 前检测远端 ETag；远端有新版本时会自动拉取。本地新增、编辑、删除连接后默认自动推送；也可以手动执行 `sshctl push`。

## 中心服务器

```bash
ssm server --listen 127.0.0.1:18787 --data-dir /srv/ssm-sync
```

推荐放在你自己的 HTTPS 反向代理后面，例如：

```text
<sync-server-url> -> 127.0.0.1:18787
```

systemd 示例：

```ini
[Unit]
Description=SSM encrypted sync server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ssm server --listen 127.0.0.1:18787 --data-dir /srv/ssm-sync
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

## Agent 一键提示词

把下面内容发给另一台机器上的 agent。私有同步文件需要单独安全传递，不要贴到公开聊天或仓库里。

```text
Install SSM from Cd1s/ssm:
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh

Create /root/.config/ssm. Put the provided private master.pass and cloud.json there with chmod 600.
Run sshctl sync, then verify with sshctl status and sshctl list.
Use sshctl run <alias> '<command>', sshctl shell <alias>, and sshctl put <alias> <local> <remote>.
Never print sync URLs, passwords, tokens, master.pass, cloud.json, private keys, or vault contents.
```

项目内 agent skill 在 `skills/agent-ssm/SKILL.md`。

## 自动更新

`1.0.0` 起默认从 `Cd1s/ssm` 检查 GitHub 最新 release。发现更高版本时会替换当前二进制。手动更新：

```bash
ssm update
```

## 多平台二进制

Release 里有多个平台文件：

```text
ssm-linux-amd64
ssm-linux-arm64
ssm-darwin-amd64
ssm-darwin-arm64
ssm-windows-amd64.exe
ssm-windows-arm64.exe
install.sh
checksums.txt
```

这些是 Go 的交叉编译产物。构建机可以是 x86，也能用 `GOOS/GOARCH` 生成 Linux ARM、macOS、Windows 等目标平台二进制；安装脚本会按当前机器系统和架构选择正确文件。

## 安全规则

不要把真实同步域名、账号、邮箱、密码、token、私钥、`master.pass`、`cloud.json` 或 vault 内容写进公开文档、日志、提交、release notes 或聊天。

</details>

<a id="english"></a>
<details>
<summary>English</summary>

## Install

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
```

The installer downloads the matching `ssm-<os>-<arch>` asset from `Cd1s/ssm`, installs `/usr/local/bin/ssm`, and creates `/usr/local/bin/sshctl -> /usr/local/bin/ssm`. `sshctl` is the same binary selected by executable name.

## Commands

```bash
sshctl status
sshctl list
sshctl sync
sshctl run <alias> 'hostname; uname -s'
sshctl shell <alias>
sshctl put <alias> ./local-file /remote/file
sshctl push
```

## Sync

Private local files:

```text
/root/.config/ssm/connections.enc
/root/.config/ssm/master.pass
/root/.config/ssm/cloud.json
/root/.config/ssm/settings.json
/root/.config/ssm/update_repo
```

Keep the sync server URL private. Use placeholders when registering or logging in:

```bash
ssm register --server <sync-server-url> --email <email> --password-file <sync-password-file>
ssm login --server <sync-server-url> --email <email> --password-file <sync-password-file>
sshctl sync
```

The center server stores only encrypted vault blobs. It never decrypts SSH passwords or private keys. `sshctl list/run/shell/status` and `ssm list/exec/shell` check the remote ETag before reading the vault and auto-pull when it changed. Local add, edit, and delete operations auto-push by default; `sshctl push` is available for manual upload.

## Center Server

```bash
ssm server --listen 127.0.0.1:18787 --data-dir /srv/ssm-sync
```

Put it behind your own HTTPS reverse proxy:

```text
<sync-server-url> -> 127.0.0.1:18787
```

systemd example:

```ini
[Unit]
Description=SSM encrypted sync server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ssm server --listen 127.0.0.1:18787 --data-dir /srv/ssm-sync
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

## Agent Prompt

Send this to another machine's agent. Transfer private sync files separately.

```text
Install SSM from Cd1s/ssm:
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh

Create /root/.config/ssm. Put the provided private master.pass and cloud.json there with chmod 600.
Run sshctl sync, then verify with sshctl status and sshctl list.
Use sshctl run <alias> '<command>', sshctl shell <alias>, and sshctl put <alias> <local> <remote>.
Never print sync URLs, passwords, tokens, master.pass, cloud.json, private keys, or vault contents.
```

Project agent skill: `skills/agent-ssm/SKILL.md`.

## Auto Update

Version `1.0.0` and later checks GitHub releases from `Cd1s/ssm` by default and replaces the current binary when a newer version exists. Manual update:

```bash
ssm update
```

## Release Binaries

Release assets:

```text
ssm-linux-amd64
ssm-linux-arm64
ssm-darwin-amd64
ssm-darwin-arm64
ssm-windows-amd64.exe
ssm-windows-arm64.exe
install.sh
checksums.txt
```

These are Go cross-compiled artifacts. An x86 build machine can produce Linux ARM, macOS, and Windows binaries with `GOOS/GOARCH`; the installer picks the asset matching the current machine.

## Safety

Do not put real sync domains, account names, emails, passwords, tokens, private keys, `master.pass`, `cloud.json`, or vault contents in public docs, logs, commits, release notes, or chat.

</details>
