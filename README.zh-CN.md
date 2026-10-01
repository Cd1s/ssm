# ssm

[English](README.md) | **简体中文**

[![CI](https://github.com/Cd1s/ssm/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Cd1s/ssm/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Cd1s/ssm)](https://github.com/Cd1s/ssm/releases/latest)
[![Go](https://img.shields.io/github/go-mod/go-version/Cd1s/ssm)](go.mod)

把 SSH 服务器一次保存好，之后就能用名字在它们上面运行命令、传文件，
可以交给脚本、CI 或 AI Agent 使用，全程不需要打开交互式 shell。

`ssm` 和 `sshctl` 是同一个程序的两个名字。下面的例子里，操作服务器用
`sshctl`，安装、更新和同步用 `ssm`。

## 为什么用 ssm

- **一个加密保险箱。** 主机、密码和私钥都保存在本机的加密文件里。
  秘密内容不会被打印出来，添加时也只传文件路径，不写在命令里。
- **按名字运行命令。** `sshctl run web-1 --argv uptime` 不需要交互输入，也没有 TUI，
  更不会去猜一个相似的名字。
- **为脚本和 AI Agent 设计。** 加上 `--json`，每次结果都是一份 JSON，
  带稳定的 `error` 错误码和退出状态。
- **安全的文件复制。** 上传、下载和服务器之间的复制都用 SHA-256 校验，
  不会留下写了一半的文件。
- **跳板机和不稳定的网络。** 可以经堡垒机连接、等待正在重启的服务器，
  并且只重试那些可以安全重试的失败。
- **经过验证的更新。** `ssm update` 会先校验发布包的校验和与 Sigstore 来源证明，
  再替换程序。

## 安装

需要 macOS 或 Linux，以及 `curl`、`jq`、`sha256sum` 或 `shasum`，
还有 [GitHub CLI](https://cli.github.com/)（`gh`）：安装脚本用它验证发布包的来源证明。

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
ssm --version
```

全新安装会得到 GitHub 当前的 latest 发布版，目前是 **v2.1.0**。要固定某个版本，
运行同一条命令，并给 `sh` 设置 `SSM_RELEASE_TAG=v2.1.0`：

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | SSM_RELEASE_TAG=v2.1.0 sh
```

安装脚本会把 `ssm` 和指向它的 `sshctl` 链接放进 `/usr/local/bin`
（用 `SSM_PREFIX` 修改），并把数据放在 `~/.config/ssm`（用 `SSM_CONFIG_DIR` 修改）。
如果没有 `/usr/local/bin` 的写权限，可以装到自己的目录，并确保该目录在 `PATH` 里：

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | SSM_PREFIX="$HOME/.local/bin" sh
```

Windows 上请从[最新发布页](https://github.com/Cd1s/ssm/releases/latest)下载
`ssm-windows-amd64.exe`（或 `ssm-windows-arm64.exe`），并按
[来源证明运行手册](docs/update-provenance-runbook.zh-CN.md)里的方法验证。

## 快速开始

例子里的服务器 `web-1` 是虚构的，地址 `203.0.113.10` 是文档专用地址。

1. **添加服务器。** 第一条命令创建保存主密码的私有文件，保险箱会在第一次使用时创建。
   请保管好这个文件，不要提交到仓库。

   ```bash
   mkdir -p ~/.config/ssm
   (umask 077; head -c 32 /dev/urandom | base64 > ~/.config/ssm/master.pass)
   sshctl host upsert web-1 --host 203.0.113.10 --user deploy \
     --key-file ~/.ssh/id_ed25519 --json
   ```

2. **信任它的主机密钥。** 先查看指纹，通过可信渠道核对，再接受这一枚指纹。

   ```bash
   sshctl host-key inspect web-1 --json
   sshctl host-key accept web-1 --fingerprint SHA256:REPLACE_WITH_VERIFIED_FINGERPRINT --yes --json
   ```

3. **运行命令。** `--argv` 会把每个词原样传给服务器。

   ```bash
   sshctl run web-1 --argv hostname
   ```

4. **上传和下载文件。** `--sha256` 会校验复制结果。

   ```bash
   sshctl put web-1 ./notes.txt /tmp/notes.txt --sha256
   sshctl get web-1 /tmp/notes.txt ./notes-copy.txt --sha256
   ```

5. **给脚本用的 JSON。**

   ```bash
   sshctl --json run web-1 --argv hostname
   ```

   ```json
   {"ok":true,"alias":"web-1","exit":0,"stdout":"web-1\n"}
   ```

   真实结果还会带上 `host`、`user`、`latency_ms` 等字段。出错时 `ok` 为 `false`，
   `error` 说明原因。详见[自动化与 AI Agent](docs/reference.zh-CN.md#自动化与-ai-agent)。

## 常见任务

| 我想……                 | 命令                                                                  |
| ---------------------- | --------------------------------------------------------------------- |
| 列出我的服务器         | `sshctl host list`                                                    |
| 运行脚本               | `sshctl run web-1 -f deploy.sh`                                       |
| 运行 Python 脚本       | `sshctl run web-1 -f report.py --interpreter python3`                 |
| 在多台服务器上运行命令 | `sshctl map 'web-*' -j 8 --argv hostname`                             |
| 上传文件               | `sshctl put web-1 ./a.txt /tmp/a.txt`                                 |
| 下载文件               | `sshctl get web-1 /tmp/a.txt ./a.txt`                                 |
| 在两台服务器之间复制   | `sshctl cp web-1:/srv/app.tgz web-2:/srv/app.tgz`                     |
| 经堡垒机连接服务器     | `sshctl host update db --proxy-jump bastion`                          |
| 等服务器重新上线       | `sshctl wait web-1 --timeout 5m`                                      |
| 在多台电脑间共享保险箱 | `ssm login --server <url> --email <you> --password-file <file>`，然后 `sshctl sync` |
| 更新 ssm               | `ssm update`                                                          |

## 更新

```bash
ssm update
```

`ssm update` 会在校验校验和与来源证明之后，安装当前主版本下最新的稳定版。ssm 也会自动检查这类更新，最多每 6 小时一次；
如需关闭，在 `~/.config/ssm/settings.json` 里设置 `"auto_update": false`。
从 v1 升到 v2 是单独的、需要明确确认的一步：先读[迁移指南](docs/migration-v1-to-v2.zh-CN.md)，
再运行 `ssm update --major --yes`。

## 更多文档

- [参考手册](docs/reference.zh-CN.md)：所有命令、选项、设置、环境变量、错误码和退出状态。
- [安全策略](SECURITY.md)和[更新来源证明运行手册](docs/update-provenance-runbook.zh-CN.md)。
- [发布说明](RELEASE_NOTES.md)和[v1→v2 迁移指南](docs/migration-v1-to-v2.zh-CN.md)。
- 给 Codex、Hermes 等 Agent 使用的 [AI Agent skill](skills/agent-ssm/README.md)。

## 开发

使用 Go 1.26.8。日常检查运行 `go test ./...`，提交改动前运行 `go run ./cmd/verify fast`。
请向 `main` 分支提交 Pull Request，详见 [AGENTS.md](AGENTS.md) 和
[开发说明](docs/reference.zh-CN.md#开发与验证)。
