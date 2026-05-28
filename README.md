# ssm

面向 agent 的无头 SSH 管理器。SSH 主机信息保存在本机加密 vault 中，同步时只上传和下载加密后的数据，真正的 SSH 连接始终从当前机器发起。

[中文](README.md) | [English](README.en.md)

## 安装

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
```

安装脚本会从 `Cd1s/ssm` 下载当前系统匹配的程序，安装到 `/usr/local/bin/ssm`，并创建 `/usr/local/bin/sshctl -> /usr/local/bin/ssm`。`sshctl` 不是额外脚本，它和 `ssm` 是同一个二进制。

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

推荐放在你自己的 HTTPS 反向代理后面：

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
从 Cd1s/ssm 安装 SSM：
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh

创建 /root/.config/ssm，把提供的私有 master.pass 和 cloud.json 放进去，并执行 chmod 600。
执行 sshctl sync，然后用 sshctl status 和 sshctl list 验证。
以后连接服务器只使用 sshctl run <alias> '<command>'、sshctl shell <alias>、sshctl put <alias> <local> <remote>。
不要打印同步地址、密码、token、master.pass、cloud.json、私钥或 vault 内容。
```

项目内 agent skill 在 `skills/agent-ssm/SKILL.md`。

## 自动更新

`1.0.0` 起默认从 `Cd1s/ssm` 检查 GitHub 最新 release。发现更高版本时会替换当前程序。手动更新：

```bash
ssm update
```

## 安全规则

不要把真实同步域名、账号、邮箱、密码、token、私钥、`master.pass`、`cloud.json` 或 vault 内容写进公开文档、日志、提交、release notes 或聊天。
