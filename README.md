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
sshctl run <alias> hostname
sshctl run <alias> bash -c 'echo "hello"'   # 多参数会自动 shell 转义，少踩引号坑
sshctl run <alias> -s <<'EOF'               # 复杂脚本：heredoc，零引号问题
echo "any quotes fine"
EOF
sshctl <alias> uname -sr                    # 类 SSH 简写：等价于 run
sshctl shell <alias>
sshctl put <alias> ./local-file /remote/dir/file   # 自动 mkdir -p 远端目录
sshctl get <alias> /remote/file ./local-file       # 下载
sshctl list --json
sshctl check <alias>                    # agent 分诊：连通 + hostname/uname
sshctl run <alias> --timeout 10s true   # 避免 dial 挂死
sshctl push
```

连接失败时 stderr 会带 `ssm: error=dial_timeout|host_key_mismatch|alias_not_found|...`，退出码 **255**（区别于远端命令的 exit code）。复杂脚本用 `-s` heredoc；不要在 `dial_*` 错误上反复改引号。

### 远程命令与引号（给 agent / 脚本）

| 写法 | 行为 | 适用 |
|------|------|------|
| `sshctl run host cmd arg1 arg2` | 每个参数单独 shell 转义后拼接 | 短命令、`bash -c '...'` |
| `sshctl run host 'cmd; cmd2'` | 单个参数原样作为远程 shell 脚本 | 管道、`&&`、经典写法 |
| `sshctl run host -s <<'EOF' ... EOF` | 从 stdin 读脚本 | 多行、任意引号 |
| `sshctl run host -f script.sh` | 本地脚本文件内容在远端执行 | 可复用脚本 |
| `sshctl run host --raw a b` | 仅空格拼接（OpenSSH 风格） | 需要 `ENV=1 cmd` 等兼容场景 |
| `sshctl host cmd...` / `sshctl host` | 等价 `run` / `shell` | 更像 `ssh host` |

## 可选同步

你可以自己部署一个中心服务器，用来在多台机器之间同步加密后的 vault：

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

把下面内容发给另一台机器上的 agent：

```text
从 Cd1s/ssm 安装 SSM：
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh

如果已有同步配置，把 master.pass 和 cloud.json 放到 /root/.config/ssm，并执行 chmod 600。
然后执行 sshctl sync，用 sshctl status 和 sshctl list 验证。
连接服务器优先用 sshctl run <alias> <command...> 或多行 sshctl run <alias> -s <<'EOF' ... EOF（少踩引号坑）。
也可用 sshctl shell <alias>、sshctl put <alias> <local> <remote>。
```

项目内 agent skill 在 `skills/agent-ssm/SKILL.md`。

## 自动更新

`1.0.0` 起默认从 `Cd1s/ssm` 检查 GitHub 最新 release。发现更高版本时会替换当前程序。手动更新：

```bash
ssm update
```

无头测试、离线环境或不希望程序启动时触网时，可以禁用 release 检查：

```bash
SSM_UPDATE_REPO=off ssm --version
```
