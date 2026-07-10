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
sshctl list --json
sshctl sync
sshctl doctor <alias> --deep --json     # vault + 连通 + 远端健康
sshctl check <alias>

# 无头主机管理（变更先保存在本地，验证后显式 push）
sshctl host list --json
sshctl host upsert prod-api --host 203.0.113.10 --user root --port 22 --key-file /secure/prod-api.key --json
sshctl host update prod-api --port 2222 --json
sshctl host show prod-api --json
sshctl check prod-api
sshctl push

# 单机（字面 argv 或 stdin 脚本；连接默认复用）
sshctl run <alias> --argv hostname
sshctl run <alias> --json hostname
sshctl plan <alias> bash -c 'echo hi'   # 干跑：remote_command + risk，不连机
sshctl run <alias> --secret API_KEY=@./key.txt -- printenv API_KEY
sshctl run <alias> --shell bash -s <<'EOF'
echo "any quotes fine"
EOF

# 并行：多机 / 多脚本（舰队）
sshctl map limee-hk,aws-sg -j 8 hostname
sshctl map 'limee-*' --json uname -s
sshctl map host1,host2 --scripts a.sh,b.sh   # 每台×每个脚本并行
sshctl run host --scripts a.sh,b.sh          # 单机多脚本并行

# 文件与目录树
sshctl put <alias> ./dir /remote/dir
sshctl get <alias> /remote/dir ./dir

# 迁移后旧名软链
sshctl redirect set old-alias limee-hk
sshctl run old-alias hostname

sshctl push
```

连接失败 stderr：`ssm: error=dial_timeout|host_key_mismatch|alias_not_found|...`，退出码 **255**。默认 **连接复用**（`SSM_REUSE=0` / `--no-reuse` 关闭）。

### Agent 主机管理

| 命令 | 行为 |
|------|------|
| `sshctl host list/show ... --json` | 返回不含密码/私钥的结构化 inventory |
| `sshctl host add ...` | 仅新增；别名已存在时失败 |
| `sshctl host update ...` | 仅修改显式给出的字段；主机不存在时失败 |
| `sshctl host upsert ...` | 幂等声明；重复执行返回 `changed:false`，适合 agent 重试 |
| `sshctl host remove ... --yes` | 显式确认后删除；`--prune-key` 只清理已无引用的 key |

新增主机必须提供 `--host`、`--user` 和一种认证方式：`--key <已保存名称>`、`--key-file <路径>` 或 `--password-file <路径>`。密码和私钥不接受 inline 参数，JSON 结果只显示 `auth`/`key_name`。`upsert` 修改已有主机时，未提供认证参数会保留原认证。

结构化 host 变更会先确认远端 vault 已刷新，再原子保存到本机，并返回 `sync_pending:true`；远端检查失败会在写入前以 `sync_pull_failed` 停止。只有明确接受本地数据可能过期时才使用 `--offline`。变更不会静默 auto-push：先执行 `sshctl check` 或只读 `run` 验证，再显式执行 `sshctl push`，同步错误会有可靠的非零退出码。

### Agent 舰队：map 并行

| 命令 | 含义 |
|------|------|
| `sshctl map a,b,c -j 8 cmd` | 最多 8 路并行在 a/b/c 上跑同一命令 |
| `sshctl map 'web-*' hostname` | shell 风格 glob 选 alias |
| `sshctl map h --scripts s1.sh,s2.sh` | 单机多脚本并行 |
| `sshctl map a,b --scripts s1,s2` | host×script 笛卡尔积并行 |
| `sshctl map ... --plan` | 只展开目标与命令，不执行 |
| `sshctl map ... --json` | 结果数组：`ok/exit/stdout/error/latency_ms` |

某一台失败**不会**丢掉其它机器的结果；最终 exit 在有失败时非 0。

### 远程命令与引号

| 写法 | 行为 | 适用 |
|------|------|------|
| `sshctl run host --argv cmd arg1` | 始终逐参数 shell 转义，单参数也不例外 | agent 生成的字面 argv |
| `sshctl run host cmd arg1 arg2` | 多参数自动逐项转义；单字符串保留旧 shell 行为 | 兼容旧调用 |
| `sshctl run host -s <<'EOF'` | 正文从 SSH stdin 送入固定 `sh -s` runner | 多行、管道、重定向、任意引号 |
| `sshctl run host --shell bash -f x.sh -- arg` | shebang/显式 shell + 精确脚本参数 | Bash 脚本、生成脚本 |
| `sshctl run host --json cmd` | 结构化结果 | agent 解析 |
| `sshctl plan host cmd` | 干跑 + risk | 确认再执行 |
| `sshctl run host --secret K=@file cmd` | 密钥作远端 env，trace 脱敏 | 密钥不进 argv 展示 |

`-s`、`-f` 和 `--scripts` 不要求本地文件有执行权限，也不会把脚本文本嵌进 SSH command。SSM 会移除 UTF-8 BOM、统一 CRLF、拒绝 NUL/超大脚本，并根据 shell shebang 自动选择 `sh/bash/dash/ash/ksh/zsh`；无 shebang 默认 `sh`。`--plan/--json` 返回 `interpreter`、`stdin_bytes`、`script_sha256`，不回显脚本正文。

## 可选同步

你可以自己部署一个中心服务器，用来在多台机器之间同步加密后的 vault：

```bash
ssm register --server <sync-server-url> --email <email> --password-file <sync-password-file>
ssm login --server <sync-server-url> --email <email> --password-file <sync-password-file>
sshctl sync
```

中心服务器只保存加密 vault blob，不解密 SSH 密码或私钥。`sshctl list/run/shell/status` 和 `ssm list/exec/shell` 会在读取 vault 前检测远端 ETag；远端有新版本时会自动拉取。TUI 变更遵循 auto-sync 设置；面向 agent 的 `sshctl host` 变更故意留在本地，验证后用 `sshctl push` 明确同步。

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
新增/修改服务器用 sshctl host upsert/update ... --json；认证只从 --key-file/--password-file 读取。先 check，再 push。
字面参数用 sshctl run <alias> --argv <command> [args...]；含 shell 语法或多行内容用 sshctl run <alias> -s <<'EOF' ... EOF。
不要把生成脚本塞进 bash -c，也不要自行嵌套引号。也可用 sshctl shell、put、get。
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
