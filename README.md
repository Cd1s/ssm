# ssm

面向 Agent 与自动化的非交互 SSH vault 管理 CLI。`ssm` 和 `sshctl` 不启动 TUI、不打开交互 shell，也不等待终端输入。SSH 主机信息保存在本机加密 vault 中，同步时只传输加密数据，真正的 SSH 连接始终从当前机器发起。

[中文](README.md) | [English](README.en.md)

## 安装

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
```

安装脚本会从 `Cd1s/ssm` 下载当前系统匹配的程序，安装到 `/usr/local/bin/ssm`，并创建 `/usr/local/bin/sshctl -> /usr/local/bin/ssm`。`sshctl` 不是额外脚本，它和 `ssm` 是同一个二进制。

## 常用命令

```bash
sshctl --json status
sshctl --json host list
sshctl sync
sshctl --json doctor <alias> --deep     # vault + 连通 + 远端健康
sshctl check <alias>

# 无头主机管理（候选配置先验证，成功后才保存）
sshctl host list --json
sshctl host search prod-web --json       # 只返回候选，不自动选择或连接
sshctl host upsert prod-api --host 203.0.113.10 --user root --port 22 --key-file /secure/prod-api.key --verify --json
sshctl host update prod-api --port 2222 --verify --json
sshctl host show prod-api --json
sshctl push --only <transaction-id>
sshctl push --all

# 单条简单命令：最快路径，不创建 request 文件
sshctl --json run <alias> --argv hostname
sshctl --json run <alias> --argv uname -a
sshctl plan <alias> --argv hostname      # 干跑：remote_command + risk，不连机
sshctl run <alias> --shell bash -s <<'EOF'
echo "any quotes fine"
EOF

# 连续简单命令：一次同步/解密/建连，每行输入一个 JSON argv 数组
sshctl run <alias> --stream
["hostname"]
["uname","-a"]

# 动态参数、脚本、secret 和变更：类型化 JSON request
sshctl request --file ./request.json     # argv/script_file/secret_files 仅放路径

# 观察/接受 host key；accept 必须绑定刚观察到的完整指纹
sshctl host-key inspect <alias> --json
sshctl host-key accept <alias> --fingerprint SHA256:... --yes --json

# 并行：多机 / 多脚本（舰队）
sshctl map limee-hk,aws-sg -j 8 hostname
sshctl map 'limee-*' --json uname -s
sshctl map host1,host2 --scripts a.sh,b.sh   # 每台×每个脚本并行
sshctl run host --scripts a.sh,b.sh          # 单机多脚本并行

# 文件与目录树
sshctl put <alias> ./dir /remote/dir
sshctl put <alias> ./artifact.tar /srv/artifact.tar --sha256 --timeout 2m --json
sshctl put <alias> ./artifact.tar /srv/artifact.tar --resume=v1 --timeout 2m --json
sshctl get <alias> /remote/dir ./dir

# 迁移后旧名软链
sshctl redirect set old-alias limee-hk
sshctl run old-alias hostname

sshctl push --all  # 审查 status 后显式发布全部兼容变更
```

首次出现的 host key 和变化后的 host key 都会被普通 run/check 拒绝。不要使用自动 `ssh-keygen -R` + `ssh-keyscan` 捷径；先通过 `inspect` 获取 `observed_fingerprint`、`known_fingerprints` 与 `classification:new|mismatch|trusted`，经可信渠道核对后，再用完全相同的指纹显式 `accept --yes`。

regular-file `put` 始终写入同目录的私有临时文件，核对远端 byte count 后才原子 rename；加 `--sha256` 可做本地/远端 SHA-256 核验，`--timeout <duration>` 设置显式 deadline。JSON 成功与失败均报告 `stage`、`bytes_sent`、`integrity`、`atomic`、`resume`；错误区分 `local_read_failed`、SSH dial/auth、`remote_write_failed`、`transfer_timeout` 与 `integrity_failed`。目录上传保留旧 tar 行为，不声称 atomicity 或 integrity。

resume 仅支持 regular file，且必须用 `--resume=v1` 显式启用；未提供时旧 put 行为不变。v1 要求远端有 `sha256sum`，以协议版本、目标路径 hash、完整 local size 与 SHA-256 digest 绑定权限为 `0600` 的 sibling partial/metadata；append 前还会把远端 prefix digest 与本地同长度 prefix digest 核对。source 改变时使用独立 state，不复用旧 partial；corrupt、缺失或歧义 state 返回 `partial_state_mismatch|partial_state_incompatible`，绝不替换目标。完整 size/digest 通过后才 atomic publish。中断后的 v1 state 保留供 retry；后续 probe 会顺带清理同一目标超过 7 天的 `.ssm-resume-v1-*` state，operator 也可在审查后提前删除。结果包含 `bytes_reused` 与 `bytes_sent`。目录 resume 不支持。

`status` 默认检查配置的同步端点并在远端 ETag 变化时刷新；同步失败会返回 `error:sync_pull_failed`、`stage:sync_pull`，不会静默使用缓存。若 `cloud.json` 存在但格式错误或不可读，所有在线 inventory 操作都会以 `error:sync_config_error`、`stage:sync_config` 停止；请修复文件及其权限，或仅在明确接受陈旧缓存时显式使用 `--offline`。缺少 `cloud.json` 仍表示同步未配置。只有调用方明确接受陈旧数据时才使用 `sshctl --json status --offline`（或全局 `--offline`）。离线结果包含 `offline:true`、`remote_state:not_checked`、`freshness`、`cache_age_seconds`、最近 pull/push 时间、`pending_changes` 与不含 secret 的 `pending_mutations`（`id`、`alias`、`operation`、`created_at`）。mutation 结果返回稳定的 `transaction_id`；用 `push --only <transaction-id>` 发布单个已审查变更，其 preflight 会列出准确 alias/operation，无关变更继续 pending。仅在明确发布全部 pending change 时使用 `push --all`（裸 `push` 作为兼容路径仍表示全部发布）。

简单、固定、已审查的字面参数直接使用 `sshctl --json run <alias> --argv ...`，无需创建 request 文件。连续的简单命令可使用 `sshctl run <alias> --stream`：stdin 每行是一个 JSON 字符串数组，stdout 每行是一个紧凑 JSON 结果；进程启动时同步并解密一次，默认每 30 秒重新检查 inventory，刷新失败立即停止而不会使用陈旧数据。需要动态/不可信参数、脚本、secret 或 host 变更时，仍使用 `sshctl request --file`。项目不提供交互式 shell。

非 capture 的 human `run` 与目录传输诊断采用 outcome-buffered 行为：stdout/stderr 在结果确定前不会渐进显示，成功时逐字节原样回放，失败或取消时先脱敏再回放。每个诊断流使用权限受限的私有临时文件，硬上限为 8 MiB；超过上限会清理缓冲文件并使操作失败，不会静默截断为成功，也不会回放已缓冲的潜在 secret。该上限同时约束未终止行或未闭合结构化值在失败脱敏期间的内存增长。

### 凭据安全边界

密码、私钥和其他 secret 只能通过受限权限的文件路径引用。绝不要把它们或 vault 内容写入 JSON、命令行参数、日志、错误报告、GitHub Issue 或提交。`--password-file`、`--key-file`、`--master-pass-file` 与 request 的 `secret_files` 只读取路径指向的文件；结构化输出不会回显内容。

连接层失败的 JSON `error` 为 `dial_timeout|host_key_mismatch|alias_not_found|...`，通常退出码是 **255**。不要只凭 255 分类，因为远端程序本身也可能返回 255。默认 **连接复用**，作用域是当前 `sshctl` 进程（`SSM_REUSE=0` / `--no-reuse` 关闭）；普通 one-shot 进程结束时连接随之关闭，`run --stream` 让同一进程跨多条命令持续复用。全局 `sshctl --json ...` 会让参数、解锁、alias 和同步错误也只输出一个 JSON 值；stream 模式显式使用 NDJSON，一行输入对应一行输出。

### 稳定 JSON 错误契约

失败对象使用 `ok:false`、`error`、`message`、`hint`、`exit`，并在可定位阶段时提供 `stage`。canonical 分类包括：`alias_not_found`、`invalid_arguments`、`invalid_request`、`sync_pull_failed`、`sync_push_failed`、`dial_timeout|dial_refused|dial_network`、`host_key_unknown|host_key_mismatch`、`auth_failed|no_auth_configured`、`session_failed`、`interpreter_not_found`、`script_syntax_error|remote_script_failed|remote_failed` 与 `transfer_failed`。`host_not_found` 和 `invalid_args` 是 v1.3 及更早版本的旧值；v1.4 起统一为 `alias_not_found` 和 `invalid_arguments`。调用方应依据 `error` 与 `stage` 分类，`exit` 只用于进程控制。

Agent 排障示例：

- alias miss：检查 `sshctl --json host list` 或 `host search`；绝不自动执行 suggestion。
- sync pull failure：停止；修复连接，或仅在明确接受 stale inventory 后使用 `--offline`，不会静默 fallback。
- sync push failure：检查 `status.pending_mutations`，重试 `push --only <same-id>`；不得扩大为 push-all。
- host-key change：先 `host-key inspect --json`，out-of-band 核验 `observed_fingerprint`，再 exact `accept ... --yes`；不得自动 remove/rescan。
- remote failure：`remote_failed|remote_script_failed` 表示 SSH transport 已成功；依据 `stage`、`stderr` 和 remote exit（包括 255）处理，不得误判为 transport failure。
- transfer failure：依据 `stage`、`bytes_sent`、`bytes_reused`、`resume`、`integrity`；不得 append incompatible partial。

### Agent 类型化 request（v1.4；schema version 1）

`sshctl request` 从 stdin 或 `--file` 读取 schema version 1。运行请求必须在 `argv`、`shell_command`、`script_file` 中三选一；`secret_files` 只接受文件路径。推荐 agent 通过文件写入工具创建 JSON，而不是在 shell 中拼接或 `echo` JSON。

```json
{
  "version": 1,
  "op": "run",
  "alias": "prod-api",
  "argv": ["printf", "%s\n", "value with spaces and ' quotes"],
  "timeout": "15s"
}
```

脚本请求用 `script_file`、`script_args`、`shell` 和 `secret_files`。脚本默认先在远端使用同一个解释器执行 `-n` 语法预检；失败返回 `script_syntax_error`，正文不会执行。请求结果包含 `mode: argv|shell_command|script`、`transport: ssh_exec|ssh_stdin` 和 `preflight`。

resumable put 同样使用 request schema version 1，并显式声明 resume capability 版本：

```json
{
  "version": 1,
  "op": "put",
  "alias": "prod-api",
  "local_path": "/secure/artifact.tar",
  "remote_path": "/srv/artifact.tar",
  "resume": "v1",
  "sha256": true,
  "timeout": "2m"
}
```

Host request 使用 `op: host.upsert|host.update|...` 与嵌套 `host` 字段，新增/修改默认 `verify:true`：

```json
{
  "version": 1,
  "op": "host.upsert",
  "alias": "prod-api",
  "host": {
    "address": "203.0.113.10",
    "port": 22,
    "user": "root",
    "key_file": "/secure/prod-api.key",
    "verify": true,
    "push": false
  }
}
```

### Agent 主机管理

| 命令 | 行为 |
|------|------|
| `sshctl host list/show ... --json` | 返回不含密码/私钥的结构化 inventory |
| `sshctl host search <query> --json` | 按 alias/address/user/group 过滤；`ambiguous:true` 时必须由调用方选择 |
| `sshctl host add ...` | 仅新增；别名已存在时失败 |
| `sshctl host update ...` | 仅修改显式给出的字段；主机不存在时失败 |
| `sshctl host upsert ... --verify` | 幂等声明；候选连接验证失败时 vault 不变 |
| `sshctl host remove ... --yes` | 显式确认后删除；`--prune-key` 只清理已无引用的 key |

新增主机必须提供 `--host`、`--user` 和一种认证方式：`--key <已保存名称>`、`--key-file <路径>` 或 `--password-file <路径>`。密码和私钥不接受 inline 参数，JSON 结果只显示 `auth`/`key_name`。`upsert` 修改已有主机时，未提供认证参数会保留原认证。

结构化 host 变更会先确认远端 vault 已刷新；`--verify` 使用内存中的候选 vault 建连并运行 `hostname; uname -sr`，失败返回 `verification_failed`、`applied:false`，加密 vault 不发生变化。成功后才原子保存并返回 `sync_pending:true`。`--push` 必须和 `--verify` 一起使用；同步失败时本地变更保留并返回 `sync_push_failed`。只有明确接受本地数据可能过期时才使用 `--offline`。

`doctor <alias> --json` 在 exact miss 时返回 `resolved_alias` 和安全的 `candidates`，但绝不选择候选或发起连接；同时报告 local/remote vault 状态、最近 pull/push、pending 状态，以及最近一次 reviewed merge 的非敏感 alias/key-name conflict 元数据。若本地与远端从同一 cached ETag 后同时变化，自动刷新返回 `sync_conflict` 并保留两端，`sshctl --offline --json doctor` 会显示 `sync_conflict` 的非敏感 blob 标识。检查 `merge_report.conflicts`/`sync_conflict` 后，明确选择 pull 或修复本地并 push。

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
| `sshctl --json run host --argv cmd arg1` | 单次进程直跑；始终逐参数 shell 转义 | 简单、固定、已审查的字面 argv |
| `sshctl run host --stream` | 每行一个 JSON argv 数组；复用同步、解密和 SSH 连接 | 连续、迭代式简单命令 |
| `sshctl run host cmd arg1 arg2` | 多参数自动逐项转义；单字符串保留旧 shell parsing | 仅兼容旧调用 |
| `sshctl run host -s <<'EOF'` | 正文从 SSH stdin 送入固定 `sh -s` runner | 多行、管道、重定向、任意引号 |
| `sshctl run host --shell bash -f x.sh -- arg` | shebang/显式 shell + 精确脚本参数 | Bash 脚本、生成脚本 |
| `sshctl run host --preflight -f x.sh` | 远端同解释器 `-n` 后再执行 | 阻止语法错误产生副作用 |
| `sshctl request --file request.json` | argv/脚本参数来自 JSON 数组 | 动态或不可信输入，无本地 shell 引号歧义 |
| `sshctl run host --json cmd` | 结构化结果 | agent 解析 |
| `sshctl plan host cmd` | 干跑 + risk | 确认再执行 |
| `sshctl run host --secret K=@file cmd` | 密钥作远端 env，trace 脱敏 | 密钥不进 argv 展示 |

`-s`、`-f` 和 `--scripts` 不要求本地文件有执行权限，也不会把脚本文本嵌进 SSH command。SSM 会移除 UTF-8 BOM、统一 CRLF、拒绝 NUL/超大脚本，并根据 shell shebang 自动选择 `sh/bash/dash/ash/ksh/zsh`；无 shebang 默认 `sh`。`--plan/--json` 返回 `interpreter`、`stdin_bytes`、`script_sha256`，不回显脚本正文。语法预检只能保证 shell 能解析脚本，运行期依赖、权限和业务逻辑仍可能失败。

直接单字符串 run 与 request `shell_command` 仅为兼容路径，会触发远端 shell quoting、glob、expansion、substitution、redirection；generated/untrusted text 可能改变语义或执行非预期代码。新 agent flow 必须用 request `argv` 表达字面参数，或用 `script_file` 表达 shell 语义。

旧的批量迁移命令不再有危险默认值：`ssm import-json` 必须明确选择 `--merge`，或使用 `--replace --yes` 执行整库替换。单机变更始终使用 `sshctl host` 或 request。

## 可选同步

你可以自己部署一个中心服务器，用来在多台机器之间同步加密后的 vault：

```bash
ssm register --server <sync-server-url> --email <email> --password-file <sync-password-file>
ssm login --server <sync-server-url> --email <email> --password-file <sync-password-file>
sshctl sync
```

中心服务器只保存加密 vault blob，不解密 SSH 密码或私钥。`sshctl list/run/status` 和 `ssm list/exec` 会在读取 vault 前检测远端 ETag；远端有新版本时会自动拉取。Agent host mutation 以 transaction 留在本地：单个 reviewed change 用 `push --only <transaction-id>`，只有审查全部 pending mutation 后才用 `push --all`；裸 `push` 是兼容 push-all。

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
简单固定命令直接使用 sshctl --json run <alias> --argv ...；连续简单命令使用 sshctl run <alias> --stream。
动态或不可信参数使用 sshctl request --file <json>：字面参数放 argv 数组，脚本使用 script_file/script_args，secret_files 只放路径。
新增/修改服务器用 host.upsert/host.update request，保持 verify:true；成功后只用 push --only 发布返回的 transaction_id，审查全部 pending mutation 后才可 push --all。
兼容 CLI 中字面参数用 --argv，复杂脚本用 --preflight -f；不要把生成脚本塞进 bash -c。
```

项目内 agent skill 在 `skills/agent-ssm/SKILL.md`。

## 自动更新

`1.0.0` 起默认从 `Cd1s/ssm` 检查 GitHub release。自动更新和普通手动更新只会替换为当前 major 内的更高版本；发现更高 major 时只报告迁移可用，不会替换当前程序。普通手动更新：

```bash
ssm update
```

查看完整的新 major 迁移审查（不替换程序）：

```bash
ssm update --major
```

完成审查后，唯一的非交互跨 major 授权路径是：

```bash
ssm update --major --yes
```

无头测试、离线环境或不希望程序启动时触网时，可以禁用 release 检查：

```bash
SSM_UPDATE_REPO=off ssm --version
```
