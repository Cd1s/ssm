# ssm

## 先用一句话认识它

`ssm` 是给 Agent、脚本和自动化使用的非交互 SSH 管理工具：它帮你保存主机信息、检查连接、运行命令和传文件，但不会打开 TUI，也不会等你在远端输入命令。适合希望把 SSH 操作安全、可重复地交给脚本或 Agent 的人。

`ssm` 和 `sshctl` 是同一个二进制，只是命令名不同。安装后通常会同时得到 `/usr/local/bin/ssm` 和指向它的 `/usr/local/bin/sshctl`；下面用更适合 Agent 的 `sshctl` 举例。

密码和私钥不会写进命令输出。主密码默认从本机 `~/.config/ssm/master.pass` 读取；主机密码、私钥和主机信息保存在本机加密 vault 中。需要新增或修改主机时，只给 `--password-file`、`--key-file` 等受限文件路径，不把 secret 内容写进命令、JSON、日志或提交。

如果启用了同步服务器，它看到的只是加密后的 vault blob，不会看到解密后的主机清单、SSH 密码或私钥；真正的 SSH 连接始终从当前这台机器发起。

[中文](README.md) | [English](README.en.md)

## 目前版本：v2.0.2

GitHub 当前 latest Release 是 **v2.0.2**，所以全新安装下面的一行命令会得到 v2.0.2。已有 v1.4.3/v1.4.4 用户执行普通 `ssm update` 时仍留在 major 1；只有完成审查并明确执行 `ssm update --major --yes` 才会跨到 v2。迁移细节见[v1→v2 迁移指南](docs/migration-v1-to-v2.zh-CN.md)，来源与签名验证见[更新来源凭证运行手册](docs/update-provenance-runbook.zh-CN.md)。

## 3 分钟上手

按顺序执行下面的命令。最后一条中的 `my-server` 必须替换为你在“列出主机”结果里看到的**完整 alias**；不要根据相似名称猜一个。

### 1. 安装

```bash
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
```

### 2. 验证版本

```bash
sshctl --json --version
```

应看到版本字段为 `2.0.1`。如果 `sshctl` 不存在，重新打开终端或检查 `/usr/local/bin` 是否在 `PATH` 中。

### 3. 查看状态

```bash
sshctl --json status
```

它会告诉你同步是否已配置、状态是否 fresh，以及有没有待发布的本地变更。没有配置同步时，结果会明确说明 unconfigured。默认的 local-first 模式下它还会报告最近一次同步的结果和缓存年龄（`remote_state`、`last_sync_error`、`cache_age_seconds`、`inventory_stale`），同步端点不可达时也不会失败，详见“同步模式”。

### 4. 列出主机

```bash
sshctl --json host list
```

记下要使用的精确 alias，例如你自己的 `my-server`。搜索只返回候选，不会自动选择或连接：

```bash
sshctl host search my --json
```

### 5. 对一个精确 alias 运行 hostname

```bash
sshctl --json run my-server --argv hostname
```

这里的 `my-server` 是示例名；请换成上一步列出的 alias。`--argv hostname` 表示把 `hostname` 作为一个明确的远端参数传递，不经过本地 shell 拼接。

如果这是第一次使用，还没有主机，可以先看下面“添加或修改主机”；如果出现 `host_key_unknown`、`host_key_mismatch` 或 `host_key_type_changed`，先按“检查连接”中的 host key 流程核验指纹。

## 先认识 6 个词

| 词 | 小白解释 |
| --- | --- |
| **vault** | 本机加密保险箱，保存主机资料以及密码/私钥的安全引用；同步时只传加密数据。 |
| **alias** | 你给一台主机起的精确名字。搜索结果只是候选，连接前必须选定完整 alias。 |
| **sync** | 在本机和同步服务器之间拉取或推送加密 vault 状态；它不是 SSH 连接。 |
| **push** | 把已经审查过的本地变更发布到同步服务器；必须指定 transaction ID 或经审查的全部 pending 范围。 |
| **request** | 一个版本为 1 的 JSON 请求文件，给动态参数、脚本、secret 文件路径、传输或主机变更使用。 |
| **host key** | SSH 用来确认“这还是同一台主机”的指纹。首次出现或发生变化时，先 inspect、通过可信渠道核验，再显式 accept。 |

## 按任务查命令

下面每组都先说明什么时候用，再给最小可用命令。示例 alias 是通用的，示例地址 `203.0.113.10` 来自 RFC 5737 文档地址段，不代表真实主机。

### 查看或搜索主机

当你只想知道 vault 里有哪些连接，或想从多个候选中找出目标时：

```bash
sshctl --json host list
sshctl host search my --json
sshctl host show my-server --json
```

`search` 不会自动挑选候选；最终连接、检查或运行命令都使用精确 alias。

### 检查连接

当你要先确认本地 vault、同步状态和 SSH 是否正常时：

```bash
sshctl check my-server --json
sshctl --json doctor my-server --deep
```

遇到新 host key、key mismatch 或 key 类型变化时，先观察并核对完整指纹：

```bash
sshctl host-key inspect my-server --json
sshctl host-key accept my-server --fingerprint SHA256:REPLACE_WITH_VERIFIED_FINGERPRINT --yes --json
```

第二条命令中的指纹只能替换成你通过可信渠道核验过的 `observed_fingerprint`；不要用自动 `ssh-keygen -R` 加 `ssh-keyscan` 代替核验。

sshctl 会按 `known_hosts` 中该主机已有的密钥类型（如 ed25519）优先协商，所以先用 OpenSSH 连过的主机不会因服务器同时提供 ECDSA 而误报。`host_key_mismatch` 表示同一类型的密钥变了；`host_key_type_changed`（inspect 状态 `type_changed`）表示服务器不再提供 `known_hosts` 里记录过的任何类型。`accept` 只替换同一类型的条目，该主机的其它类型条目与其它主机的行保持不变。

### 运行命令

当你要在一台已选定的主机上执行一个固定、简单的命令时：

```bash
sshctl --json run my-server --argv hostname
sshctl --json run my-server --argv uname -sr
```

别名之后，`--argv`、`--` 或第一个非选项参数即开始远端命令；其后的全部内容（包括 `-h`、`--help`、`--json`）原样交给远端程序（`sshctl run my-server --argv df -h` 会真的执行 `df -h`）。`-h/--help` 和 `--json` 只在这个边界之前才是 sshctl 的选项。`exec`、`plan`、`map` 以及 `-f`/`-s`/`--scripts` 模式下 `--` 之后的脚本参数同样适用。

#### 本地 stdin 的转发规则

`sshctl run` 把本地 stdin 转发给远端命令的规则是显式的：

- `--stdin`：任何模式（human、`--json`）都转发本地 stdin，EOF 时关闭远端 stdin。`printf 'a\nb\n' | sshctl --json run my-server --stdin --argv cat` 的 `stdout` 为 `"a\nb\n"`。
- `--no-stdin`（等价 `ssh -n`）：不转发。
- `--stdin-file <path>`：等价 `< path`，任何模式都生效，也可用于 request JSON 的 `stdin_file`。
- 都未指定时：human 模式在 stdin 不是终端时直接转发（不再探测数据是否已就绪，所以慢速上游如 `pg_dump | sshctl run ...` 不会被丢弃）；`--json` 默认仍不转发。此时若 stdin 是管道或文件（不是终端或 `/dev/null`），JSON 结果带 `"stdin_forwarded": false` 和一条 `warning`，提示加 `--stdin`；转发时带 `"stdin_forwarded": true`。
- `SSM_FORWARD_STDIN=1` 等价默认开启转发（含 `--json`），`SSM_FORWARD_STDIN=0` 等价 `--no-stdin`；显式选项优先于环境变量。
- `-s`、`-f`、`--scripts` 的脚本正文已经占用远端 stdin，与 `--stdin`/`--stdin-file` 同用返回 `invalid_arguments`；`map` 与 `run --stream` 同样拒绝 `--stdin`/`--stdin-file`。

去掉探测后，human 默认模式下若 stdin 是永不结束的管道（CI 或 agent 继承的 stdin 常见如此）且远端命令会读取 stdin，命令会一直等待；此时加 `--no-stdin` 或 `</dev/null`。

在 `while read h; do ...; done < hosts.txt` 这类循环里，务必给循环内的每次调用加 `--no-stdin`（或 `</dev/null`），否则第一次调用会把剩余的输入转发给远端：

```bash
while read -r h; do sshctl run "$h" --no-stdin --argv uptime; done < hosts.txt
```

需要连续执行多条简单命令时，可以复用同一进程和连接；每行输入一个 JSON argv 数组：

```bash
sshctl run my-server --stream
["hostname"]
["uname","-sr"]
```

在线 stream 的 `--refresh` 必须为正数；`--refresh=0` 只有在显式全局 `--offline` 时才允许。复杂 shell 语法、动态参数或 secret 使用 request 文件；不要把生成的脚本塞进 `bash -c`。

#### 运行脚本（shell 或 Python）

`-f`/`-s` 通过 SSH stdin 发送脚本正文，不会在远端写临时文件。不带 `--interpreter` 时按脚本 shebang 选 shell（`#!/bin/bash`、`#!/usr/bin/env bash` 用 bash）；没有 shebang 则用 `sh`。shebang 指向 python3 等非 shell 程序时会返回 `invalid_arguments` 并提示加 `--interpreter`。

```bash
sshctl --json run my-server -f report.py --interpreter python3 -- a b   # sys.argv[1:] == ['a', 'b']
sshctl run my-server -f deploy.sh --shell bash
```

显式 `--interpreter` 视为用户已确认，不受 shell 白名单限制。取值只能是一个程序名、一个绝对路径，或 `env <name>`（例如 `--interpreter "env python3"`）；带参数或含 shell 元字符的值会被拒绝。非 shell 解释器以 `<解释器> - <参数...>` 启动，要求它在收到 `-` 时从 stdin 读脚本（python3、perl、ruby 支持）。远端缺少解释器时返回 `interpreter_not_found`（退出码 127）。`--preflight` 只做 shell 语法检查，与非 shell 解释器同时使用会被拒绝。`--shell` 仍是仅限 shell 的选项；`--interpreter bash` 继续可用，等同 `--shell bash`。request 文件在 `script_file` 旁用 `"interpreter"` 字段表达同样语义。

### 上传或下载文件

当你要传普通文件或目录树时：

```bash
sshctl put my-server ./notes.txt /tmp/notes.txt --sha256 --json
sshctl get my-server /tmp/notes.txt ./notes.txt --sha256 --timeout 30s --json
```

`--sha256` 只适用于需要完整性核验的普通文件；目录传输的保证与普通文件不同，详见[进阶契约](#进阶--给-agent-与自动化)。远端依次探测 `sha256sum`、`shasum -a 256`、`openssl dgst -sha256`，三者都没有时返回 `error:integrity_tool_unavailable`（去掉 `--sha256` 即可）。`put` 自动创建的父目录默认权限为 `0755`，可用 `--dir-mode <八进制>`（如 `--dir-mode 0750`）覆盖；文件本身仍通过私有临时文件加 rename 写入，权限语义不变。`get` 与 `put` 接受同样位置无关的 `--json`、`--timeout`、`--sha256`（下载后在本地计算并与远端摘要比对，不一致则失败且不替换目标）；`get` 不支持 `--resume`。

#### 没有 POSIX shell 的目标（SFTP）

默认（主机 `transfer: auto`）通过远端 POSIX shell 传输。目标的 shell 无法回答路径探测（输出不是 `DIR`/`FILE`/`MISSING`、shell 报错，或整个 exec 被拒）时，`get`/`put` 返回 `error:remote_shell_unsupported`（`stage:discovery`），不再误报路径不存在。此时改用 SFTP 子系统（同一条 SSH 连接，不执行任何远端命令）：单次加 `--sftp`，或把主机设为 `sftp`：

```bash
sshctl put win-box ./notes.txt C:/temp/notes.txt --sftp --sha256 --json
sshctl host update win-box --transfer sftp --offline --json   # auto|shell|sftp，默认 auto
```

request v1 用 `host.transfer` 设置主机字段，`put`/`get` 请求可带顶层 `transfer`（`auto|shell|sftp`，只对这一次操作覆盖主机设置）。SFTP 目前只支持单个普通文件：目录和 `put --resume` 返回 `error:unsupported_transfer_option`；服务器没有 sftp 子系统返回 `error:sftp_unavailable`。SFTP 的保证与 shell 路径不同，结果里的字段如实反映：

- `get`：先 `Stat` 判断类型，流式写入本地 staging 再原子发布（`atomic:true`）。SFTP 没有远端摘要命令，`--sha256` 对收到的字节流计算摘要，并核对远端报告的大小和落盘文件，`remote_sha256` 即该流摘要；不加 `--sha256` 时 `integrity:not_checked`。
- `put`：写入同目录的私有临时文件后 rename。服务器支持 `posix-rename@openssh.com` 时原子替换（`atomic:true`）；不支持时先把旧目标移到一旁再 rename，失败会还原，但结果报 `atomic:false`。`--sha256` 通过 SFTP 读回临时文件在本地比对（`integrity:sha256_verified`），服务器不允许读回时返回 `integrity_tool_unavailable`（`integrity:not_available`）且不发布；不加时只核对大小（`size_verified`）。`--dir-mode` 对新建父目录同样生效。

### 添加或修改主机

当你要新增一台主机，或只改现有 alias 的某个字段时。先用 `--verify` 检查候选配置，验证成功后才保存：

```bash
sshctl host upsert my-server \
  --host 203.0.113.10 --port 22 --user demo \
  --key-file /secure/my-server.key --verify --json

sshctl host update my-server --port 2222 --verify --json
```

`--transfer auto|shell|sftp`（request v1 的 `host.transfer`）设置该主机 `put`/`get` 使用的协议，默认 `auto`（不写入 vault）；见[上传或下载文件](#上传或下载文件)。

私钥和密码只能通过 `--key-file`、`--password-file` 或已保存的 `--key` 名称引用，不能作为 inline 值。变更默认只保存在本机 pending ledger；成功结果会返回一个待审查的 `transaction_id`。幂等 no-op 会返回 `changed:false`、`action:"unchanged"` 并省略 ID；do not publish 这个 no-op。

### 发布已审查的变更

当你已经检查过变更内容，并确认要让同步服务器接收它时，只发布返回的那个 transaction：

```bash
sshctl --json push --only <transaction-id>
```

把 `<transaction-id>` 替换为刚才命令返回的精确 ID。不要使用裸 `push`；只有在审查了调用开始时的全部 pending 变更后，才使用 `sshctl --json push --all`。

## 安全边界（请保留）

- 不把密码、私钥、master pass、token、`cloud.json` 或解密后的 vault 内容放进命令参数、JSON、日志、Issue、PR 或提交。
- 不自动选择 alias，不把候选名称当成精确目标。
- host key 首次出现或变化时必须先 inspect、带外核验完整 SHA-256 指纹，再显式 accept。
- 默认 local-first：读命令直接用本地清单，同步服务器不挡命令；使用本地清单不是静默的，`status` 报告 `remote_state`/`last_sync_error`/`cache_age_seconds`，清单过期时有 `inventory_stale` 和 stderr 警告。需要“刷新失败即失败”时设置 `sync_mode: strict`。
- 发布必须有明确 scope；`push --only <transaction-id>` 只发布一个 reviewed transaction，相关依赖未满足时也不会偷偷扩大范围。

## 更新与回滚

全新安装跟随 GitHub latest，目前是 v2.0.2。普通更新只在已安装的 major 内选择更高版本：

```bash
ssm update
```

v1.4.3/v1.4.4 用户如需迁移到 v2，先生成不安装的审查报告：

```bash
ssm update --major
```

确认发布说明、自动检查、外部消费者和回滚准备都通过后，唯一的跨 major 授权路径是：

```bash
ssm update --major --yes
```

`--major --yes` 不会跳过 SHA-256、精确 tag、keyless provenance 或失败恢复检查；失败时保留旧可执行文件和恢复证据。详见[迁移指南](docs/migration-v1-to-v2.zh-CN.md)与[来源凭证运行手册](docs/update-provenance-runbook.zh-CN.md)。

## 开发与验证

日常开发直接运行 `go test ./...`，任何较新的 Go 都可以；宿主机不是固定工具链时，`cmd/verify` 里检查“宿主机就是固定版本”的子测试会显示 SKIP 并写明原因，而不是失败。设置 `SSM_VERIFY_REQUIRE_PINNED=1`（官方 CI 已设置）会强制执行这些检查。

正式 gate 是 `go run ./cmd/verify ci`，需要精确的固定工具：Go 1.26.8 和 golangci-lint 2.11.4。缺少或版本不符时，verify 会在提示里给出获取命令：

```bash
# 固定 Go 工具链（由 Go 自动下载）
GOTOOLCHAIN=go1.26.8 go run ./cmd/verify ci

# 固定 golangci-lint
GOBIN=<dir> go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4
PATH=<dir>:$PATH GOTOOLCHAIN=go1.26.8 go run ./cmd/verify ci
```

## 进阶 / 给 Agent 与自动化

先读[官方 Agent Skill](skills/agent-ssm/SKILL.md)和[版本兼容矩阵](skills/agent-ssm/references/version-compatibility.md)。它们定义了 v1.4.3/v1.4.4 兼容分支，以及受支持的 v2.0.0 与当前 v2.0.2 共用的 v2 兼容分支各自可以使用的 schema 和字段。

### 结构化输出与 request

普通 `--json` 调用输出一个 JSON 值；显式 `run --stream` 输出逐行 NDJSON。Agent 应按 `ok`、`error`、`stage`、`exit` 和 `hint` 分类；远端程序本身也可能退出 255，不能只看退出码判断 SSH 是否失败。

写错命令时 sshctl 会给出提示而不是当作别名：第一个词不是已知子命令时仍按 `sshctl <alias> <command>` 简写处理，别名不存在才判断它是不是命令。`ssm` 独有的命令（如 `keys`、`login`）、与子命令只差一两个字符的拼写（如 `stauts`、`hostkey`）返回 `unknown_command`（退出码 2），`hint` 给出正确的入口或命令，相近的命令名放在 `candidates`；`ssm` 入口对 sshctl 独有命令和拼写错误同样提示（human 模式下有建议时返回 `unknown_command` 和退出码 2；没有建议时保持旧的 `Unknown command` 输出，退出码不变）。别名与命令同样接近（平局）或更近，包括 redirect 的旧名，则按别名处理，返回 `alias_not_found`。其余情况仍是 `alias_not_found`（退出码 255），`candidates` 是编辑距离最近的别名，只是候选，绝不会自动选择或执行。`run`/`exec`/`plan`/`map` 的未知选项返回 `invalid_arguments`（退出码 2），`hint` 会给出建议，例如 `--script-file` 提示 `-f`、`--fetch` 提示 `get`，其余按真实选项表的编辑距离匹配。

#### 退出码与传输错误

`--json` 模式下以 `error` 字段为准，不要看进程退出码：远端程序可以返回任意退出码（包括 1、2、255），而 `2>&1 | tail` 这类管道还会丢掉退出码。

| 退出码 | 含义 |
|---|---|
| 0 | 成功。 |
| 1 | sshctl 的非 SSH 传输层失败：`internal`、vault、同步与更新错误，所有 `host` 与 `host-key` 子命令失败（包括其中的 `alias_not_found`），`script_syntax_error`，以及 `put`/`get` 的传输错误（`remote_write_failed`、`transfer_timeout`、`integrity_failed`、`partial_state_*`、`local_read_failed`）；或远端命令返回 1。请读 `error`。 |
| 2 | 参数或 request 无效（`invalid_arguments`、`invalid_request`），或远端命令返回 2。 |
| 127 | 远端脚本解释器不存在（`interpreter_not_found`），或远端命令返回 127。 |
| 128 + 信号编号 | 本地 SIGINT/SIGTERM/SIGHUP 中断了 `run`（`interrupted`；130、143、129）。信号已转发，远端命令可能仍在运行。 |
| 255 | `run`、`map`、`check`、`doctor`、`put`、`get` 的 SSH 传输层失败：`dial_timeout`、`dial_refused`、`dial_network`、`handshake_failed`、`host_key_unknown`/`host_key_mismatch`/`host_key_type_changed`（连接被拒绝）、`auth_failed`、`no_auth_configured`、`session_failed`、`connection_lost`；以及 `run`、`map`、`check`、`doctor` 的 `alias_not_found`。远端命令本身也可能返回 255。 |
| 其它值 | 远端命令自己的退出码，原样透传。 |

`map` 以第一个失败结果的退出码退出；数组里每个结果各自带 `error`。`put`/`get` 传输中途断开时与 `run` 一样返回 `connection_lost` 和 255，因为这是传输层失败，而不是传输专属错误。

**契约变化。** `put`/`get` 传输中途断开，原来报 `remote_write_failed`（下载为 `remote_read_failed`）和退出码 1，现在报 `connection_lost`，退出码 255，并带 `outcome:"unknown"`。sshctl 自己因 `--timeout` 中止文件或目录 `get`、文件 `put` 的行为不变：`transfer_timeout`、退出码 1、没有 `outcome`。`host` 子命令的 `alias_not_found` 在 JSON 中 `exit` 为 255，进程退出码为 1；请以 `error` 字段为准。

是否可以安全重试，取决于命令有没有发出：

- 可以重试：`dial_timeout`、`dial_refused`、`dial_network`；`handshake_failed`（`stage:handshake`，TCP 已连上但 SSH 握手失败，例如 EOF、connection reset 或协议错误，命令没有发出）；以及 `stage:session` 的 `session_failed`（会话没能打开，命令没有发出）。`no common algorithm` 这类确定性的握手失败每次都会同样失败，重试没有意义，应修正算法或服务器配置。`auth_failed` 和 `host_key_*` 保持各自的错误码，需要修复而不是重试。
- 不可安全重试：`connection_lost`（`stage:remote_execution`，并带 `outcome:"unknown"`）。命令发出后连接中断，例如主机重启或执行了 `sysupgrade`，远端命令可能仍在运行，也可能已经结束。先去主机上确认进程状态。

`outcome` 是加性字段，只出现在 `connection_lost` 上。

动态或不可信参数、脚本、secret 文件路径、传输和主机变更使用 schema version 1 的[request-v1 schema](skills/agent-ssm/references/request-v1.schema.json)：

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

v2 的 request schema 支持 `op:get`；v1.4.3/v1.4.4 必须使用[兼容桥接 schema](skills/agent-ssm/references/request-v1-bridge.schema.json)，不能假设 v2-only 字段。

### 传输、resume 和公开字段

v2 transfer result 按 `direction`（`put`/`get`）和 `kind`（`file`/`directory`）分支。普通文件只报告实际提供的 `atomic`、`integrity`、`resume` 和 byte 字段；目录传输明确报告 `atomic:false`、`integrity:not_available`、`resume:unsupported`，目录 get 不虚构 `bytes_received`。只有明确使用 `--resume=v1` 才启用普通文件续传，续传状态和完整性校验失败时不会替换目标文件。目录上传遇到远端 tar 失败（权限、磁盘满、目标不是目录）会直接返回远端错误 `stage:remote_extract`，目标目录可能已部分写入，不会再逐文件重试；只有本机没有可执行的 `tar` 时才使用逐文件 fallback。目录下载在任一端失败时立即关闭另一端并有界退出。request v1 的 `op:put` 增加 `dir_mode`，`op:get` 增加 `sha256`/`timeout`（均为加性字段）。

strict 模式下，`status` 的在线刷新失败会返回 `error:sync_pull_failed` 与 `stage:sync_pull`，只有显式 `--offline` 才读取缓存；local_first（默认）下 `status` 与读命令不因同步失败而失败。存在但格式错误的 `cloud.json` 在两种模式下都会返回 `error:sync_config_error`。非 capture 的 human run 默认流式输出：stdout 逐字节透传（包括远端回显的值，与成功输出契约一致），stderr 中的显式 `--secret` 值替换为 `***`，并按行脱敏凭据形态的内容；没有大小上限，也不写临时文件，适合 `tar -czf - dir | tar -xzf -` 这类字节管道和长时间运行的命令。收到 SIGINT/SIGTERM/SIGHUP 时，sshctl 把信号转发给远端命令，输出 flush 后以 `error:interrupted` 和 128+信号编号退出。`--json` 会把完整 stdout/stderr 缓存在内存里再输出一个 JSON 值，失败结果整体脱敏；大输出请用 human 模式或 `get`。设置 `SSM_RUN_OUTPUT=buffered` 可恢复 v2.0.2 的回放模式：结果确定后再输出、失败时整体脱敏、每个流 8 MiB 上限，超限返回 `error:internal`。流式模式不再按行屏蔽 `-s`/`-f` 脚本正文（否则 `set -x` 轨迹会被抹掉），也不再事后脱敏失败时的 stdout，凭据请用 `--secret` 传入；启动时已被忽略的信号（如 `nohup`）保持忽略；`--json` 运行不转发信号。buffered 模式和目录/文件传输的诊断缓冲仍以 0600 私有临时文件保存原始字节，回放后删除，进程被杀留下的文件会在 24 小时后由下一次运行清理。

同步失败的具体原因保留在错误链中：`sync_pull_failed`（以及推送、host 的同步失败）的 `--json` 结果新增顶层 `cause` 字段（仅出现在同步失败上，加性），`message` 带上已脱敏的底层错误，human 输出在 `ssm: error=... stage=...` 行末追加 `cause=<值>`。`cause` 是稳定枚举：`dns`（域名无法解析）、`connect_refused`（连接被拒）、`timeout`（超时）、`tls`（证书校验失败）、`auth`（HTTP 401/403，token 被拒）、`http_5xx`（服务端 5xx）、`missing_token`（配置缺 token）、`network`（其他传输层错误）、`unknown`（其余，包括其他 HTTP 状态）。`hint` 随 `cause` 变化：`auth` 与 `missing_token` 要求重新 `ssm login` 后重试，不建议 `--offline`；`tls` 需要人工排查证书，不要绕过校验；`dns`、`connect_refused`、`timeout`、`http_5xx`、`network` 可稍后重试，或在明确接受 stale inventory 时显式 `--offline`。

### 精确发布范围与空 ledger

`push --only <transaction-id>` 发布一个 reviewed transaction，`push --all` 只固定并发布调用开始时的 pending ID 集合。空集合不会覆盖整个本地 blob：一致时是 `action:"noop"`，缺少或不一致的身份则是 `error:"sync_conflict"`；按[空 ledger 恢复说明](skills/agent-ssm/references/import-json.md)执行受保护的 pull、reviewed `--merge` 和新的 `push --only <transaction-id>`。

### 同步模式：local-first（默认）与 strict

中心服务器只负责同步，不会挡在每条命令前，离线也能用。默认的 `sync_mode: local_first` 下，读命令（`run`、`map`、`get`、`put`、`check`、`doctor`、`list`、`host list|show`、`host-key`、`keys`、`status`）只读本地 vault，前台不发任何同步请求。自动同步到期时，命令在 `sync-state.json` 里原子占位，派生一个分离的后台进程 `sshctl sync --background`（隐藏选项）：它先做短超时的“有变化才拉取”检查，只在远端变化时拉取，绝不自动 push，也不覆盖有分叉的本地 vault；只在短暂的 vault 写锁下替换 vault（本地修改共用同一把锁），不会覆盖本地修改。成功后至少间隔 `sync_interval`（默认 `10m`）才再检查；失败按 30 秒起、每次翻倍、封顶 1 小时的指数退避记录，退避期内的命令不再尝试。同步失败绝不会让读命令失败。

可见而非阻断：`status` 在 local_first 下永不因同步失败而失败，并报告 `remote_state`（`checked`、`unreachable`、`not_checked`、`not_configured`、`auto_sync_disabled`）、`last_successful_sync`、`last_sync_error`（`cause`、脱敏的 `message`、`at`；分叉时 `cause` 为 `conflict`）、`next_sync_attempt`、`cache_age_seconds` `inventory_stale` 和 `inventory_unsynced`（已配置同步但从未确认过清单时为 true，human 读命令也会在 stderr 提示一次；这些字段都是加性的）。缓存年龄超过 `stale_after`（默认 `7d`，从最近一次确认的 pull、push 或成功的后台检查算起）时，`run` 的 JSON 结果带 `inventory_stale:true`，human 读命令在 stderr 打一行警告，stdout 不受影响。

`settings.json` 配置项：`sync_mode`（`local_first` 或 `strict`）、`sync_interval`、`stale_after`（Go 时长，或整数加 `d` 表示天）；环境变量 `SSM_SYNC_MODE` 可对单个进程覆盖 `sync_mode`。`auto_sync:false` 在两种模式下都关闭自动同步。`--offline` 与 `SSM_OFFLINE=1` 等价：不解析同步配置、不联网，也不派生后台同步。

显式 `sync`、`pull`、`push` 在两种模式下都保持严格语义（出错即失败），并把结果写入 `sync-state.json`。写操作与发布不变：修改先记为 pending，由 `push --only <transaction-id>` 或 `push --all` 发布，分叉检测仍然 fail-closed。`run --stream --refresh` 在 local_first 下到期时会在 vault 已被后台更新时重新加载快照，同步失败不会中止流。`login` 成功后会立即通过与显式 `sshctl sync` 相同的路径（strict 语义、vault 写锁、分叉时保留冲突证据）拉取清单；只有这次初始拉取失败（stderr 会给出 `cause` 并提示运行 `sshctl sync`，`login` 本身仍然成功）时才需要手动运行 `sshctl sync`。

`--offline` 对读命令已弃用：仅为兼容而接受；读默认就是本地的，它现在只用来抑制后台同步（`strict` 模式下仍跳过在线刷新）。`run` 的 JSON 结果还会在“已配置同步但从未确认过清单”时带 `inventory_unsynced:true`，在最近一次同步尝试失败时带 `inventory_sync_error:"<cause>"`（`cause` 取值同上，例如 `http_5xx`；加性字段，human 模式不为此打警告，离线使用保持安静）。在 `strict` 模式以及显式 `sync`/`pull` 下，若另一个 ssm 进程正持有短暂的 vault 写锁（例如并发的本地修改），命令会以 “vault is busy” 失败，重试即可；`pull --adopt-remote <sha256> --yes` 只在冲突证据记录之后本地 vault 没有再变化时才会执行，否则被拒绝并保留本地修改，请重新检查冲突。

需要 v2.0.2 的行为（每次读之前在线刷新、刷新失败即命令失败）时，在 `settings.json` 设置 `"sync_mode": "strict"`，或对单个进程设置 `SSM_SYNC_MODE=strict`。相对 v2.0.2，默认行为的变化是：读命令不再因同步端点不可达而失败，也不再为每条命令多花一次 `HEAD` 请求。

### 可选同步服务器

你可以自建同步端点；它只保存加密 vault blob：

```bash
ssm register --server <sync-server-url> --email <email> --password-file <sync-password-file>
ssm login --server <sync-server-url> --email <email> --password-file <sync-password-file>
sshctl sync
```

中心服务器示例：

```bash
ssm server --listen 127.0.0.1:18787 --data-dir /srv/ssm-sync
```

不要把同步服务器当成 SSH 跳板；SSH 仍然从当前机器连接目标主机。

### 给另一个 Agent 的最小提示词

```text
从 Cd1s/ssm 安装 SSM：
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
先运行 sshctl --json --version，再运行 sshctl --json status 和 sshctl --json host list。
只使用精确 alias；固定简单命令用 sshctl --json run <alias> --argv ...。
密码和私钥只引用受限文件路径；新增/修改主机先 verify，成功后只发布返回的 transaction_id。
```
