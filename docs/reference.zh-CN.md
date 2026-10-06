# ssm 参考手册

`ssm` 与 `sshctl` v2.1.0 的完整参考：所有命令和选项、配置文件、环境变量、错误码和退出状态。简短介绍和快速开始见 [README](../README.zh-CN.md)。

标注 **未发布** 的内容已合入 `main`，但还不在最新发布版里。

## 目录

- [基本概念](#基本概念)
  - [词汇表](#词汇表)
- [安装细节](#安装细节)
  - [安装脚本变量](#安装脚本变量)
  - [Windows](#windows)
  - [从源码构建](#从源码构建)
- [主机与主机密钥](#主机与主机密钥)
  - [查看或搜索主机](#查看或搜索主机)
  - [添加或修改主机](#添加或修改主机)
  - [经跳板主机连接（ProxyJump）](#经跳板主机连接proxyjump)
  - [检查连接](#检查连接)
- [命令执行](#命令执行)
  - [运行命令](#运行命令)
  - [等待主机就绪（`wait`）与拨号重试（`--retry-dial`）](#等待主机就绪wait与拨号重试--retry-dial)
  - [超时与 keepalive](#超时与-keepalive)
  - [选项速查](#选项速查)
- [文件传输](#文件传输)
  - [上传或下载文件](#上传或下载文件)
  - [传输、resume 和公开字段](#传输resume-和公开字段)
- [同步与发布](#同步与发布)
  - [同步模式：local-first（默认）与 strict](#同步模式local-first默认与-strict)
  - [可选同步服务器](#可选同步服务器)
  - [发布已审查的变更](#发布已审查的变更)
  - [精确发布范围与空 ledger](#精确发布范围与空-ledger)
- [自动化与 AI Agent](#自动化与-ai-agent)
  - [结构化输出与 request](#结构化输出与-request)
  - [退出码与传输错误](#退出码与传输错误)
  - [输出处理、信号与同步失败原因](#输出处理信号与同步失败原因)
  - [给另一个 Agent 的最小提示词](#给另一个-agent-的最小提示词)
- [配置](#配置)
  - [配置目录](#配置目录)
  - [settings.json](#settingsjson)
  - [环境变量](#环境变量)
- [安全边界](#安全边界)
- [更新与回滚](#更新与回滚)
- [故障排查](#故障排查)
- [开发与验证](#开发与验证)

## 基本概念

`ssm` 是给 Agent、脚本和自动化使用的非交互 SSH 管理工具：它帮你保存主机信息、检查连接、运行命令和传文件，但不会打开 TUI，也不会等你在远端输入命令。适合希望把 SSH 操作安全、可重复地交给脚本或 Agent 的人。

`ssm` 和 `sshctl` 是同一个二进制，只是命令名不同。安装后通常会同时得到 `/usr/local/bin/ssm` 和指向它的 `/usr/local/bin/sshctl`；下面用更适合 Agent 的 `sshctl` 举例。

密码和私钥不会写进命令输出。主密码默认从本机 `~/.config/ssm/master.pass` 读取；主机密码、私钥和主机信息保存在本机加密 vault 中。需要新增或修改主机时，只给 `--password-file`、`--key-file` 等受限文件路径，不把 secret 内容写进命令、JSON、日志或提交。

如果启用了同步服务器，它看到的只是加密后的 vault blob，不会看到解密后的主机清单、SSH 密码或私钥；真正的 SSH 连接始终从当前这台机器发起。

### 词汇表

| 词 | 小白解释 |
| --- | --- |
| **vault** | 本机加密保险箱，保存主机资料以及密码/私钥的安全引用；同步时只传加密数据。 |
| **alias** | 你给一台主机起的精确名字。搜索结果只是候选，连接前必须选定完整 alias。 |
| **sync** | 在本机和同步服务器之间拉取或推送加密 vault 状态；它不是 SSH 连接。 |
| **push** | 把已经审查过的本地变更发布到同步服务器；必须指定 transaction ID 或经审查的全部 pending 范围。 |
| **request** | 一个版本为 1 的 JSON 请求文件，给动态参数、脚本、secret 文件路径、传输或主机变更使用。 |
| **host key** | SSH 用来确认“这还是同一台主机”的指纹。首次出现或发生变化时，先 inspect、通过可信渠道核验，再显式 accept。 |

## 安装细节

`install.sh` 需要 `sh`、`curl`、`jq`、`head`、`wc`、`sha256sum` 或 `shasum`，以及带 `gh attestation verify` 的 GitHub CLI（`gh`）。它会下载适合你平台的发布包，用 `checksums.txt` 校验 SHA-256，再按确切的发布 tag 验证 Sigstore 来源证明，全部通过后才安装。支持 `amd64` 和 `arm64` 上的 Linux 与 macOS。

它把 `ssm` 和指向它的 `sshctl` 符号链接装进前缀目录，以 `0700` 权限创建配置目录，写入 `update_repo`，并在缺少 `settings.json` 时创建它，最后运行 `ssm --version`。装好后 `sshctl --json --version` 应报告版本字段（当前发布版是 `2.1.0`）；找不到 `sshctl` 时，重新打开终端或把前缀目录加入 `PATH`。

### 安装脚本变量

| 变量 | 默认值 | 含义 |
| --- | --- | --- |
| `SSM_RELEASE_TAG` | 最新发布版 | 安装某一个确切的稳定 tag，例如 `v2.1.0`；其他写法会被拒绝。 |
| `SSM_PREFIX` | `/usr/local/bin` | 接收 `ssm` 和 `sshctl` 符号链接的目录。 |
| `SSM_CONFIG_DIR` | `~/.config/ssm` | 安装脚本准备的配置目录。 |
| `SSM_REPO` | `Cd1s/ssm` | 安装脚本下载发布包的 GitHub 仓库。来源证明仍然验证 `Cd1s/ssm` 的发布工作流身份。 |

### Windows

从[最新发布页](https://github.com/Cd1s/ssm/releases/latest)下载 `ssm-windows-amd64.exe`（或 `ssm-windows-arm64.exe`）、对应的 `.sigstore.json` 证明包和 `checksums.txt`。把可执行文件的 SHA-256 与 `checksums.txt` 里的记录比对，再用 `gh attestation verify` 验证来源证明，参数是可执行文件、它的 `.sigstore.json` 证明包和 `Cd1s/ssm` 仓库。准确的验证规则（包括固定的发布工作流身份）见[更新来源证明运行手册](update-provenance-runbook.zh-CN.md)。

### 从源码构建

```bash
go build ./cmd/ssm
```

使用 Go 1.26.8。源码构建用于开发；发布的二进制由发布工作流构建并附带来源证明。

## 主机与主机密钥

### 查看或搜索主机

当你只想知道 vault 里有哪些连接，或想从多个候选中找出目标时：

```bash
sshctl --json host list
sshctl host search my --json
sshctl host show my-server --json
```

`search` 不会自动挑选候选；最终连接、检查或运行命令都使用精确 alias。

### 添加或修改主机

当你要新增一台主机，或只改现有 alias 的某个字段时。先用 `--verify` 检查候选配置，验证成功后才保存：

```bash
sshctl host upsert my-server \
  --host 203.0.113.10 --port 22 --user demo \
  --key-file /secure/my-server.key --verify --json

sshctl host update my-server --port 2222 --verify --json
```

`--transfer auto|shell|sftp`（request v1 的 `host.transfer`）设置该主机 `put`/`get` 使用的协议，默认 `auto`（不写入 vault）；见[上传或下载文件](#上传或下载文件)。

`--proxy-jump <别名>`（request v1 的 `host.proxy_jump`，空值清除）设置该主机经哪个别名跳转；见[经跳板主机连接](#经跳板主机连接proxyjump)。

私钥和密码只能通过 `--key-file`、`--password-file` 或已保存的 `--key` 名称引用，不能作为 inline 值。变更默认只保存在本机 pending ledger；成功结果会返回一个待审查的 `transaction_id`。幂等 no-op 会返回 `changed:false`、`action:"unchanged"` 并省略 ID；do not publish 这个 no-op。

### 经跳板主机连接（ProxyJump）

把一台主机设为“经另一个别名跳转”：

```bash
sshctl host update inner --proxy-jump bastion --offline --json     # 值是另一个别名；链式可多级
sshctl host update inner --proxy-jump "" --offline --json          # 空值清除
sshctl run inner --argv hostname                                   # run/map/put/get/check/doctor/cp/host-key 都可用
```

- 逐跳建连：第一跳走普通拨号（host key 校验、认证、握手期限、keepalive）；之后每一跳通过上一跳的 `direct-tcpip` 通道做 SSH 握手，**每一跳都用本机 `known_hosts` 校验自己的 host key，并用自己的凭据认证**。任何凭据都不会发给跳板机，也不启用 agent forwarding；不放宽任何一跳的 host key 校验。
- 解析时校验：链上不许有环，最多 5 个跳板机，被引用的别名必须存在（redirect 在解析时生效）；否则返回 `error:proxy_jump_invalid`（`stage:validate`，exit 2），不会发起任何连接。
- 失败结果新增可选字段 `via`：出错的那一跳的别名（跳板机或目标本身），分类沿用现有的 `dial_*`、`handshake_failed`、`auth_failed`、`host_key_*`，`stage` 不变；host key 的 `hint` 指向该跳的别名。某一跳的 host key 未受信时，链在该跳终止，后面的主机不会被联系、也不会收到任何认证尝试。
- `host-key inspect|accept <目标别名>` 检查并记录的是**目标**的 host key；跳板机必须已经单独受信（先对跳板别名 `host-key inspect`/`accept`），否则失败并在 `via` 里指明跳板别名。
- **兼容性**：v2.0.2 及更早的客户端不认识 `proxy_jump`，重新保存同步下来的 vault 时会丢掉它，该主机就变成直连（host key 校验会让它失败关闭，但设置已丢失）。使用 `proxy_jump` 前请先升级所有客户端。
- 每个位于跳板机后面的目标各自打开一条自己的跳板连接（不共享）。
- 连接池按整条链缓存；目标连接关闭或被淘汰时，它拥有的跳板机连接一并关闭。request v1 用 `host.proxy_jump`（空字符串清除）。

Vault 加密格式 v2 增加了经过认证的单调代数。上线前请先升级所有客户端；旧客户端无法读取 v2 vault。

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

## 命令执行

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

要限制命令的运行时间，用 `--exec-timeout 2m`（到期先发 SIGTERM，再返回 `exec_timeout`、退出码 124 和已收到的输出）；`--connect-timeout` 及其别名 `--timeout` 只管建连。详见[超时与 keepalive](#超时与-keepalive)。

在线 stream 的 `--refresh` 必须为正数；`--refresh=0` 只有在显式全局 `--offline` 时才允许。复杂 shell 语法、动态参数或 secret 使用 request 文件；不要把生成的脚本塞进 `bash -c`。

#### 运行脚本（shell 或 Python）

`-f`/`-s` 通过 SSH stdin 发送脚本正文，不会在远端写临时文件。不带 `--interpreter` 时按脚本 shebang 选 shell（`#!/bin/bash`、`#!/usr/bin/env bash` 用 bash）；没有 shebang 则用 `sh`。shebang 指向 python3 等非 shell 程序时会返回 `invalid_arguments` 并提示加 `--interpreter`。

```bash
sshctl --json run my-server -f report.py --interpreter python3 -- a b   # sys.argv[1:] == ['a', 'b']
sshctl run my-server -f deploy.sh --shell bash
```

显式 `--interpreter` 视为用户已确认，不受 shell 白名单限制。取值只能是一个程序名、一个绝对路径，或 `env <name>`（例如 `--interpreter "env python3"`）；带参数或含 shell 元字符的值会被拒绝。非 shell 解释器以 `<解释器> - <参数...>` 启动，要求它在收到 `-` 时从 stdin 读脚本（python3、perl、ruby 支持）。远端缺少解释器时返回 `interpreter_not_found`（退出码 127）。`--preflight` 只做 shell 语法检查，与非 shell 解释器同时使用会被拒绝。`--shell` 仍是仅限 shell 的选项；`--interpreter bash` 继续可用，等同 `--shell bash`。request 文件在 `script_file` 旁用 `"interpreter"` 字段表达同样语义。

### 等待主机就绪（`wait`）与拨号重试（`--retry-dial`）

主机重启或路由短暂中断时，用 `wait` 代替外部 `sleep` 循环：

```bash
sshctl --json wait my-server --timeout 5m --interval 5s
sshctl --json wait my-server --until tcp
sshctl --json run my-server --retry-dial 3:500ms --argv hostname
```

- `wait` 只在「传输层还没就绪」时继续等待：拨号被拒、超时、无路由，以及服务器 host key 到达之前的握手失败（EOF、reset、超时）。此后（可能正在认证时）的断开或超时只报告、不重试。默认 `--until ssh` 每次尝试只用一条真实的 SSH 连接（不做单独的 banner 探测，那会在 sshd 日志里留下 pre-auth 失败记录，可能被 fail2ban 计数）。
- **`wait` 和 `--retry-dial` 永远不会重试认证失败或 host key 失败。** `auth_failed`、`host_key_unknown`/`host_key_mismatch`/`host_key_type_changed`、缺少凭据、alias 或配置错误都会立即以真实的错误码退出，因为对运行 fail2ban 的主机反复登录会很快被封。
- `--interval` 不得小于 `1s`；间隔按指数退避加抖动增长，上限 30 秒；每次尝试都有时间上限，总耗时不会明显超过 `--timeout`。超时返回 `error:wait_timeout`（`stage:wait`，退出码 1），`message` 中带最后一次观察到的原因。`--until tcp` 只检查 TCP，不认证。成功时 JSON 为 `{"ok":true,"alias":…,"attempts":N,"elapsed_ms":…}`。
- `--retry-dial N[:backoff]`（N 最大 10，`backoff` 默认 250ms，指数退避加抖动）只重试命令发出之前的传输失败（`dial_*`，以及服务器 host key 到达之前的握手失败）；`auth_failed`、`host_key_*`、`connection_lost` 以及会话打开之后的任何失败都不会重试。只有给了 `--retry-dial` 或实际重试过时，JSON 才带 `dial_attempts`。
- 经 `proxy_jump` 别名时规则按跳逐一适用：某一跳在**它自己的** host key 到达之前的传输失败（例如跳板后面的目标还没起来、端口被拒）会继续等待/重试，每次只是重新成功登录前面的跳板；任何一跳认证失败，或任何一跳在其 host key 到达之后失败，都不会重试。`wait --until tcp` 不支持 `proxy_jump` 别名（目标只能经跳板到达）。
- 提案中的 `--until cmd:<…>` 尚未实现（已推迟）。

### 超时与 keepalive

每个超时管的是不同的阶段，不要混用：

| 选项 | 管什么 | 默认 |
|---|---|---|
| `--connect-timeout <时长>` | TCP 建连 **加上** SSH 握手（含认证）的总时限。到期报 `handshake_failed`（`stage:handshake`，命令没有发出，可以安全重试，提示可调大 `--connect-timeout`）；TCP 都没连上仍报 `dial_timeout`。 | 15s |
| `--timeout <时长>`（`run`/`exec`/`plan`/`map`，已弃用） | `--connect-timeout` 的兼容别名。它是连接超时，**不是执行超时**。两者写进同一个值，命令行上后出现的生效，并且都优先于继承来的 `SSM_CONNECT_TIMEOUT`/`SSM_TIMEOUT`。 | 15s |
| `--exec-timeout <时长>` | 远端命令最长运行多久（`run`/`exec`/`plan`、`map`、`run --stream` 的每一行；request 用 `exec_timeout`）。到期先发 `SIGTERM`，5 秒宽限期后关闭 session，返回 `exec_timeout`（只要 SIGTERM 已经发出，即使命令捕获 TERM 并在宽限期内以 0 退出，也报 `exec_timeout`；命令在信号发出之前就已结束时才返回它的真实结果），退出码 124，JSON 带 `timed_out:true` 与已收到的 `stdout`/`stderr`；human 模式已流式输出的内容保留，最后打印分类行。 | 不限制 |
| `put`/`get` 的 `--timeout` | 文件传输超时（`transfer_timeout`）。语义不变。 | 不限制 |

环境变量 `SSM_CONNECT_TIMEOUT` 等价于 `--connect-timeout`（`SSM_TIMEOUT` 是旧别名）。没有任何选项时握手期限也生效，取默认 15s。

**契约变化。** `--timeout` 过去只限制 TCP 建连，握手阶段可以无限期挂住；现在它覆盖 TCP 建连加握手。这是对挂死行为的收紧：能正常握手的连接不受影响；握手卡住的连接会在期限内以 `handshake_failed` 失败，而不再无限等待。超时的握手（TCP 已连上）归为 `handshake_failed` 而不是 `dial_timeout`，因为命令没有发出、可以安全重试，且卡住的原因是 sshd（限流、OOM、半开）而不是网络不可达。

**Keepalive。** 默认开启：每 15 秒对每条 SSH 连接发一次 `keepalive@openssh.com`（要求回复）；连续 3 次没有回复就关闭连接，此时正在运行的命令报 `connection_lost`（`outcome:"unknown"`）。连接池里复用的连接同样受益。`SSM_KEEPALIVE=0` 关闭；无法解析的值会回退到默认的 15 秒；`SSM_KEEPALIVE=<时长>`（如 `5s`）修改间隔。sshctl 因 `--exec-timeout` 自己关闭 session 后得到的 EOF 不会被报成 `connection_lost`。

### 选项速查

`run`/`exec`/`plan`/`map` 的选项写在别名（`map` 是目标列表）之后、远端命令边界之前：

| 选项 | 说明 |
|---|---|
| `--argv` | 之后的全部内容是远端 argv，逐词字面传递，不经本地 shell 拼接。 |
| `--raw` | 用单个空格连接各词且不加引号，由远端 shell 解析；仅为兼容，有引号和展开风险。不能与 `--argv` 或脚本选项合用。 |
| `--plan`、`--dry-run` | 只解析并显示 `remote_command` 与风险，不连接也不执行；`plan` 命令等同 `run --plan`。 |
| `-j`、`--jobs`、`--parallel <n>` | `map` 的并发 worker 数（默认 8）；单主机 `run` 不使用它。 |
| `--trace`、`-v` | 等同 `SSM_TRACE=1`，见上。 |
| `--no-reuse` | 本次调用不使用连接池，等同 `SSM_REUSE=0`。 |
| `-f`、`--file <路径>`（可重复）、`--scripts a.sh,b.sh`、`-s`、`--script` | 脚本来源：`-f`/`--scripts` 读本地文件，`-s`/`--script` 从本地 stdin 读脚本；脚本正文经 stdin 发给远端。`map` 的 `--scripts` 对每台主机并行运行每个脚本。 |
| `--shell <名称>`、`--interpreter <程序>` | 选择运行脚本的 shell 或非 shell 解释器，见“运行脚本”。 |
| `--preflight`、`--no-preflight` | 先做 shell 语法检查；`--no-preflight` 把它关掉，后出现的生效。 |
| `--secret`、`-e NAME=@文件` | 把 `NAME` 作为环境变量传给远端命令，值从文件读取（也接受 `NAME=值`，但值会出现在命令行里，不建议）；输出中会被脱敏。 |
| `--retry-dial N[:backoff]` | 拨号重试，规则见“等待主机就绪（`wait`）与拨号重试（`--retry-dial`）”。 |
| `--connect-timeout`、`--exec-timeout`、`--timeout` | 见“超时与 keepalive”。 |
| `--stdin`、`--no-stdin`、`--stdin-file` | 见“本地 stdin 的转发规则”。 |
| `--stream`、`--refresh <时长>` | `run <alias> --stream` 的常驻 argv 流及其在线刷新间隔。 |

其它命令的选项：

- 全局：`--json`、`--offline`（读命令已弃用，仅抑制后台同步）、`--master-pass-file <路径>`、`--version`。
- `host add|update|upsert`：`--host`、`--port`、`--user`、`--group`、`--transfer auto|shell|sftp`、`--proxy-jump <alias>`、三选一的认证 `--key <名称>` / `--key-file <路径>`（可加 `--key-name <名称>` 给新密钥起名）/ `--password-file <路径>`，以及 `--verify`（先连接验证再保存，验证失败不保存）、`--push`（需与 `--verify` 合用，保存后立即发布该事务）。`host search` 可写 `--filter <查询>` 代替位置参数；`host remove` 需要 `--yes`，`--prune-key` 同时删除不再被引用的已存密钥。
- `import-json <路径>`：`--merge` 或 `--replace --yes`；`--manifest <路径>` 为没有 alias 的条目提供 alias；`--expect-count <n>` 在条目数不是 n 时失败（0 表示不检查）。
- `wait <alias>`：`--timeout`、`--interval`、`--until ssh|tcp` 见“等待主机就绪（`wait`）与拨号重试（`--retry-dial`）”。
- `put`/`get`/`cp`：见“上传或下载文件”。`--dir-mode` 必须是不超过 `0777` 的八进制权限，并且保留属主的写和执行位（即包含 `0300`，如 `0700`、`0750`、`0755`）；`0500`、`0644` 这类会让嵌套目录无法创建的值会在连接之前被拒绝。
- 同步服务：`ssm login`/`register` 用 `--server`、`--email`、`--password-file`，`ssm server` 用 `--listen`、`--data-dir`。
- `ssm update [--major [--yes]]`：见“更新与回滚”。

## 文件传输

### 上传或下载文件

当你要传普通文件或目录树时：

```bash
sshctl put my-server ./notes.txt /tmp/notes.txt --sha256 --json
sshctl get my-server /tmp/notes.txt ./notes.txt --sha256 --timeout 30s --json
```

`--sha256` 只适用于需要完整性核验的普通文件；目录传输的保证与普通文件不同，详见[传输、resume 和公开字段](#传输resume-和公开字段)。远端依次探测 `sha256sum`、`shasum -a 256`、`openssl dgst -sha256`，三者都没有时返回 `error:integrity_tool_unavailable`（去掉 `--sha256` 即可）。`put` 自动创建的父目录默认权限为 `0755`，可用 `--dir-mode <八进制>`（如 `--dir-mode 0750`）覆盖，取值须不超过 `0777` 且保留属主写和执行位（包含 `0300`），否则连接前就会被拒绝；文件本身仍通过私有临时文件加 rename 写入，权限语义不变。`get` 与 `put` 接受同样位置无关的 `--json`、`--timeout`、`--sha256`（下载后在本地计算并与远端摘要比对，不一致则失败且不替换目标）；`get` 不支持 `--resume`。

#### 没有 POSIX shell 的目标（SFTP）

默认（主机 `transfer: auto`）通过远端 POSIX shell 传输。`get` 在路径探测无法解析（输出不是 `DIR`/`FILE`/`MISSING`）、shell 报错或整个 exec 被拒时返回 `error:remote_shell_unsupported`（`stage:discovery`），不再误报路径不存在；`put` 只在 exec 被拒时返回它。此时改用 SFTP 子系统（同一条 SSH 连接，不执行任何远端命令）：单次加 `--sftp`，或把主机设为 `sftp`：

```bash
sshctl put win-box ./notes.txt C:/temp/notes.txt --sftp --sha256 --json
sshctl host update win-box --transfer sftp --offline --json   # auto|shell|sftp，默认 auto
```

request v1 用 `host.transfer` 设置主机字段，`put`/`get` 请求可带顶层 `transfer`：`shell`/`sftp` 只对这一次操作覆盖主机设置；`auto` 或省略则沿用主机设置（因此 `auto` 不能覆盖已设为 `sftp` 的主机）。SFTP 目前只支持单个普通文件：目录和 `put --resume` 返回 `error:unsupported_transfer_option`；服务器没有 sftp 子系统返回 `error:sftp_unavailable`。SFTP 的保证与 shell 路径不同，结果里的字段如实反映：

- `get`：先 `Stat` 判断类型，流式写入本地 staging 再原子发布（`atomic:true`）。SFTP 没有远端摘要命令，`--sha256` 对收到的字节流计算摘要，并核对远端报告的大小和落盘文件，`remote_sha256` 即该流摘要；不加 `--sha256` 时 `integrity:not_checked`。
- `put`：写入同目录的私有临时文件后 rename。服务器支持 `posix-rename@openssh.com` 时原子替换（`atomic:true`）；不支持时先把旧目标移到一旁再 rename，失败会还原，但结果报 `atomic:false`。`--sha256` 通过 SFTP 读回临时文件在本地比对（`integrity:sha256_verified`），服务器不允许读回时返回 `integrity_tool_unavailable`（`stage:capability`，与 shell 路径一致，`integrity:not_available`）且不发布；不加时只核对大小（`size_verified`）。`--dir-mode` 对新建父目录同样生效。目标已是目录时报错且不动它。超时或连接中断的 SFTP `put` 可能遗留 `<目标>.ssm-upload.<hex>` 临时文件：会先尝试用新的 SFTP 会话清理，清理不了时失败信息会写出该临时文件的路径。

#### 主机间复制（`cp`）

`sshctl cp <别名A>:<路径> <别名B>:<路径>` 把 A 上的一个普通文件复制到 B，数据经本机流式中转，**不落本机磁盘**：

```bash
sshctl cp web1:/srv/app.tgz web2:/srv/app.tgz --timeout 5m --json
# A 直接推到 B（需要显式确认，见下面的 --direct）
sshctl cp web1:/srv/app.tgz web2:/srv/app.tgz --direct --yes
```

- 读取沿用 `get` 的读路径（`cat` over SSH），写入沿用 `put` 的“私有临时文件 + 校验 + rename”，所以 B 上不会出现半成品；失败或摘要不一致时 B 的旧目标保持原样。
- 本机对流过的字节计算 SHA-256，并与 A 端源文件摘要、B 端写后（rename 前）摘要三方比对，三者一致才成功。结果 JSON 含 `direction:"cp"`、`route:"local_relay"`、`source`/`destination`（`alias`、`path`）、`bytes`、`source_sha256`、`local_sha256`、`destination_sha256`、`atomic:true`、`integrity:"sha256_verified"`；失败结果带常规的 `error`/`stage`/`exit`/`hint`（摘要不一致为 `integrity_failed`，`integrity:"mismatch"`）。
- 两端都需要 POSIX shell 和 `sha256sum`/`shasum`/`openssl` 之一（否则 `integrity_tool_unavailable`）；只支持单个普通文件，目录返回 `unsupported_transfer_option`（先用 `get`/`put`，或在源端打包）；`transfer: sftp` 的主机不支持 `cp`。A 有 `stat` 时保留源文件权限位，否则用 `0600`。
- `--json` 输出机器结果；`--timeout <时长>` 限制建立连接之后的摘要探测和传输（建连本身由连接超时管），超时返回 `transfer_timeout`。源和目标解析到同一别名且同一路径时拒绝（`invalid_arguments`）。任一端都可以本身经 `proxy_jump` 连接。
- **`--direct --yes`（A 直接推到 B）。** *未发布：已合入 `main`，不在 v2.1.0 中。* `sshctl cp web1:/srv/app.tgz web2:/srv/app.tgz --direct --yes` 让文件沿 A 自己的网络路径直接传给 B，不再经本机中转。没有 `--yes` 时在建立任何连接之前返回 `confirmation_required`（exit 2，人类输出和 `--json` 都一样），因为它有实实在在的暴露面：
  - A 必须向 B 认证，所以 sshctl 在进程内启动一个只持有 **B 的 vault 私钥** 的 SSH agent，只为这一次会话转发给 A（`auth-agent@openssh.com`），复制结束即清空并关闭。本机的 `SSH_AUTH_SOCK`、其他密钥和 B 的密码都不会离开本机。**复制进行期间，A 以及能控制 A 的人可以用 B 的密钥去连 B（或任何接受该密钥的主机）；但拿不到私钥本身。**
  - A 执行 `ssh -F /dev/null -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<私有临时文件> -o GlobalKnownHostsFile=/dev/null ... <user>@<host>`，并运行 `put` 同款的“临时文件 + 摘要校验 + rename”脚本。**A 上的 `ssh_config`（用户级和系统级，含 `Include`、ProxyCommand/ProxyJump、LocalCommand、ControlMaster）和 A 自己的密钥（`~/.ssh/id_*`）都被忽略**：这条 ssh 只使用转发来的 agent（`IdentityFile=/dev/null`，ssh 通过 `SSH_AUTH_SOCK` 找到转发的 socket），并关闭密码、键盘交互、基于主机的认证和所有转发。临时文件（权限 0600，退出时删除）只含本机已信任的 B 的主机密钥，写成 A 实际连接的 `host[:port]`；A 自己的 known_hosts 不会被使用或修改。B 的密钥在本机尚未信任时，在接触 A 之前就返回 `host_key_unknown`。
  - 要求与拒绝。在接触 A 之前拒绝（`unsupported_transfer_option`、`stage:validate`、exit 1）：只有密码的 B，或不接受 vault 密钥的 B（由本机用纯密钥登录检查）；B 有 `proxy_jump`（A 本身仍可经跳板访问）；任一端是 `transfer: sftp`；vault 密钥不可用。B 的主机密钥未受信是 `host_key_unknown`（`stage:dial`、exit 255），同样发生在接触 A 之前。连上 A 之后才拒绝：源是目录（`unsupported_transfer_option`、`stage:validate`、exit 1，与普通 `cp` 一致）；A 没有 `ssh` 客户端（`remote_tool_unavailable`、`stage:capability`、exit 1）；A 的 sshd 没有提供转发的 agent（`unsupported_transfer_option`、`stage:capability`、exit 1，需要 `AllowAgentForwarding`）。A 的 ssh 使用 `BatchMode` 和 `ConnectTimeout`，不会等待输入。
  - 时间上界：传输受 `--timeout` 约束。设置后，A 上的 ssh 在 A 有 GNU 风格 `timeout` 时也在其下运行（用 `timeout --version` 检测，BusyBox 等不使用包装），到期报 `transfer_timeout`。到期时 sshctl 一定会清空 agent 并关闭到 A 的、承载 agent 通道的连接，所以 B 的密钥不能再通过 agent 使用。但没有 `timeout` 包装时，A 上已经认证完成的 ssh 可能继续运行到自己结束或失败（没有 pty 时关闭会话不发 SIGHUP，`signal` 请求只有 OpenSSH 7.9+ 才处理，且只到达登录 shell 而不是 ssh）。**不带 `--timeout` 时没有上限**（与普通 `cp` 相同），使用 `--direct` 时请带上 `--timeout`。
  - 完整性：sshctl 先读 A 的源文件摘要，B 在 rename 前用它校验临时文件，传完后 sshctl 再通过自己的连接读 B 的摘要，三者相等才算成功。结果 JSON 含 `route:"direct"`、`source_sha256`、`destination_sha256`、`bytes`、`integrity:"sha256_verified"`，没有 `local_sha256`（本机不经手数据）。request v1 暂无 `direct` 字段。

### 传输、resume 和公开字段

v2 transfer result 按 `direction`（`put`/`get`）和 `kind`（`file`/`directory`）分支。普通文件只报告实际提供的 `atomic`、`integrity`、`resume` 和 byte 字段；目录传输明确报告 `atomic:false`、`integrity:not_available`、`resume:unsupported`，目录 get 不虚构 `bytes_received`。只有明确使用 `--resume=v1` 才启用普通文件续传，续传状态和完整性校验失败时不会替换目标文件。目录上传遇到远端 tar 失败（权限、磁盘满、目标不是目录）会直接返回远端错误 `stage:remote_extract`，目标目录可能已部分写入，不会再逐文件重试；只有本机没有可执行的 `tar` 时才使用逐文件 fallback。目录下载在任一端失败时立即关闭另一端并有界退出。request v1 的 `op:put` 增加 `dir_mode`，`op:get` 增加 `sha256`/`timeout`（均为加性字段）。

## 同步与发布

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

### 发布已审查的变更

当你已经检查过变更内容，并确认要让同步服务器接收它时，只发布返回的那个 transaction：

```bash
sshctl --json push --only <transaction-id>
```

把 `<transaction-id>` 替换为刚才命令返回的精确 ID。不要使用裸 `push`；只有在审查了调用开始时的全部 pending 变更后，才使用 `sshctl --json push --all`。

### 精确发布范围与空 ledger

`push --only <transaction-id>` 发布一个 reviewed transaction，`push --all` 只固定并发布调用开始时的 pending ID 集合。空集合不会覆盖整个本地 blob：一致时是 `action:"noop"`，缺少或不一致的身份则是 `error:"sync_conflict"`；按[空 ledger 恢复说明](../skills/agent-ssm/references/import-json.md)执行受保护的 pull、reviewed `--merge` 和新的 `push --only <transaction-id>`。

## 自动化与 AI Agent

先读[官方 Agent Skill](../skills/agent-ssm/SKILL.md)和[版本兼容矩阵](../skills/agent-ssm/references/version-compatibility.md)。它们定义了 v1.4.3/v1.4.4 兼容分支，以及受支持的 v2.0.0 与当前 v2.1.0 共用的 v2 兼容分支各自可以使用的 schema 和字段。

### 结构化输出与 request

普通 `--json` 调用输出一个 JSON 值；显式 `run --stream` 输出逐行 NDJSON。Agent 应按 `ok`、`error`、`stage`、`exit` 和 `hint` 分类；远端程序本身也可能退出 255，不能只看退出码判断 SSH 是否失败。

写错命令时 sshctl 会给出提示而不是当作别名：第一个词不是已知子命令时仍按 `sshctl <alias> <command>` 简写处理，别名不存在才判断它是不是命令。`ssm` 独有的命令（如 `keys`、`login`）、与子命令只差一两个字符的拼写（如 `stauts`、`hostkey`）返回 `unknown_command`（退出码 2），`hint` 给出正确的入口或命令，相近的命令名放在 `candidates`；`ssm` 入口对 sshctl 独有命令和拼写错误同样提示（human 模式下有建议时返回 `unknown_command` 和退出码 2；没有建议时保持旧的 `Unknown command` 输出，退出码不变）。别名与命令同样接近（平局）或更近，包括 redirect 的旧名，则按别名处理，返回 `alias_not_found`。其余情况仍是 `alias_not_found`（退出码 255），`candidates` 是编辑距离最近的别名，只是候选，绝不会自动选择或执行。`run`/`exec`/`plan`/`map` 的未知选项返回 `invalid_arguments`（退出码 2），`hint` 会给出建议，例如 `--script-file` 提示 `-f`、`--fetch` 提示 `get`，其余按真实选项表的编辑距离匹配。

动态或不可信参数、脚本、secret 文件路径、传输和主机变更使用 schema version 1 的[request-v1 schema](../skills/agent-ssm/references/request-v1.schema.json)：

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

v2 的 request schema 支持 `op:get`；v1.4.3/v1.4.4 必须使用[兼容桥接 schema](../skills/agent-ssm/references/request-v1-bridge.schema.json)，不能假设 v2-only 字段。

### 退出码与传输错误

`--json` 模式下以 `error` 字段为准，不要看进程退出码：远端程序可以返回任意退出码（包括 1、2、255），而 `2>&1 | tail` 这类管道还会丢掉退出码。

| 退出码 | 含义 |
|---|---|
| 0 | 成功。 |
| 1 | sshctl 的非 SSH 传输层失败：`internal`、vault、同步与更新错误，所有 `host` 与 `host-key` 子命令失败（包括其中的 `alias_not_found`），`script_syntax_error`，以及 `put`/`get` 的传输错误（`remote_write_failed`、`transfer_timeout`、`integrity_failed`、`partial_state_*`、`local_read_failed`）；或远端命令返回 1。请读 `error`。 |
| 2 | 参数或 request 无效（`invalid_arguments`、`invalid_request`），或 `proxy_jump_invalid`（跳板链缺别名、有环或超过 5 级，未发起任何连接），或远端命令返回 2。 |
| 124 | `run`、`map` 的 `--exec-timeout` 到期（`exec_timeout`）：先向远端发 SIGTERM，宽限期后关闭 session。与 GNU `timeout` 的退出码一致；远端命令自己也可能返回 124，请读 `error`。 |
| 127 | 远端脚本解释器不存在（`interpreter_not_found`），或远端命令返回 127。 |
| 128 + 信号编号 | 本地 SIGINT/SIGTERM/SIGHUP 中断了 `run`（`interrupted`；130、143、129）。信号已转发，远端命令可能仍在运行。 |
| 255 | `run`、`map`、`check`、`doctor`、`put`、`get` 的 SSH 传输层失败：`dial_timeout`、`dial_refused`、`dial_network`、`handshake_failed`、`host_key_unknown`/`host_key_mismatch`/`host_key_type_changed`（连接被拒绝）、`auth_failed`、`no_auth_configured`、`session_failed`、`session_limit`、`connection_lost`；以及 `run`、`map`、`check`、`doctor` 的 `alias_not_found`。远端命令本身也可能返回 255。 |
| 其它值 | 远端命令自己的退出码，原样透传。 |

`map` 以第一个失败结果的退出码退出；数组里每个结果各自带 `error`。`put`/`get` 传输中途断开时与 `run` 一样返回 `connection_lost` 和 255，因为这是传输层失败，而不是传输专属错误。

**契约变化。** `put`/`get` 传输中途断开，原来报 `remote_write_failed`（下载为 `remote_read_failed`）和退出码 1，现在报 `connection_lost`，退出码 255，并带 `outcome:"unknown"`。sshctl 自己因 `--timeout` 中止文件或目录 `get`、文件 `put` 的行为不变：`transfer_timeout`、退出码 1、没有 `outcome`。`host` 子命令的 `alias_not_found` 在 JSON 中 `exit` 为 255，进程退出码为 1；请以 `error` 字段为准。

是否可以安全重试，取决于命令有没有发出：

- 可以重试：`dial_timeout`、`dial_refused`、`dial_network`；`handshake_failed`（`stage:handshake`，TCP 已连上但 SSH 握手失败，例如 EOF、connection reset 或协议错误，命令没有发出）；以及 `stage:session` 的 `session_failed` 和 `session_limit`（会话没能打开，命令没有发出）。`session_limit` 表示服务器每条连接的会话数上限（sshd `MaxSessions`）持续占满：sshctl 会在连接超时内退避等待空位，不会关闭共享连接，也不会打断已在运行的会话；仍等不到时才返回它，请降低 `-j` 或调高 sshd `MaxSessions`。`no common algorithm` 这类确定性的握手失败每次都会同样失败，重试没有意义，应修正算法或服务器配置。`auth_failed` 和 `host_key_*` 保持各自的错误码，需要修复而不是重试。
- 不可盲目重试：`exec_timeout`（`stage:remote_execution`，带 `timed_out:true`）。命令已经发出并跑到了 `--exec-timeout`；sshctl 发过 SIGTERM 并在宽限期后关闭了 session，但远端进程可能仍在运行。先在主机上确认，再决定是否加大 `--exec-timeout` 重跑。
- 不可安全重试：`connection_lost`（`stage:remote_execution`，并带 `outcome:"unknown"`）。命令发出后连接中断，例如主机重启或执行了 `sysupgrade`，远端命令可能仍在运行，也可能已经结束。先去主机上确认进程状态。

`outcome` 是加性字段，只出现在 `connection_lost` 上。

### 输出处理、信号与同步失败原因

strict 模式下，`status` 的在线刷新失败会返回 `error:sync_pull_failed` 与 `stage:sync_pull`，只有显式 `--offline` 才读取缓存；local_first（默认）下 `status` 与读命令不因同步失败而失败。存在但格式错误的 `cloud.json` 在两种模式下都会返回 `error:sync_config_error`。非 capture 的 human run 默认流式输出：stdout 逐字节透传（包括远端回显的值，与成功输出契约一致），stderr 中的显式 `--secret` 值替换为 `***`，并按行脱敏凭据形态的内容；没有大小上限，也不写临时文件，适合 `tar -czf - dir | tar -xzf -` 这类字节管道和长时间运行的命令。收到 SIGINT/SIGTERM/SIGHUP 时，sshctl 把信号转发给远端命令，输出 flush 后以 `error:interrupted` 和 128+信号编号退出。`--json` 会把完整 stdout/stderr 缓存在内存里再输出一个 JSON 值，失败结果整体脱敏；大输出请用 human 模式或 `get`。设置 `SSM_RUN_OUTPUT=buffered` 可恢复 v2.0.2 的回放模式：结果确定后再输出、失败时整体脱敏、每个流 8 MiB 上限，超限返回 `error:internal`。流式模式不再按行屏蔽 `-s`/`-f` 脚本正文（否则 `set -x` 轨迹会被抹掉），也不再事后脱敏失败时的 stdout，凭据请用 `--secret` 传入；启动时已被忽略的信号（如 `nohup`）保持忽略；`--json` 运行不转发信号。buffered 模式和目录/文件传输的诊断缓冲仍以 0600 私有临时文件保存原始字节，回放后删除，进程被杀留下的文件会在 24 小时后由下一次运行清理。

同步失败的具体原因保留在错误链中：`sync_pull_failed`（以及推送、host 的同步失败）的 `--json` 结果新增顶层 `cause` 字段（仅出现在同步失败上，加性），`message` 带上已脱敏的底层错误，human 输出在 `ssm: error=... stage=...` 行末追加 `cause=<值>`。`cause` 是稳定枚举：`dns`（域名无法解析）、`connect_refused`（连接被拒）、`timeout`（超时）、`tls`（证书校验失败）、`auth`（HTTP 401/403，token 被拒）、`http_5xx`（服务端 5xx）、`missing_token`（配置缺 token）、`network`（其他传输层错误）、`unknown`（其余，包括其他 HTTP 状态）。`hint` 随 `cause` 变化：`auth` 与 `missing_token` 要求重新 `ssm login` 后重试，不建议 `--offline`；`tls` 需要人工排查证书，不要绕过校验；`dns`、`connect_refused`、`timeout`、`http_5xx`、`network` 可稍后重试，或在明确接受 stale inventory 时显式 `--offline`。

### 给另一个 Agent 的最小提示词

```text
从 Cd1s/ssm 安装 SSM：
curl -fsSL https://github.com/Cd1s/ssm/releases/latest/download/install.sh | sh
先运行 sshctl --json --version，再运行 sshctl --json status 和 sshctl --json host list。
只使用精确 alias；固定简单命令用 sshctl --json run <alias> --argv ...。
密码和私钥只引用受限文件路径；新增/修改主机先 verify，成功后只发布返回的 transaction_id。
```

## 配置

### 配置目录

所有数据都在同一个目录：`~/.config/ssm`，或 `SSM_CONFIG_DIR` 指定的目录。

| 文件 | 用途 |
| --- | --- |
| `connections.enc` | 加密 vault：主机、保存的密钥和受保护的密码引用。 |
| `master.pass` | 可选的主密码文件。存在时自动使用，vault 不存在时也用它创建；`--master-pass-file` 和 `SSM_MASTER_PASS_FILE` 可以指定别的文件。请保持私有。 |
| `settings.json` | 设置，见下文。 |
| `cloud.json` | `ssm login` 写入的同步服务器与凭据。 |
| `sync-state.json` | 自动同步的结果与计划（见[同步模式](#同步模式local-first默认与-strict)）。 |
| `redirects.json` | 用 `sshctl redirect` 管理的别名重定向。 |
| `update_repo` | `ssm update` 读取发布的 GitHub 仓库；安装脚本写入 `Cd1s/ssm`。 |

主机密钥按标准 OpenSSH 的 `~/.ssh/known_hosts` 校验。

### settings.json

| 键 | 默认值 | 含义 |
| --- | --- | --- |
| `sync_mode` | `local_first` | `local_first` 或 `strict`；环境变量 `SSM_SYNC_MODE` 可对单个进程覆盖它。 |
| `sync_interval` | `10m` | 两次成功后台同步之间的最小间隔。 |
| `stale_after` | `7d` | 缓存超过这个年龄就报告库存已过期。Go duration，或整数加 `d`。 |
| `auto_sync` | `true` | `false` 在两种模式下都关闭自动同步。 |
| `auto_update` | `true` | 联网命令最多每 6 小时检查一次已安装主版本下是否有更新的稳定版，并在通过校验和与来源证明检查后安装。`--offline` 跳过检查；设为 `false` 关闭。 |
| `update_repo` | `Cd1s/ssm` | 发布仓库；优先级见下面的 `SSM_UPDATE_REPO`。 |
| `password_cache` | 忽略 | 旧设置会被忽略；不再提供会话密码缓存。 |
| `vim_keys` | 忽略 | 旧设置会被忽略；目前没有命令读取它。 |
| `last_push`、`last_pull` | 空 | 由 `ssm` 维护的时间戳，请勿手改。 |

`sync_interval` 或 `stale_after` 为空、无法解析或不是正数时回退到默认值；无法识别的 `sync_mode` 按 `local_first` 处理。

### 环境变量

| 变量 | 含义 |
| --- | --- |
| `SSM_CONFIG_DIR` | 配置目录（默认 `~/.config/ssm`）。 |
| `SSM_MASTER_PASS_FILE` | 受保护的主密码文件；等价于全局 `--master-pass-file <路径>`。 |
| `SSM_CONNECT_TIMEOUT` | 等价于 `--connect-timeout`：TCP 建连加 SSH 握手，不限制远端执行。 |
| `SSM_TIMEOUT` | `SSM_CONNECT_TIMEOUT` 的已弃用别名，优先级低于它。 |
| `SSM_DIAL_TIMEOUT` | 更早的名字，作用相同，最后读取。 |
| `SSM_KEEPALIVE` | `0` 关闭 keepalive；`5s` 之类的时长设置间隔；无效值回退到 15s。 |
| `SSM_REUSE` | `0`、`off`、`false`、`no` 关闭连接池。连接复用范围始终是单个进程（`status` 显示 `reuse_scope=process`）。 |
| `SSM_FORWARD_STDIN` | `1` 默认转发本地 stdin（包括 `--json`）；`0` 等同于 `--no-stdin`。 |
| `SSM_RUN_OUTPUT` | `buffered` 恢复 v2.0.2 的缓冲输出模式。 |
| `SSM_NO_PERMISSION_WARNING` | 设为 `1` 可关闭凭据文件被其他用户读取时的警告。 |
| `SSM_TRACE` | `1`（也接受 `true`、`yes`、`on`）等价于 `--trace`/`-v`。 |
| `SSM_OFFLINE` | `1` 等价于 `--offline`。 |
| `SSM_SYNC_MODE` | `strict` 或 `local_first`；对单个进程覆盖 `sync_mode`。 |
| `SSM_UPDATE_REPO` | `ssm update` 使用的发布仓库，或 `off`；见下文。 |
| `SSM_VERIFY_REQUIRE_PINNED` | 仅用于仓库工具链：设为 `1` 时，断言固定工具链的 `cmd/verify` 子测试会失败而不是跳过。 |

`SSM_UPDATE_REPO=<owner/repo>|off` 指定 `ssm update` 读取发布的 GitHub 仓库，默认 `Cd1s/ssm`；它用于测试和 fork 自己的发布流程。优先级高于配置目录里的 `update_repo` 文件和 `settings.json` 的 `update_repo`；`off`、`none`、`disabled` 关闭更新。它不会绕过 SHA-256 和 provenance 校验：provenance 始终固定验证 `Cd1s/ssm` 的发布工作流身份，所以另一个仓库的发布没有 `Cd1s/ssm` 签发的凭证就无法安装。但它决定去哪里查版本，所以只应在可信的环境里设置（被人改掉可以让更新检查失败或停在旧版本），不要把它当作安装第三方构建的入口。

## 安全边界

- 不把密码、私钥、master pass、token、`cloud.json` 或解密后的 vault 内容放进命令参数、JSON、日志、Issue、PR 或提交。
- 不自动选择 alias，不把候选名称当成精确目标。
- host key 首次出现或变化时必须先 inspect、带外核验完整 SHA-256 指纹，再显式 accept。
- 默认 local-first：读命令直接用本地清单，同步服务器不挡命令；使用本地清单不是静默的，`status` 报告 `remote_state`/`last_sync_error`/`cache_age_seconds`，清单过期时有 `inventory_stale` 和 stderr 警告。需要“刷新失败即失败”时设置 `sync_mode: strict`。
- 发布必须有明确 scope；`push --only <transaction-id>` 只发布一个 reviewed transaction，相关依赖未满足时也不会偷偷扩大范围。

## 更新与回滚

全新安装跟随 GitHub latest，目前是 v2.1.0。普通更新只在已安装的 major 内选择更高版本（已安装 major 内最高的 stable release，不看 GitHub latest 标记；v2.0.2 曾在 latest 标记移动之前就更新到了 v2.1.0）：

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

`--major --yes` 不会跳过 SHA-256、精确 tag、keyless provenance 或失败恢复检查；失败时保留旧可执行文件和恢复证据。详见[迁移指南](migration-v1-to-v2.zh-CN.md)与[来源凭证运行手册](update-provenance-runbook.zh-CN.md)。

## 故障排查

| 现象（`error`） | 含义 | 处理方法 |
| --- | --- | --- |
| `host_key_unknown` | `known_hosts` 里还没有这台主机的密钥。 | 运行 `sshctl host-key inspect <alias>`，通过可信渠道核对完整 SHA-256 指纹，再 `host-key accept <alias> --fingerprint ... --yes`。 |
| `host_key_mismatch` | 已记录类型的密钥变了。 | 视为可能被冒充或服务器重装。通过可信渠道核对新指纹后再接受；不要用 `ssh-keygen -R` 加 `ssh-keyscan` 自动替代这个流程。 |
| `host_key_type_changed` | 服务器不再提供任何已记录的密钥类型。 | 同上：检查、核对、接受。 |
| `auth_failed` | 服务器拒绝了凭据，不会重试。 | 用 `host update` 检查密钥或密码文件。不要循环重试：反复登录会被 fail2ban 封禁。 |
| `dial_refused`、`dial_timeout`、`dial_network` | 主机不可达。 | 可以安全重试：用 `sshctl wait <alias>` 或 `--retry-dial`；检查地址、端口和防火墙。 |
| `handshake_failed` | TCP 已连上，但 SSH 握手失败或 `--connect-timeout` 到期，没有发送命令。 | 可以安全重试；调大 `--connect-timeout`。`no common algorithm` 这类确定性失败需要修改服务器或算法配置。 |
| `connection_lost` | 命令发出之后连接断了（`outcome:"unknown"`）。 | 不能盲目重试：先在主机上检查进程状态。 |
| `session_limit` | 服务器的单连接会话上限（sshd `MaxSessions`）一直是满的。 | 调低 `-j`，或调大 `MaxSessions`。 |
| `exec_timeout` | `--exec-timeout` 到期（退出码 124）；远端进程可能仍在运行。 | 先检查主机，必要时用更大的 `--exec-timeout` 重跑。 |
| `remote_shell_unsupported` | 目标没有可用于 `put`/`get` 的 POSIX shell。 | 加 `--sftp`，或 `host update <alias> --transfer sftp`。 |
| `integrity_tool_unavailable` | 远端没有 `sha256sum`、`shasum` 或 `openssl`。 | 去掉 `--sha256` 重试。 |
| `sync_pull_failed` 和其他同步错误 | 看 `cause` 字段。 | `auth`、`missing_token`：运行 `ssm login`。`tls`：检查证书，不要绕过。其他：稍后重试，只有能接受过期库存时才用 `--offline`。 |
| `sync_conflict` | 本地和远端 vault 出现分歧，或远端回到本机已取代的版本（可能是回滚或备份恢复）。 | 按[空 ledger 恢复指引](../skills/agent-ssm/references/import-json.md)处理，或先审查冲突再使用 `pull --adopt-remote`。 |
| `vault is busy` | 另一个本地写入者持有短暂的 vault 写锁。 | 重试命令。 |
| `alias_not_found` | alias 不存在；`candidates` 只是建议。 | 使用 `sshctl host list` 里的精确 alias。 |
| `confirmation_required` | `cp --direct` 需要 `--yes`。 | 先阅读暴露风险说明，接受后才加 `--yes`。 |

### 从备份恢复同步服务端

管理员从备份恢复同步服务端后，曾采用并取代该旧版本的客户端会将其视为 `sync_conflict` 而拒绝安装，保留本地 vault。
审查冲突后，需要在每台受影响的机器上运行 `sshctl pull --adopt-remote <sha> --yes`，使用恢复后的远端身份确认采用。
也可以由一台机器采用恢复的版本后，重新发布一个新版本，供其他客户端拉取。

`sync-superseded.json` 是客户端本地内部账本，最多保留 64 个已取代身份，不上传，也不进入 vault。
它无法识别本机从未采用过或已淘汰的旧身份；账本缺失或不可读时也无法检测重放。登录、登出和注册会清空账本。

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
