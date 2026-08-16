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

应看到版本字段为 `2.0.2`。如果 `sshctl` 不存在，重新打开终端或检查 `/usr/local/bin` 是否在 `PATH` 中。

### 3. 查看状态

```bash
sshctl --json status
```

它会告诉你同步是否已配置、状态是否 fresh，以及有没有待发布的本地变更。没有配置同步时，结果会明确说明 unconfigured，不会偷偷改用旧缓存。

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

如果这是第一次使用，还没有主机，可以先看下面“添加或修改主机”；如果出现 `host_key_unknown` 或 `host_key_mismatch`，先按“检查连接”中的 host key 流程核验指纹。

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

遇到新 host key 或 key mismatch 时，先观察并核对完整指纹：

```bash
sshctl host-key inspect my-server --json
sshctl host-key accept my-server --fingerprint SHA256:REPLACE_WITH_VERIFIED_FINGERPRINT --yes --json
```

第二条命令中的指纹只能替换成你通过可信渠道核验过的 `observed_fingerprint`；不要用自动 `ssh-keygen -R` 加 `ssh-keyscan` 代替核验。

### 运行命令

当你要在一台已选定的主机上执行一个固定、简单的命令时：

```bash
sshctl --json run my-server --argv hostname
sshctl --json run my-server --argv uname -sr
```

需要连续执行多条简单命令时，可以复用同一进程和连接；每行输入一个 JSON argv 数组：

```bash
sshctl run my-server --stream
["hostname"]
["uname","-sr"]
```

在线 stream 的 `--refresh` 必须为正数；`--refresh=0` 只有在显式全局 `--offline` 时才允许。复杂 shell 语法、动态参数或 secret 使用 request 文件；不要把生成的脚本塞进 `bash -c`。

### 上传或下载文件

当你要传普通文件或目录树时：

```bash
sshctl put my-server ./notes.txt /tmp/notes.txt --sha256 --json
sshctl get my-server /tmp/notes.txt ./notes.txt
```

`--sha256` 只适用于需要完整性核验的普通文件上传；目录传输的保证与普通文件不同，详见[进阶契约](#进阶--给-agent-与自动化)。

### 添加或修改主机

当你要新增一台主机，或只改现有 alias 的某个字段时。先用 `--verify` 检查候选配置，验证成功后才保存：

```bash
sshctl host upsert my-server \
  --host 203.0.113.10 --port 22 --user demo \
  --key-file /secure/my-server.key --verify --json

sshctl host update my-server --port 2222 --verify --json
```

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
- 在线同步失败时不会静默切到旧缓存；只有明确接受 stale inventory 才能使用 `--offline`。
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

## 进阶 / 给 Agent 与自动化

先读[官方 Agent Skill](skills/agent-ssm/SKILL.md)和[版本兼容矩阵](skills/agent-ssm/references/version-compatibility.md)。它们定义了 v1.4.3/v1.4.4 兼容分支，以及受支持的 v2.0.0 与当前 v2.0.2 共用的 v2 兼容分支各自可以使用的 schema 和字段。

### 结构化输出与 request

普通 `--json` 调用输出一个 JSON 值；显式 `run --stream` 输出逐行 NDJSON。Agent 应按 `ok`、`error`、`stage`、`exit` 和 `hint` 分类；远端程序本身也可能退出 255，不能只看退出码判断 SSH 是否失败。

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

v2 transfer result 按 `direction`（`put`/`get`）和 `kind`（`file`/`directory`）分支。普通文件只报告实际提供的 `atomic`、`integrity`、`resume` 和 byte 字段；目录传输明确报告 `atomic:false`、`integrity:not_available`、`resume:unsupported`，目录 get 不虚构 `bytes_received`。只有明确使用 `--resume=v1` 才启用普通文件续传，续传状态和完整性校验失败时不会替换目标文件。

`status` 的在线刷新失败会返回 `error:sync_pull_failed` 与 `stage:sync_pull`；存在但格式错误的 `cloud.json` 会返回 `error:sync_config_error`。只有显式 `--offline` 才读取缓存。非 capture 的 human run 使用 outcome-buffer，失败时先脱敏再回放，并受 8 MiB 上限约束。

### 精确发布范围与空 ledger

`push --only <transaction-id>` 发布一个 reviewed transaction，`push --all` 只固定并发布调用开始时的 pending ID 集合。空集合不会覆盖整个本地 blob：一致时是 `action:"noop"`，缺少或不一致的身份则是 `error:"sync_conflict"`；按[空 ledger 恢复说明](skills/agent-ssm/references/import-json.md)执行受保护的 pull、reviewed `--merge` 和新的 `push --only <transaction-id>`。

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
