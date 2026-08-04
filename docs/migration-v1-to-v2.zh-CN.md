# SSM v1 到 v2 的迁移契约

本指南是获授权稳定版 SSM v2.0.0 的运维者和机器消费者契约。exact-tag workflow
只能把它发布为 non-latest，v1.4.4 仍是 GitHub latest；v1 客户端只能通过经过审查的显式
major 迁移选择它。

[English](migration-v1-to-v2.md) | [来源证明运行手册](update-provenance-runbook.zh-CN.md)

<!-- ssm-v2-migration: guide-begin -->

<!-- ssm-v2-migration: section=prerequisites -->

## 前置条件和保留的基线

更改客户端之前，确定其当前可执行文件、配置目录、同步端点、操作系统、架构，以及所有
解析 SSM 输出的自动化程序。发布门禁要求 Go 1.25.12、`jq`、`bash`、官方 golangci-lint 2.11.4
二进制文件、`v1.2.0` lint 基线，以及 `go run ./cmd/verify list` 报告的其他工具。

[#2](https://github.com/Cd1s/ssm/issues/2) 至 [#11](https://github.com/Cd1s/ssm/issues/11)
是保留的 v1 基线，而不是新的 v2 工作：非交互操作、事务性/有范围的更改、可观测且可
恢复的传输、稳定的机器失败、明确的同步新鲜度/离线状态、精确别名选择、绑定指纹的
主机密钥接受、对 agent 安全的调用，以及解锁前的命令帮助都继续生效。请求 schema v1
仍然严格，并拒绝未知字段。

<!-- ssm-v2-migration: section=backup-recovery-metadata -->

## 备份加密状态和恢复元数据

停止可能修改同一配置目录的 SSM 进程。制作保留权限的私有备份，包括 encrypted vault
以及现有的 `remote.etag`、`publishing-intent.json`、`sync-conflict.json`，还有 Windows
`.old`/`.old.state` 可执行文件恢复记录。不要把解密后的 inventory 或 secret 内容复制到
工单、日志、命令或本清单中。

保留待处理事务 ID 及其顺序。未完成的 v2 发布意图必须由 v2 先协调，然后 v1 可执行文件
才能触碰同一状态。经过认证的 updater 恢复记录必须由 updater 恢复；不得手动删除或重命名。

<!-- ssm-v2-migration: section=automated-preflight -->

## 运行自动预检

从精确的干净候选 checkout 运行：

```bash
go run ./cmd/verify ci
go run ./cmd/verify release
```

要求 `preflight_passed`，而不是 `completed_with_unavailable`。major-update 审查还必须报告
名为 `cloud_configuration`、`pending_recovery`、`untracked_divergence`、`platform_asset`
和 `rollback_readiness` 的自动检查成功。本地预检无法发现未知的外部解析器、cron、部署包装器
或 agents。

<!-- ssm-v2-migration: section=manual-external-consumer-review -->

## 手动审查外部消费者

盘点每一个外部调用点。完成 `ssm --json update --major` 报告的三项手动检查：

- `legacy_bare_push_consumers`：用精确且经过审查的范围替换 bare push；
- `zero_refresh_online_streams`：选择严格 positive（positive）的在线刷新间隔；
- `directory_transfer_consumers`：使用 `direction` 和 `kind`，并遵守真实的保证值和省略项。

同时确认单值 JSON 与 NDJSON 解析、精确别名处理、主机密钥批准、request-v1 严格性、secret
文件引用和退出码处理。远程命令可以合法地以 255 退出；使用 `error` 和 `stage` 将其与传输
失败区分开。

<!-- ssm-v2-migration: section=staged-canary-rollout -->

## 分阶段进行 canary 发布

普通 v1 自动更新只对已安装的 major 保持启用。在已备份的 canary 上，先运行不安装的审查：

```bash
ssm --json update --major
```

审查目标、发布说明、BC-1 至 BC-10、自动检查、手动检查、回滚指南，以及
`authorized:false`/`installed:false`。随后才能授权该精确的 canary 迁移：

```bash
ssm --json update --major --yes
```

`--yes` 仅在与 `--major` 一起使用时有效；任一标志都不会绕过摘要或 provenance 验证。
只有 canary 通过下面的成功证据要求后，才扩大发布范围。

<!-- ssm-v2-migration: section=success-evidence -->

## 收集成功证据

保留不含 secret 的证据，显示：

- 精确 tag、可执行文件版本、平台和 digest；
- 所选资产的有效 pinned provenance；
- `go run ./cmd/verify release` 在精确 main 上返回了 `preflight_passed`；
- 在线状态是 fresh，或明确批准的 offline 结果如此说明；
- 每次改变状态的 mutation 都返回稳定的 transaction ID，且只发布经过审查的范围；幂等的
  unchanged 结果改为 `changed:false`（`changed=false`）、`action:"unchanged"` 且
  `transaction_id` omitted，因此 do not publish；
- stream 消费者对每个已消费的 non-empty 输入行都观察到一条紧凑 NDJSON 结果；以及
- file/directory 传输消费者按下面的精确 v2 字段进行解释。

绝不把 credentials、解密后的 inventory、vault 字节、私有恢复元数据或 secret-file 内容
作为发布证据保存。

<!-- ssm-v2-migration: section=failure-handling -->

## 失败处理

在最早失败的门禁处停止（stop）。保留（preserve）旧可执行文件、encrypted vault、待处理 ledger、发布意图、
冲突报告和 updater 恢复证据（evidence）。不要扩大 push 范围、静默切换 offline、重新排队 stream 输入、
删除主机密钥、在较新版本不再通过信任后使用旧版本，或把未经验证的二进制文件放到位。

有歧义的发布只能通过比较持久化意图的 prerequisite/target identity 与远端 identity 来解决。
与 target 相等才允许精确 ID finalization；第三种 identity 表示 divergence，必须保持不变，
等待经过审查的协调。

<!-- ssm-v2-migration: section=rollback -->

## 回滚

没有自动降级迁移。只有在 encrypted vault/磁盘 schema 兼容、没有待处理的 v2 发布意图或
Windows updater 恢复、且所有 pending ID 和远程状态都已确认或有意保留时，才可以安全地
重新安装 v1。将保留权限的备份与经过审查的 v1 可执行文件一起恢复。

如果远程发布可能已经提交、本地/远程 encrypted identity 不同、存在 v2-only 意图，或回滚
元数据无法认证，则不要再修改。必要时重新安装 v2，协调精确 identity 和 pending transaction，
然后决定哪份经过审查的 inventory 应保留并完成 reconcile。绝不要为了让 v1 启动而抹去证据。

<!-- ssm-v2-migration: section=troubleshooting -->

## 故障排除

- `sync_config_error` / `sync_config`：修复 `cloud.json` 和权限，或使用全局 `--offline`
  有意接受缓存状态。
- `sync_conflict` / `sync_compare`：保留加密的两端和 `sync-conflict.json`；按照下面经过
  审查的 pull/import 协调流程操作。
- `sync_push_failed`：保留相同的 pending transaction ID，只重试其经过审查的 prerequisite
  和精确范围。
- `update_recovery_required` / `update_recovery`：停止命令分发，保留经过认证的 `.old`
  和 `.old.state` 证据，直到序列化恢复还原精确的原始内容。
- `host_key_unknown|host_key_mismatch`：检查并进行带外验证，然后接受精确的已观察指纹；
  绝不自动移除/重新扫描。

<!-- ssm-v2-migration: section=stream-cardinality-refresh -->

## Stream framing、基数和刷新

`sshctl run <exact-alias> --stream` 从进程启动就使用紧凑 NDJSON。初始化失败会发出一条终止
结果且不消费输入。初始化之后，每个已消费的 non-empty 输入行恰好产生一条有序结果；空行不
产生结果。刷新失败只产生触发该失败的行的一条终止结果并停止进程。没有 ready、summary 或
footer 记录。

在线 `--refresh` 必须严格 positive（positive，默认 30 秒），以便观察 credentials、endpoint、
alias 和 trust 撤销。检测到任何 inventory 更改时，会在使用新缓存之前关闭整个进程 SSH pool。
只有在明确的全局 `--offline` 下才接受 `--refresh=0`；它跳过 cloud 解析/网络访问，并保持一份
固定的缓存 snapshot。

<!-- ssm-v2-migration: section=mutation-publication-reconciliation -->

## Mutation、发布和协调

改变状态的 host add/update/upsert/remove、旧式 `ssm remove`、`ssm keys remove` 以及
`import-json --merge|--replace` 会创建可审查的 pending transaction。ID 稳定（`tx_` 加上 32
个小写十六进制字符）。导入是一个原子 bulk transaction。幂等 host update/upsert 也可能返回
`changed:false`（`changed=false`）、`action:"unchanged"`（`action=unchanged`）且
transaction_id omitted；它不创建新 transaction，因此 do not publish。没有 mutation 会自动发布。

使用 `sshctl --json status` 审查不含 secret 的 ledger。跨 alias 和 saved-key 的
create/replace/rename/delete/prune/reference 依赖会在网络 I/O 之前报告。按 ledger 顺序明确
发布 prerequisite ID，然后发布原始 ID：

```bash
sshctl --json push --only <transaction-id>
```

只有在审查其非空、按 invocation-start 排序的集合后，才使用 `sshctl --json push --all`；之后
创建的 ID 仍保持 pending。Bare push 无效。空 `--all` 只执行一次 identity 比较且 no PUT：相等
时为 no-op，缺失/不同 identity 则是保留的 `sync_conflict`。

对于空 ledger divergence，保留私有证据；仅当缓存的 prerequisite 使替换安全时才运行
`sshctl --json pull`，然后用受保护的
`ssm --offline --json import-json <reviewed-file> --merge` 重新应用保留的本地 inventory。
完整的 `--replace --yes` 需要单独明确的全量替换审查。只发布返回的 transaction。持久化
`publishing-intent.json` 协调（reconcile）使用精确的所选 ID 和 encrypted-blob identity；绝不扩展范围。

生产环境的 merge-only machine hint 必须保持精确：

```text
review sshctl --offline --json doctor and preserve the local vault and sync-conflict.json; run sshctl --json pull to adopt remote, then use guarded ssm --offline --json import-json <reviewed-file> --merge and publish its reviewed transaction with sshctl --json push --only <transaction-id>
```

<!-- ssm-v2-migration: section=update-authorization-trust -->

## 更新授权和信任

普通自动/手动更新只选择已安装 major 内（same-major）较新的 stable release。跨 major 的可用性会报告，但不
会安装。`ssm update --major` 仅供审查；`ssm update --major --yes` 是唯一明确的 major 替换路径。

每次替换仍需要所选 digest，以及针对精确 repository、workflow、issuer、tag、subject 和六目标
release manifest 的 pinned keyless provenance。仅 checksum 的 artifacts 会被拒绝。Draft、
prerelease、格式错误、不完整、较旧或不受信任的 release 不是 fallback。直到验证和原子平台替换
成功，旧可执行文件都保持可用。参见[来源证明运行手册](update-provenance-runbook.zh-CN.md)。

<!-- ssm-v2-migration: section=verification-profiles -->

## 验证配置

`make check` 正是 non-mutating（non-mutating）的 `go run ./cmd/verify ci` 适配器。
`verify fast` 是便利子集，不是 merge 或 release 门禁。`verify ci` 是完整的 non-publishing
（non-publishing）merge 配置。`verify release` 是严格的 non-publishing（non-publishing）
超集，包括六次 cross-build、installer/checksum 检查和 synthetic provenance 验证。

配置只写入私有 verifier 临时/cache 状态，不会获得 publication credentials。它们不会 merge、
tag、install、replace 可执行文件、upload、publish 或创建 GitHub release。其精确前置条件和
运行时边界记录在[验证清单](plans/verification-manifest.md)中。

<!-- ssm-v2-migration: section=all-decisions -->

## 已批准的架构决策

以下登记表将 D01 至 D14 的每项已批准决策映射到运维者可见的行为。详细维护者记录仍在
[架构决策日志](plans/ssm-v2-decision-log.md)中。

<!-- ssm-v2-migration: decision=D01 -->

### D01 — 默认保留兼容性

仅批准 BC-1 至 BC-10 的破坏性变更。CLI、JSON、退出码、磁盘状态、平台行为和安全性都保持兼容，
除非其中一行明确另有说明；major 编号本身永远不授权破坏性变更。

<!-- ssm-v2-migration: decision=D02 -->

### D02 — 缺失配置不同于无效配置

缺失的同步配置仍表示未配置。存在但格式错误或不可读的配置在 online 时是致命错误；只有明确
offline 模式才接受过期的缓存状态，并阻止配置解析和网络访问。

<!-- ssm-v2-migration: decision=D03 -->

### D03 — 有范围的发布具有传递依赖

别名排序以及 saved-key 的创建、替换、重命名、删除、prune 和引用依赖都会预检。报告所需 ID
是安全的，但 SSM 永远不会自动将它们加入所选范围。

<!-- ssm-v2-migration: decision=D04 -->

### D04 — 远程 identity 相等是提交点

持久化的 non-secret 意图先于传输。只有确认 target encrypted-blob identity 后，精确事务才会
变为已发布；丢失的响应和本地 finalization 失败会在重启时协调。

<!-- ssm-v2-migration: decision=D05 -->

### D05 — JSON 和 NDJSON 基数精确

普通机器命令发出一个 JSON 值。Stream 从启动起发出紧凑 NDJSON，每个已消费的 non-empty 行一条
结果，且没有 ready、summary 或 footer 记录；终止刷新失败只消费其触发的那一行。

<!-- ssm-v2-migration: decision=D06 -->

### D06 — 每次 inventory mutation 都可审查

每次改变状态的 mutation 都创建一个 pending transaction，包括旧式删除、saved-key 删除和受保护
的批量导入。若幂等 host update/upsert 报告 `changed:false`、`action:"unchanged"` 并省略
`transaction_id`，它不创建 transaction，也不得发布。没有 mutation 路径会自动发布；发布是之后
的明确操作。

<!-- ssm-v2-migration: decision=D07 -->

### D07 — 无范围和空 ledger 的 push 不能发布

Bare push 无效。非空 all 使用 invocation-start snapshot，而空 all 不执行 PUT，并返回已证明的
no-op 或保留的 divergence，要求经过审查的 pull/import 协调。

<!-- ssm-v2-migration: decision=D08 -->

### D08 — Online stream 保持可刷新

Online 刷新间隔必须严格 positive。零刷新要求全局 offline 模式，该模式有意使用一份固定的过期
snapshot，不解析 cloud 配置，也不访问网络。

<!-- ssm-v2-migration: decision=D09 -->

### D09 — inventory 更改关闭整个 SSH pool

任何 online inventory 更改都会在使用新缓存状态前关闭完整的进程级 SSH pool。即时的 credentials
和 trust 撤销优先于选择性连接复用。

<!-- ssm-v2-migration: decision=D10 -->

### D10 — 三个模块专门负责策略

`machinecontract` 专门负责 failure/redaction/framing/exits；`synctransaction` 专门负责
online/offline refresh、transport、conflicts、freshness 和 invalidation；`inventorytransaction`
专门负责 mutations、dependencies、projection、durable intent、finalization、reconciliation
和 recovery。命令只适配输入和 success payload。

<!-- ssm-v2-migration: decision=D11 -->

### D11 — 自动更新从不授权 major 迁移

普通替换保持在当前 major 内。major 迁移先展示 release notes、所有批准的破坏性变更、自动检查、
手动检查和回滚指南，然后要求明确的 `--major --yes` 授权。

<!-- ssm-v2-migration: decision=D12 -->

### D12 — 固定 provenance 阻止不合规发布

HTTPS 和相邻 checksum 不能建立发布权威。绑定 repository、workflow、精确 tag、subject 和
issuer 的 digest 加 keyless provenance，必须在所有受支持平台上通过后才能替换。

<!-- ssm-v2-migration: decision=D13 -->

### D13 — 一个 manifest 定义验证

一个签入仓库的 non-mutating manifest 负责配置、操作、顺序、前置条件和扩展。CI 与 `make check`
共用 `verify ci`；release 使用严格超集，而 coverage 仍然只是观察性的。

<!-- ssm-v2-migration: decision=D14 -->

### D14 — 传输输出表明真实保证

Direction、kind 和 failure stage 都是明确的。常规文件 detail 保持兼容，而 directory 字段报告
不支持/不可用的保证，或省略所选协议无法真实提供的测量值。

Direct CLI 和 request-v1 结果使用相同的成功合同：

| 路径 | 成功后始终存在 | 条件字段 | 明确保证或省略 |
| --- | --- | --- | --- |
| 文件 put | `ok`、`action`、`alias`、`local`、`remote`、`direction=put`、`kind=file`、`stage=complete`、`bytes_sent`、`integrity`、`atomic`、`resume` | 仅 digest 验证时有 `local_sha256`、`remote_sha256`；仅 resume 时有 `bytes_reused` | `atomic=true`；integrity 和 resume state 描述选定协议；省略 `bytes_received` |
| 目录 put | 公共 identity 字段、`direction=put`、`kind=directory`、`stage=complete`、`bytes_sent=0`、`integrity=not_available`、`atomic=false`、`resume=unsupported` | 无 | 省略 digest、reuse、receive-byte 字段；不承诺整棵目录 atomicity 或 integrity |
| 文件 get | 公共 identity 字段、`direction=get`、`kind=file`、`stage=complete`、实际 `bytes_received`、`integrity=not_checked`、`atomic=true`、`resume=unsupported` | 无 | 省略 `bytes_sent`、digest、reuse 字段；atomic 表示本地最终路径发布，不表示端到端 digest 验证 |
| 目录 get | 公共 identity 字段、`direction=get`、`kind=directory`、`stage=complete`、`integrity=not_available`、`atomic=false`、`resume=unsupported` | 无 | 省略 `bytes_sent`、`bytes_received`、digest、reuse 字段，因为 tar 没有稳定 payload 度量或整棵目录保证 |

失败时，canonical envelope 仍是 `ok:false`、`error`、`message`、`hint`、`exit`；增加
`direction`、已发现的 `kind` 和 canonical `stage` 而不改变分类器。`kind=unknown` 仅限协议
kind 尚不可知之前的失败。Staged 文件/目录恢复在恢复成功时保留原目标；若目录恢复也失败，则
保留一个 backup，且不声称 unchanged-final。

<!-- ssm-v2-migration: section=release-blockers -->

## 发布阻断项

初始 v2 在下列全部源程序发布条件通过前保持阻断：

- all child tickets 直至 #31 都带验收和验证证据关闭，包括 #31 的非发布 final readiness；
- compiled public contract matrix 覆盖每个稳定失败类别和每个批准的旧/新行为；
- `verify ci` 是唯一 non-mutating 的 `make check`/CI 命令集合，而 `verify release` 是经过测试的
  严格超集，覆盖 six supported target combinations、source/tag/assets、migration、updater、digest、
  provenance、identity-rotation 和 recovery 失败；
- publication crash/retry 覆盖 intent、send、remote-commit、response 和 local-finalization 的每个窗口；
- every mutation and push entry point 都由 inventory transaction 模块拥有，且三模块
  contraction/deletion 门禁通过；
- 双语迁移文档和 release notes 包含 BC-1 至 BC-10 的完整 field-level/behavioral matrix；以及
- no secrets 进入 fixture 或诊断，所有安全契约保持完好，权威 CI/审查通过且全部精确资产就绪。

已提升的 `v2-readiness-report` 清单检查会依据可执行的
`initial_v2_release_readiness` profile，校验已签入的 BC-1 至 BC-10 与发布证据映射。完整的
`preflight_passed` 结果是最终就绪证据，但不代表已经发布。

验证 does not merge、tag、upload、publish artifacts 或创建 release。只有在所有阻断项通过后，官方的
精确 tag workflow 才可以执行这些操作。

<!-- ssm-v2-migration: section=reviewer-mapping -->

## 审查者映射

以下每一项都是必审项。每条 BC 把摘要矩阵映射到已检查的旧/新 fixture 和最终行为；决策与发布项
映射到稳定的章节锚点。

- [ ] BC-1 — [BC 矩阵](#bc-contract-matrix)；[Issue #20 最终行为](plans/issue-20-sync-transaction-ownership.md)；[已检查旧/新 fixture 源码](../cmd/ssm/compiled_cli_contract_test.go)
- [ ] BC-2 — [BC 矩阵](#bc-contract-matrix)；[Issue #22 最终行为](plans/issue-22-inventory-transaction-ownership.md)；[已检查旧/新 fixture 源码](../cmd/ssm/inventory_transaction_compiled_test.go)
- [ ] BC-3 — [BC 矩阵](#bc-contract-matrix)；[Issue #21 最终行为](plans/issue-21-stream-contract-migration.md)；[已检查旧/新 fixture 源码](../cmd/ssm/compiled_stream_contract_test.go)
- [ ] BC-4 — [BC 矩阵](#bc-contract-matrix)；[Issue #24 最终行为](plans/issue-24-legacy-mutation-ownership.md)；[已检查 legacy fixture 源码](../cmd/ssm/legacy_mutation_compiled_test.go)；[Issue #23 最终协调行为](plans/issue-23-publication-intent.md)；[已检查 crash fixture 源码](../cmd/ssm/publication_intent_compiled_test.go)
- [ ] BC-5 — [BC 矩阵](#bc-contract-matrix)；[Issue #25 最终行为](plans/issue-25-exact-push-scopes.md)；[已检查旧/新 fixture 源码](../cmd/ssm/push_scope_compiled_test.go)
- [ ] BC-6 — [BC 矩阵](#bc-contract-matrix)；[Issue #21 最终行为](plans/issue-21-stream-contract-migration.md)；[已检查旧/新 fixture 源码](../cmd/ssm/compiled_stream_contract_test.go)
- [ ] BC-7 — [BC 矩阵](#bc-contract-matrix)；[Issue #26 最终行为](plans/bc-7-transfer-outcome-migration.md)；[已检查旧/新 fixture 源码](../cmd/ssm/transfer_outcome_test.go)
- [ ] BC-8 — [BC 矩阵](#bc-contract-matrix)；[Issue #27 最终行为](plans/issue-27-major-update-migration.md)；[已检查旧/新 fixture 源码](../internal/update/update_test.go)
- [ ] BC-9 — [BC 矩阵](#bc-contract-matrix)；[Issue #28 最终行为](plans/issue-28-pinned-provenance.md)；[已检查旧/新 fixture 源码](../internal/update/update_test.go)
- [ ] BC-10 — [BC 矩阵](#bc-contract-matrix)；[最终验证行为](plans/verification-manifest.md)；[已检查 profile/release fixture 源码](../cmd/verify/main_test.go)
- [ ] D01 — [决策契约](#d01--默认保留兼容性)
- [ ] D02 — [决策契约](#d02--缺失配置不同于无效配置)
- [ ] D03 — [决策契约](#d03--有范围的发布具有传递依赖)
- [ ] D04 — [决策契约](#d04--远程-identity-相等是提交点)
- [ ] D05 — [决策契约](#d05--json-和-ndjson-基数精确)
- [ ] D06 — [决策契约](#d06--每次-inventory-mutation-都可审查)
- [ ] D07 — [决策契约](#d07--无范围和空-ledger-的-push-不能发布)
- [ ] D08 — [决策契约](#d08--online-stream-保持可刷新)
- [ ] D09 — [决策契约](#d09--inventory-更改关闭整个-ssh-pool)
- [ ] D10 — [决策契约](#d10--三个模块专门负责策略)；[Issue #29 最终三模块 ownership 行为](plans/issue-29-three-module-contraction.md)；[已检查 contraction fixture 源码](../cmd/ssm/deep_policy_ownership_test.go)
- [ ] D11 — [决策契约](#d11--自动更新从不授权-major-迁移)
- [ ] D12 — [决策契约](#d12--固定-provenance-阻止不合规发布)
- [ ] D13 — [决策契约](#d13--一个-manifest-定义验证)
- [ ] D14 — [决策契约](#d14--传输输出表明真实保证)
- [ ] Release blockers — [初始 v2 发布门禁](#发布阻断项)
- [ ] Rollback guarantees — [迁移回滚契约](#回滚)

<!-- markdownlint-disable MD013 -->
### BC contract matrix

<!-- ssm-v2-migration: bc-table columns=bc|old|new|affected|action|machine|rollback -->
| bc | old | new | affected | action | machine | rollback |
| --- | --- | --- | --- | --- | --- | --- |
| BC-1 | 现有无效 `cloud.json` 可能被当作未配置同步处理。 | 每条 online inventory 路径都失败并返回 `sync_config_error`。 | Online 读取、mutations、stream 启动、sync、push 和 pull。 | 修复文件/权限，或用明确的 `--offline` 接受过期状态。 | `process exit=1`；`cardinality=one JSON value or one terminal NDJSON record`；失败包含 `stage=sync_config`、`exit=1`；offline 发出零网络请求。 | 不改变状态；恢复有效配置或备份的 encrypted state。 |
| BC-2 | 同别名检查可能发布带有跨别名悬空 saved-key 引用的内容。 | 传递依赖（如 `saved_key_create`）在网络前拒绝。 | `push --only <transaction-id>` 调用方和共享 saved-key 更改。 | 按 ledger 顺序发布每个报告的 prerequisite transaction，然后重试原始 ID。 | `process exit=1`；`cardinality=one JSON value`；稳定且安全的 transaction/alias/key/reason 字段、零网络（network）请求且不自动扩展范围。 | 本地 encrypted vault 保持 pending，字节/逻辑状态得到保留。 |
| BC-3 | Stream 启动失败是一个缩进的普通 JSON 文档。 | Stream 输出从 `startup` 起是紧凑（compact）NDJSON，并有一条 `terminal` 初始化结果。 | 面向行的 stream 读取器和 supervisor。 | 每行解析一条紧凑（compact）记录，在终止的启动/刷新失败后停止。 | `process exit=1`；`cardinality=one terminal NDJSON record`；`startup` 不消费输入，也没有 stderr、ready、summary 或 footer。 | 修复刷新后再重启，或明确选择 offline 缓存状态。 |
| BC-4 | `remove`、`keys remove` 和 `import-json` 可能保存/自动发布而没有可审查 mutation。 | 每个操作追加一个 pending transaction，且从不自动 publish。 | 旧式 mutation 和批量迁移调用方。 | 审查 `transaction_id`、依赖，然后明确发布精确 ID。 | `process exit=0 on success`，已分类失败的 exit 不变；`cardinality=one JSON value`；稳定 ID 和不含 secret 的 pending receipt；已配置 mutation 会刷新但不 publish。 | 保留之前的 ledger；晚期验证失败保持 vault 字节不变。 |
| BC-5 | Bare push 表现得像 all，空 ledger all 可能 PUT 整个本地 blob。 | Bare push 返回 `invalid_arguments`；非空 all 对 invocation-start ID 做 snapshot；空 all 不执行 PUT，并可能返回 `sync_conflict`。 | 所有发布包装器和恢复工具。 | 使用精确 `--only`，或有意使用非空 `--all`；对 divergence 遵循审查过的 merge 恢复。 | `process exit=2 for bare`；`process exit=1 for divergence`；`cardinality=one JSON value`；bare 在 unlock/network 前失败，空相等是 no PUT、noop，divergence 为 `stage=sync_compare`。 | 保留本地/远程 blob 和私有冲突证据；只有审查后才能 pull/import/re-publish。 |
| BC-6 | Online `--refresh=0` 接受仅启动时的 snapshot。 | Online refresh 必须为 positive；零值需要明确的 `--offline`。 | 长时间运行的 stream 消费者。 | 使用 positive 默认值/间隔，或明确接受一份过期的 offline 缓存 snapshot。 | `process exit=2`；`cardinality=one terminal NDJSON record`；online 零值是 `invalid_arguments`、`exit=2`，不消费输入，也不建立 sync/SSH 连接。 | 使用 positive 间隔重启；offline 回滚意味着保留固定缓存 snapshot。 |
| BC-7 | Direct/request-v1 传输字段不同，且可以推断 directory 保证。 | Direct 和 request-v1 共用 `direction`、`kind`、`stage`；request-v1 支持 get。 | 文件/目录 put/get JSON 消费者。 | 按 direction/kind 分支：文件 put 有 `bytes_sent`；文件 get 有 `bytes_received`；directory get 保持 `bytes_received` omitted。 | `process exit=0 on success`，已分类失败的 exit 不变；`cardinality=one JSON value`；文件 put 按条件增加 `local_sha256`、`remote_sha256`、`bytes_reused`；文件 get 为 `not_checked`、atomic true、resume unsupported；directory put/get 为 `not_available`、`atomic=false`、`resume=unsupported` 并省略 digest/reuse；directory put 的 bytes_sent 为零；direct/request-v1 parity。 | 文件 staging 保留先前 final；directory restore 失败保留一条 backup 路径，且不声称 unchanged-final。 |
| BC-8 | 自动最新版本替换可能跨越 major 边界。 | 自动/手动普通更新为 same-major；`update --major --yes` 是明确迁移。 | Installer、无人值守更新作业和发布系统。 | 先运行 review，要求自动/手动检查，然后授权精确目标。 | `process exit=0 on successful review/install`，已分类失败的 exit 不变；`cardinality=one JSON value`；review 报告 `installed=false`、breaks/checks/rollback；普通状态只报告跨 major 可用性。 | Trust/preflight 失败保留旧可执行文件；仅在兼容状态假设下恢复经审查的 v1。 |
| BC-9 | 仅相邻 `checksums.txt` digest 就能授权替换。 | digest 加精确 pinned provenance 以及 14-name release manifest 是强制要求。 | Updater、installer、release workflow 和全部六个平台。 | 验证 `Cd1s/ssm`、精确 tag 的 `release.yml` identity、issuer、subject、digest 和 rotation 状态。 | `process exit=1 on trust failure`；`cardinality=one JSON value for updater machine mode`，installer 保持非 JSON；任一 selection/trust/digest/provenance 失败都无 fallback，并保留已安装字节/模式。 | 使用保留的可执行文件；通过审查的 overlap 进行轮换，绝不使用 checksum-only 或 skip 路径。 |
| BC-10 | `make check` 运行了 `gofmt -w`、PATH lint 和仓库根目录构建。 | `make check` 是 non-mutating `verify ci`；`verify release` 是 non-publishing 严格超集。 | 贡献者、CI、release 维护者和外部门禁包装器。 | 安装精确前置条件，并要求在安全的干净 worktree 上完成配置。 | `process exit=0 only on completed profile`，否则非零；`cardinality=not a JSON/NDJSON contract`：确定性的检查行加一条终止状态；release 成功是 `preflight_passed` 就绪证据，而不是发布。 | 恢复未改动的源代码；修复前置条件或操作失败，不削弱 manifest。 |
<!-- markdownlint-enable MD013 -->

<!-- ssm-v2-migration: guide-end -->
