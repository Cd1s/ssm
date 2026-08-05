# SSM 更新 provenance 运行手册

本运行手册规定当前 GitHub latest v2.0.0 所涉及的 updater、installer、
release-maintainer 和紧急恢复决策。运行手册本身不会发布 tag、release 或修改 latest
指针；v1.4.3/v1.4.4 客户端仍必须经过审查并显式授权 major 迁移才能选择 v2。

[English](update-provenance-runbook.md) | [迁移指南](migration-v1-to-v2.zh-CN.md)

<!-- ssm-v2-provenance: runbook-begin -->

<!-- ssm-v2-provenance: repository-pin -->

## Repository 和 manifest pin

唯一接受的 repository 是 `Cd1s/ssm`。所选 release 必须恰好包含 14 个名称：`install.sh`、
`checksums.txt`、下面六个 binary，以及每个 binary 相邻的一个 `.sigstore.json` bundle：

```text
ssm-linux-amd64
ssm-linux-arm64
ssm-darwin-amd64
ssm-darwin-arm64
ssm-windows-amd64.exe
ssm-windows-arm64.exe
```

缺少、多出、重复或命名错误的资产都会使所选 release 不符合条件。选择在信任失败后绝不会
回退到旧 release。

<!-- ssm-v2-provenance: workflow-pin -->

## Workflow 和精确 tag identity pin

经过审查的 workflow 路径是 `.github/workflows/release.yml`。identity-set 版本
`release-tag-v1` 只接受这一精确 subject alternative name：

```text
https://github.com/Cd1s/ssm/.github/workflows/release.yml@refs/tags/EXACT_SELECTED_TAG
```

Tag 文本是 authority 数据。`1.2.3` 和 `v1.2.3` 永远不会相互授权。未版本化的 branch、不同
tag、workflow alias、wildcard 或未审查 workflow 都不能授权替换。

<!-- ssm-v2-provenance: issuer-pin -->

## Issuer 和证书策略 pin

Issuer 是 `https://token.actions.githubusercontent.com`；构建必须使用经过审查的
GitHub-hosted runner 策略，以及针对 `release-tag-v1`、不早于 2026-07-30 00:00:00 UTC 的
证书边界。备用 issuer、自托管 runner、未知 identity、已过期/尚未生效的证书和未审查的 ref
claim 都会 fail closed。

<!-- ssm-v2-provenance: digest-binding -->

## Digest 和 subject 绑定

每个相邻 bundle 都是 Sigstore bundle media type v0.3，恰好包含一个 DSSE in-toto Statement v1、
SLSA provenance v1 predicate 和恰好一个 subject。Subject name 必须等于所选 asset name，其
SHA-256 必须同时等于唯一的 `checksums.txt` 记录和下载的字节。

仅有 HTTPS、checksum 或 provenance 都不足够。Metadata 和 bundle stream 限制为 1 MiB，checksum
限制为 16 KiB，binary 限制为 64 MiB；即使通过重定向或未知长度响应，超过限制一个字节也会被
拒绝。Installer 需要 `jq`、`head -c`、SHA-256 工具和提供 `gh attestation verify` 的当前
GitHub CLI。

<!-- ssm-v2-provenance: identity-rotation -->

## 经过审查的 identity 轮换

冻结拟议的 repository/workflow/issuer identity；只有在代码、synthetic negative matrix、
installer 行为和全部六个平台通过审查后，才将其作为 bridge verifier 加入。旧、新审查过的
identity 至少重叠 seven（seven）个完整日，并在切换 release workflow 前用新 identity 发布一
个完整的六目标 release。

重叠期间，回滚恢复旧的审查 identity，并且只发布仍通过未改变的 digest-and-provenance 规则的
release。只有在已发布客户端接受新 identity 后，才退役旧 identity。绝不使用 wildcard、branch
identity、备用 issuer、checksum-only bridge 或 verification skip 来缩短轮换。

<!-- ssm-v2-provenance: emergency-recovery -->

## 紧急 release 恢复

遇到损坏、缺失、格式错误、过期、错误 subject 或错误 digest 的 bundle 时，冻结发布并保持每个
已安装可执行文件不变。保留失败 release 的元数据和不含 secret 的 verifier 诊断。Release owner
必须通过审查过的 identity 修复或重新发布精确的 14-name 集合；客户端不得回退到旧 release。

如果所有接受的 identity 都不再可用，先通过仍然有效的 identity 审查并发布 bridge client。若
没有这条路径，则要求人工带外重新安装，并独立审查 binary、checksum、provenance、tag 和 source
commit。这是紧急 trust 决策，而不是 updater bypass。

<!-- ssm-v2-provenance: old-executable-recovery-state -->

## 旧可执行文件和平台恢复状态

在 canonical replacement 之前，trust 或 authorization 失败会保留旧 executable 字节和 mode，
并删除 staging 输出。Unix replacement 会认证 descriptor-bound/private sibling state，并保留
精确旧 object 供回滚；它不声称在每个有限 acceptance boundary 之后能防止同样获授权的 writer。

Windows 在 replacement 和 rollback 期间保留 update lock 及已验证 handles。如果 forward commit
和 authenticated rollback 都在旧 image 移动后拒绝，结果是在 `stage=update_recovery` 的
`update_recovery_required`。保留精确的 `.old` object 和仅 owner 可读的 `.old.state`；启动时会
阻止 command dispatch、stdin 和后续 update 工作，直到序列化恢复在 canonical path 验证 File ID、
SHA-256 和所选 security descriptor tier。不要手动删除该记录。

<!-- ssm-v2-provenance: verification-no-bypass -->

## 验证和 no-bypass 规则

在精确且干净的 release commit 上运行 `go run ./cmd/verify release`。要求全部六个 asset build、
精确 checksum 输入、synthetic provenance 生成、identity/digest negative matrix、installer
失败保留和原生平台替换测试。`preflight_passed` 只是证据：验证不会 tag、upload、publish、
install 或替换生产可执行文件。

There is no verification bypass（no verification bypass）。`--major --yes`
授权经过审查的 major 迁移，但不能授权失败的 digest、provenance、manifest、identity 或 recovery 检查。保留旧可执行
文件和证据，通过官方 workflow 修复 release，且只有权威验证通过后才重试。

<!-- ssm-v2-provenance: runbook-end -->
