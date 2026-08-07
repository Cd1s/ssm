# v2 follow-up closure status

Status: reviewed against default-branch merge `707fbf61aea59a9f106b10889c6ecbe38bab29c1`.

These follow-ups are closed as implementation/documentation decisions. This
record does not claim that a new protocol or security bypass was introduced.

| Follow-up | Resolution | Evidence |
| --- | --- | --- |
| No-transaction local/remote divergence repair | **Implemented as reviewed repair only.** Preserve encrypted local state, `remote.etag`, and `sync-conflict.json`; inspect with offline doctor; adopt remote with guarded pull; reapply reviewed inventory through offline merge/replace; publish only the returned transaction ID. No force, automatic repair, evidence deletion, or empty-ledger overwrite exists. | `docs/plans/issue-25-exact-push-scopes.md` § Reviewed divergence recovery; `docs/migration-v1-to-v2.zh-CN.md`; `internal/machinecontract/contract_test.go`; `internal/synctransaction/policy_test.go` |
| Publishing-intent encoding/location | **Implemented and frozen.** Private additive sidecar `$SSM_CONFIG_DIR/publishing-intent.json`, strict version-2 JSON, v1 sanitization, atomic replacement, exact ID scope and encrypted-blob identities. | `docs/plans/issue-23-publication-intent.md`; `internal/inventorytransaction/publication_intent*.go`; `internal/inventorytransaction/publication_intent_test.go` |
| Directory put/get field matrix | **Implemented and frozen.** Direct and request-v1 parity, explicit `direction`/`kind`, truthful `atomic`, `integrity`, `resume`, and `bytes_received` omission rules. | `docs/plans/bc-7-transfer-outcome-migration.md`; `internal/ssh/dirsync_test.go`; compiled transfer contract tests |
| Keyless identity rotation and emergency recovery | **Implemented as a reviewed overlap runbook.** Pin repository/workflow/issuer and certificate boundary; add a new identity only after negative matrices and six-platform verification; retain old/new overlap; retire old identity only after released clients accept the new one. Emergency path is fail-closed recovery with no wildcard, alternate issuer, checksum-only bridge, or verification bypass. | `docs/update-provenance-runbook.md` §§ Issuer and certificate-policy pin, Reviewed identity rotation, Emergency recovery; `SECURITY.md`; `docs/plans/issue-28-pinned-provenance.md` |
| Selective SSH-pool invalidation | **Closed as not adopted.** The approved v2 contract intentionally invalidates the entire process-scoped SSH pool after any changed inventory. Selective invalidation remains rejected unless a complete connection-security identity model and exhaustive native tests are added; no weaker implementation is shipped. | `docs/plans/ssm-v2-decision-log.md` Out of scope; `internal/synctransaction/transaction.go`; `internal/synctransaction/policy_test.go`; stream contract tests |

## Closure boundary

The five items refine already-approved v2 behavior and operations. They do not
close the release umbrella by themselves: release state, exact-head CI, asset
inventory, provenance, installer, and disposable canary evidence remain
separate gates. No tag, release, latest promotion, or live installation change
is authorized by this document.
