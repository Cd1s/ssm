# BC-7 truthful transfer outcome migration

This document records the compiled direct CLI and request-v1 behavior at
`de66f23` before BC-7, and the approved migration implemented by issue 26.
The SSH file, resumable-v1, and tar transports are unchanged.

## Success field matrix

`always` means the JSON member is emitted on every successful route. `option`
means it is emitted only when that existing option/protocol supplies it. `—`
means omitted. Direct and request-v1 use the same renderer after request
validation, so every after-BC-7 row has direct/request parity.

| Field | file put before | file put after | directory put before | directory put after | file get before | file get after | directory get before | directory get after |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `ok` | always | unchanged | always | unchanged | always | unchanged | always | unchanged |
| `action` | `put` | unchanged | `put` | unchanged | `get` | unchanged | `get` | unchanged |
| `alias` | always | unchanged | always | unchanged | always | unchanged | always | unchanged |
| `local` / `remote` | always | unchanged | always | unchanged | always | unchanged | always | unchanged |
| `direction` | — | `put` | — | `put` | — | `get` | — | `get` |
| `kind` | — | `file` | — | `directory` | — | `file` | — | `directory` |
| `stage` | `complete` | unchanged | `complete` | unchanged | — | `complete` | — | `complete` |
| `bytes_sent` | always | unchanged | `0` | unchanged | — | — | — | — |
| `bytes_received` | — | — | — | — | — | actual local file size | — | omitted: tar has no stable payload measure |
| `integrity` | existing value | unchanged | `not_available` | unchanged | — | `not_checked` | — | `not_available` |
| `local_sha256` / `remote_sha256` | option | unchanged | — | — | — | — | — | — |
| `atomic` | existing value | unchanged | `false` | unchanged | — | `true` | — | `false` |
| `resume` | existing value | unchanged | `unsupported` | unchanged | — | `unsupported` | — | `unsupported` |
| `bytes_reused` | option | unchanged | — | — | — | — | — | — |

Before BC-7, request-v1 accepted `put` only. BC-7 adds strict-schema `get`
with the same output as direct get; unknown fields and malformed requests remain
`invalid_request`.

## Failure field and stage matrix

All failures retain canonical `ok=false`, `error`, `message`, `hint` when
applicable, and `exit`. `alias`, `local`, and `remote` are context and are not
classifiers.

| Failure route | Before BC-7 | After BC-7 exact additions/semantics | Protocol guarantee source |
| --- | --- | --- | --- |
| put local stat/read | upload projection; no direction/kind | `direction=put`, `kind=unknown`, `stage=local_read`; existing upload fields remain | no protocol selected |
| file put validate/local read | existing upload fields | `direction=put`, `kind=file`; canonical stage; `atomic`/`resume`/`integrity` reflect selected file protocol | file adapter/result |
| directory put unsupported option/source | upload-shaped failure | `direction=put`, truthful `kind` (`directory` after stat, otherwise `unknown`), `stage=validate` or `local_read`; `atomic=false`, `resume=unsupported`, `integrity=not_available` | tar/walk has no whole-tree guarantees |
| file/directory put session or remote write | existing failure projection | direction/kind plus canonical `session`/`remote_write`; old regular-put byte/receipt fields retained | selected SSH protocol |
| get discovery/probe | generic download failure; no stage/direction/kind | `direction=get`, `kind=unknown`, `stage=discovery` (or canonical session stage when transport classification is available), paths retained | probe cannot invent file/directory kind |
| file get remote read/local write/publish | generic download failure | `direction=get`, `kind=file`, canonical stage, `atomic=true`, `resume=unsupported`, `integrity=not_checked`, `bytes_received` only for bytes actually staged | sibling temp file + rename |
| directory get remote read/local write/publish | generic download failure | `direction=get`, `kind=directory`, canonical stage, `atomic=false`, `resume=unsupported`, `integrity=not_available`, `bytes_received` omitted | sibling staging directory + publish/restore sequence |

`kind=unknown` is reserved for failure before a transfer protocol is selected.
It is not a third successful transfer kind.

## Direct/request parity

`TestTransferDirectAndRequestParity` compares direct and request-v1 file and
directory put/get results. `TestCompiledTransferOutcomeMatrix` pins all four
successful direction/kind routes and strict request-v1 get acceptance.
`TestCompiledTransferAdaptersPreserveFailureProjections` pins canonical failure
fields for missing local input, file and directory put session failures, get
session failures, and redirect context. Regular put/resume fields remain
covered by the pre-existing compiled compatibility fixtures.
`TestCompiledRegularDownloadRemoteReadFailurePreservesDestinationAndRemovesTemps`
and `TestCompiledDirectoryDownloadStreamFailuresPreserveDestinationAndRemoveTemps`
exercise both direct and request-v1 get through the compiled CLI and assert the
same failure identity and final/temp-path safety for each adapter.

## Final and temporary path evidence

| Route/failure | Final-path evidence | Temporary-path evidence | Test source |
| --- | --- | --- | --- |
| file put success | final remote bytes and optional digest match | sibling remote temp is renamed only after receipt/checksum | existing put, SHA-256 and resume compiled/SSH tests |
| file put timeout/disconnect/corrupt resume/source change | existing final is not replaced by incomplete bytes | partial/state files follow resumable-v1 cleanup/retention rules | `scripts/ssh_matrix_test.sh` put timeout/resume cases |
| file get success | local final matches remote bytes | local sibling temp is closed/chmodded before rename | `TestCompiledTransferOutcomeMatrix` |
| file get discovery failure | pre-existing local final remains byte-identical | no file staging begins, and no `.ssm-get-*` output exists | `TestTransferGuaranteesAreTruthful` |
| file get remote-read failure | pre-existing local final remains byte-identical for direct and request-v1 | partially streamed `.ssm-get-*` output is removed | `TestCompiledRegularDownloadRemoteReadFailurePreservesDestinationAndRemovesTemps` |
| file get local-write failure | pre-existing local final remains byte-identical after a deterministic post-stream chmod failure | `.ssm-get-*` output is removed | `TestRegularDownloadFilesystemFailuresPreserveDestinationAndRemoveTemps` / `local write` |
| file get publish/rename failure | pre-existing local final remains byte-identical after a deterministic rename failure | `.ssm-get-*` output is removed | `TestRegularDownloadFilesystemFailuresPreserveDestinationAndRemoveTemps` / `publish` |
| directory get success | staged tree becomes final only after tar/session success | sibling `.ssm-get-dir-*` is renamed; prior destination backup is removed | `TestCompiledTransferOutcomeMatrix` |
| directory get remote-read failure | pre-existing local tree remains byte-identical for direct and request-v1 | `.ssm-get-dir-*` staging is removed after the local extractor is stopped and reaped | `TestCompiledDirectoryDownloadStreamFailuresPreserveDestinationAndRemoveTemps` / `remote read` |
| directory get extraction/local-write failure | pre-existing local tree remains byte-identical for direct and request-v1 | partially extracted `.ssm-get-dir-*` staging is removed | `TestCompiledDirectoryDownloadStreamFailuresPreserveDestinationAndRemoveTemps` / `local extraction write` |
| directory get publish failure with successful restore | prior destination is restored byte-for-byte after deterministic staging rename failure | failed `.ssm-get-dir-*` staging is removed and the backup is renamed back, leaving no `.ssm-get-*` sibling | `TestDirectoryDownloadPublishFailureRestoresDestinationAndRemovesTemps` |
| directory get publish plus restore failure | no unchanged-final claim is made; the prior tree is byte-identical at the exact retained backup path named by the error | failed `.ssm-get-dir-*` staging is removed; exactly one `.ssm-get-backup-*` remains for operator recovery | `TestDirectoryDownloadRestoreFailureRetainsBackupWithoutPreservationClaim` |

Directory results remain `atomic=false`: the portable tar transport does not
promise a whole-tree atomic exchange. A restoration failure is never reported
as preservation success: it retains the public `publish_failed` error and
`publish` stage, uses a restore-specific recovery hint, and names the retained
backup path in the error.

## Consumer migration

Consumers must select `direction` and `kind`, not infer them from `action`, byte
fields, or guarantee fields. Existing regular-put consumers may continue
reading their old fields. Consumers must treat `not_available`, `not_checked`,
`unsupported`, and `atomic=false` as explicit absence or limitation of a
guarantee. Failures must branch on canonical `error` and `stage`; paths are
context only.
