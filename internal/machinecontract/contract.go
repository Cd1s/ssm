// Package machinecontract owns the public failure taxonomy and its rendering.
// Command packages retain typed success results and identify failures by
// semantic Kind; public codes, stages, hints, exits, redaction, framing, and
// output placement stay here.
package machinecontract

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssm/internal/synctransaction"
)

// Kind identifies a failure context without exposing its serialized policy to
// callers.
type Kind string

const (
	InternalFailure                     Kind = "internal_failure"
	UnknownSSHCTLCommand                Kind = "unknown_sshctl_command"
	UnknownSSMCommand                   Kind = "unknown_ssm_command"
	InvalidRequestDocument              Kind = "invalid_request_document"
	MasterPassFileRequiredCreate        Kind = "master_pass_file_required_create"
	AliasNotFound                       Kind = "alias_not_found"
	SyncConflict                        Kind = "sync_conflict"
	EmptyLedgerSyncConflict             Kind = "empty_ledger_sync_conflict"
	SyncPullFailed                      Kind = "sync_pull_failed"
	StreamSyncPullFailed                Kind = "stream_sync_pull_failed"
	TransferLocalRead                   Kind = "transfer_local_read"
	DialTimeout                         Kind = "dial_timeout"
	DialRefused                         Kind = "dial_refused"
	DialNetwork                         Kind = "dial_network"
	HostKeyUnknown                      Kind = "host_key_unknown"
	HostKeyMismatch                     Kind = "host_key_mismatch"
	AuthenticationFailed                Kind = "authentication_failed"
	NoAuthenticationConfigured          Kind = "no_authentication_configured"
	SessionFailed                       Kind = "session_failed"
	RemoteCommandFailed                 Kind = "remote_command_failed"
	InterpreterNotFound                 Kind = "interpreter_not_found"
	RemoteScriptFailed                  Kind = "remote_script_failed"
	ScriptSyntaxFailed                  Kind = "script_syntax_failed"
	HostInvalidArguments                Kind = "host_invalid_arguments"
	HostApplyInvalidArguments           Kind = "host_apply_invalid_arguments"
	HostAliasNotFound                   Kind = "host_alias_not_found"
	HostVerificationFailed              Kind = "host_verification_failed"
	HostPushFailed                      Kind = "host_push_failed"
	HostSyncPullFailed                  Kind = "host_sync_pull_failed"
	HostVaultFailed                     Kind = "host_vault_failed"
	HostAuthenticationRequired          Kind = "host_authentication_required"
	HostApplyAuthenticationRequired     Kind = "host_apply_authentication_required"
	HostConfirmationRequired            Kind = "host_confirmation_required"
	HostAlreadyExists                   Kind = "host_already_exists"
	HostInvalidAlias                    Kind = "host_invalid_alias"
	HostSavedKeyNotFound                Kind = "host_saved_key_not_found"
	HostInvalidAddress                  Kind = "host_invalid_address"
	HostInvalidUser                     Kind = "host_invalid_user"
	HostInvalidGroup                    Kind = "host_invalid_group"
	HostPasswordFileFailed              Kind = "host_password_file_failed"
	HostKeyFileFailed                   Kind = "host_key_file_failed"
	HostInvalidKey                      Kind = "host_invalid_key"
	HostKeyConflict                     Kind = "host_key_conflict"
	HostTransactionFailed               Kind = "host_transaction_failed"
	HostInternalFailure                 Kind = "host_internal_failure"
	PanicFailure                        Kind = "panic_failure"
	GenericFailure                      Kind = "generic_failure"
	UpdateFailed                        Kind = "update_failed"
	UpdateMigrationFailed               Kind = "update_migration_failed"
	MissingCommand                      Kind = "missing_command"
	InvalidGlobalArguments              Kind = "invalid_global_arguments"
	SSHCTLCommandRequired               Kind = "sshctl_command_required"
	InvalidSSHCTLArguments              Kind = "invalid_sshctl_arguments"
	RunAliasRequired                    Kind = "run_alias_required"
	PlanAliasRequired                   Kind = "plan_alias_required"
	CheckAliasRequired                  Kind = "check_alias_required"
	UnsupportedInteractiveShell         Kind = "unsupported_interactive_shell"
	InvalidStreamArguments              Kind = "invalid_stream_arguments"
	MasterPassFileReadFailed            Kind = "master_pass_file_read_failed"
	MasterPassFileEmpty                 Kind = "master_pass_file_empty"
	VaultCreateFailed                   Kind = "vault_create_failed"
	VaultUnlockFailed                   Kind = "vault_unlock_failed"
	MasterPassFileRequiredExisting      Kind = "master_pass_file_required_existing"
	InvalidRequestRun                   Kind = "invalid_request_run"
	InvalidRequestAlias                 Kind = "invalid_request_alias"
	InvalidRequestCheck                 Kind = "invalid_request_check"
	InvalidRequestDoctor                Kind = "invalid_request_doctor"
	InvalidRequestDoctorAlias           Kind = "invalid_request_doctor_alias"
	InvalidRequestHost                  Kind = "invalid_request_host"
	InvalidRequestPutFields             Kind = "invalid_request_put_fields"
	InvalidRequestPutPaths              Kind = "invalid_request_put_paths"
	InvalidRequestTimeout               Kind = "invalid_request_timeout"
	InvalidRequestOperation             Kind = "invalid_request_operation"
	StreamVaultUnlockFailed             Kind = "stream_vault_unlock_failed"
	StreamDecodeFailed                  Kind = "stream_decode_failed"
	StreamReadFailed                    Kind = "stream_read_failed"
	RegisterArgumentsInvalid            Kind = "register_arguments_invalid"
	LoginArgumentsInvalid               Kind = "login_arguments_invalid"
	PushArgumentsInvalid                Kind = "push_arguments_invalid"
	PushOnlyRequired                    Kind = "push_only_required"
	PushScopeConflict                   Kind = "push_scope_conflict"
	SyncPushFailed                      Kind = "sync_push_failed"
	SyncUnconfigured                    Kind = "sync_unconfigured"
	SyncConfigurationFailed             Kind = "sync_configuration_failed"
	SyncPullReplaceFailed               Kind = "sync_pull_replace_failed"
	TransferArgumentsInvalid            Kind = "transfer_arguments_invalid"
	MapNoTargets                        Kind = "map_no_targets"
	RedirectActionRequired              Kind = "redirect_action_required"
	RedirectSetArgumentsInvalid         Kind = "redirect_set_arguments_invalid"
	RedirectRemoveArgumentsInvalid      Kind = "redirect_remove_arguments_invalid"
	RedirectActionInvalid               Kind = "redirect_action_invalid"
	ImportArgumentsInvalid              Kind = "import_arguments_invalid"
	ImportCountMismatch                 Kind = "import_count_mismatch"
	MergeReportFailed                   Kind = "merge_report_failed"
	RunAliasNotFound                    Kind = "run_alias_not_found"
	MapAliasNotFound                    Kind = "map_alias_not_found"
	DoctorAliasNotFound                 Kind = "doctor_alias_not_found"
	SessionAcquisitionFailed            Kind = "session_acquisition_failed"
	SSHStdinFailed                      Kind = "ssh_stdin_failed"
	InvalidRunArguments                 Kind = "invalid_run_arguments"
	HostKeyArgumentsInvalid             Kind = "host_key_arguments_invalid"
	HostKeyVaultFailed                  Kind = "host_key_vault_failed"
	HostKeyOperationFailed              Kind = "host_key_operation_failed"
	HostKeyScanDirectFailed             Kind = "host_key_scan_direct_failed"
	HostKeyScanFailed                   Kind = "host_key_scan_failed"
	KnownHostsPermissionsFailed         Kind = "known_hosts_permissions_failed"
	KnownHostsMalformed                 Kind = "known_hosts_malformed"
	KnownHostsInspectionFailed          Kind = "known_hosts_inspection_failed"
	SSHDirectoryPermissionsFailed       Kind = "ssh_directory_permissions_failed"
	KnownHostsUnchanged                 Kind = "known_hosts_unchanged"
	KnownHostsUpdateFailed              Kind = "known_hosts_update_failed"
	HostKeyFingerprintMismatch          Kind = "host_key_fingerprint_mismatch"
	HostKeyFingerprintChanged           Kind = "host_key_fingerprint_changed"
	TransferLocalFileStat               Kind = "transfer_local_file_stat"
	TransferRegularFileRequired         Kind = "transfer_regular_file_required"
	TransferIntegritySourceRead         Kind = "transfer_integrity_source_read"
	TransferSeekableSourceRequired      Kind = "transfer_seekable_source_required"
	TransferSessionOpenFailed           Kind = "transfer_session_open_failed"
	TransferStdinOpenFailed             Kind = "transfer_stdin_open_failed"
	TransferStartFailed                 Kind = "transfer_start_failed"
	TransferTimedOut                    Kind = "transfer_timed_out"
	TransferRemoteWriteFailed           Kind = "transfer_remote_write_failed"
	TransferRemoteCloseFailed           Kind = "transfer_remote_close_failed"
	TransferIntegrityMismatch           Kind = "transfer_integrity_mismatch"
	TransferRemotePermissionsFailed     Kind = "transfer_remote_permissions_failed"
	TransferReceiptInvalid              Kind = "transfer_receipt_invalid"
	ResumeVersionUnsupported            Kind = "resume_version_unsupported"
	ResumeRegularFileRequired           Kind = "resume_regular_file_required"
	ResumeSourceReadFailed              Kind = "resume_source_read_failed"
	ResumeSourceChanged                 Kind = "resume_source_changed"
	ResumePartialMismatch               Kind = "resume_partial_mismatch"
	ResumeSourceSeekFailed              Kind = "resume_source_seek_failed"
	ResumeStdinOpenFailed               Kind = "resume_stdin_open_failed"
	ResumeStartFailed                   Kind = "resume_start_failed"
	ResumeTimedOut                      Kind = "resume_timed_out"
	ResumeRemoteWriteFailed             Kind = "resume_remote_write_failed"
	ResumeRetryFailed                   Kind = "resume_retry_failed"
	ResumeVerificationToolMissing       Kind = "resume_verification_tool_missing"
	ResumeStateChanged                  Kind = "resume_state_changed"
	ResumeIntegrityMismatch             Kind = "resume_integrity_mismatch"
	ResumePublishFailed                 Kind = "resume_publish_failed"
	ResumeReceiptInvalid                Kind = "resume_receipt_invalid"
	ResumeProbeSessionFailed            Kind = "resume_probe_session_failed"
	ResumeStateIncompatible             Kind = "resume_state_incompatible"
	ResumeProbeFailed                   Kind = "resume_probe_failed"
	ResumeProbeResponseInvalid          Kind = "resume_probe_response_invalid"
	TransferDirectorySourceUnsupported  Kind = "transfer_directory_source_unsupported"
	TransferDirectoryOptionsUnsupported Kind = "transfer_directory_options_unsupported"
	TransferDownloadRemoteRead          Kind = "transfer_download_remote_read"
	TransferDownloadLocalWrite          Kind = "transfer_download_local_write"
	TransferDownloadPublish             Kind = "transfer_download_publish"
	TransferDownloadRestoreFailed       Kind = "transfer_download_restore_failed"
)

const ExitConnectionFailed = 255

const interpreterNotFoundPrefix = "ssm: error=interpreter_not_found interpreter="

// Stable public failure codes live here even when compatibility aliases remain
// in older internal packages during migration.
const (
	CodeAliasNotFound  = "alias_not_found"
	CodeInvalidArgs    = "invalid_arguments"
	CodeInvalidRequest = "invalid_request"
	CodeDialTimeout    = "dial_timeout"
	CodeDialRefused    = "dial_refused"
	CodeDialNetwork    = "dial_network"
	CodeHostKey        = "host_key_mismatch"
	CodeHostKeyUnknown = "host_key_unknown"
	CodeAuth           = "auth_failed"
	CodeNoAuth         = "no_auth_configured"
	CodeSession        = "session_failed"
	CodeRemote         = "remote_failed"
	CodeRemoteWrite    = "remote_write_failed"
	CodeInterpreter    = "interpreter_not_found"
	CodeScriptSyntax   = "script_syntax_error"
	CodeRemoteScript   = "remote_script_failed"
	CodeTransfer       = "transfer_failed"
	CodeSyncPull       = "sync_pull_failed"
	CodeSyncPush       = "sync_push_failed"
	CodeInternal       = "internal"
)

type humanStyle uint8

const (
	humanStandard humanStyle = iota
	humanPlain
	humanAliasNotFound
	humanScript
	humanHostVerification
	humanHostPush
	humanMapNoTargets
	humanRunArguments
	humanHostKeyOperation
	humanPanic
	humanLegacyUsage
	humanLegacyNotFound
	humanLegacyUnknownCommand
	humanLegacyMessage
	humanRaw
	humanDoctorOption
	humanImportArguments
)

type rendererPolicy uint8

const (
	rendererRequested rendererPolicy = iota
	rendererHumanOnly
)

type failurePolicy struct {
	Code            string
	Stage           string
	Hint            string
	HumanHint       string
	Exit            int
	Process         int
	Human           humanStyle
	Renderer        rendererPolicy
	HintFromCause   bool
	SuppressMessage bool
}

var failurePolicies = map[Kind]failurePolicy{
	InternalFailure: {
		Code: CodeInternal, Exit: 1,
	},
	UnknownSSHCTLCommand: {
		Code: "unknown_command", Hint: "use sshctl run <alias> --argv <command> or sshctl --help", Exit: 2,
	},
	UnknownSSMCommand: {
		Code: "unknown_command", Hint: "use ssm --help for available commands", Exit: 2,
	},
	InvalidRequestDocument: {
		Code: CodeInvalidRequest, Hint: "use schema version 1 and exactly one typed operation", Exit: 2,
	},
	MasterPassFileRequiredCreate: {
		Code: "master_pass_file_required", Hint: "provide --master-pass-file or SSM_MASTER_PASS_FILE to create it non-interactively", Exit: 2,
	},
	AliasNotFound: {
		Code: CodeAliasNotFound, Hint: "use sshctl host list --json and retry with an exact alias", Exit: ExitConnectionFailed, Human: humanAliasNotFound,
	},
	SyncConflict: {
		Code: "sync_conflict", Stage: "sync_compare",
		Hint: "local and remote blobs were preserved; inspect sshctl --offline --json doctor, then explicitly pull or push after review", Exit: 1,
	},
	EmptyLedgerSyncConflict: {
		Code: "sync_conflict", Stage: "sync_compare",
		Hint: "review sshctl --offline --json doctor and preserve the local vault and sync-conflict.json; run sshctl --json pull to adopt remote, then reapply retained local inventory with ssm --offline --json import-json <reviewed-file> --merge or --replace --yes and publish only its transaction", Exit: 1,
	},
	SyncPullFailed: {
		Code: CodeSyncPull, Stage: "sync_pull", Hint: "fix sync connectivity or retry explicitly with --offline", Exit: 1,
	},
	StreamSyncPullFailed: {
		Code: CodeSyncPull, Stage: "sync_pull", Hint: "fix sync connectivity or restart explicitly with --offline", Exit: 1,
	},
	TransferLocalRead: {
		Code: "local_read_failed", Stage: "local_read", Hint: "verify the local path and read permissions", Exit: 1,
	},
	DialTimeout: {
		Code: CodeDialTimeout, Stage: "dial",
		Hint: "network/host unreachable or filtered; verify host online/firewall/IPv6. Not an ssm quote bug.", Exit: ExitConnectionFailed,
	},
	DialRefused: {
		Code: CodeDialRefused, Stage: "dial", Hint: "sshd not listening or wrong port; not an ssm quote bug", Exit: ExitConnectionFailed,
	},
	DialNetwork: {
		Code: CodeDialNetwork, Stage: "dial", Hint: "routing/DNS/firewall issue; not an ssm quote bug", Exit: ExitConnectionFailed,
	},
	HostKeyUnknown: {
		Code: CodeHostKeyUnknown, Stage: "dial",
		Hint: "run sshctl host-key inspect <alias> --json, verify the observed fingerprint through a trusted channel, then use fingerprint-bound host-key accept",
		Exit: ExitConnectionFailed,
	},
	HostKeyMismatch: {
		Code: CodeHostKey, Stage: "dial",
		Hint: "do not remove or rescan automatically; run sshctl host-key inspect <alias> --json, verify out-of-band, then accept the exact observed fingerprint",
		Exit: ExitConnectionFailed,
	},
	AuthenticationFailed: {
		Code: CodeAuth, Stage: "dial", Hint: "check password/key in vault; not a quote or SSM client bug", Exit: ExitConnectionFailed,
	},
	NoAuthenticationConfigured: {
		Code: CodeNoAuth, Stage: "dial",
		Hint: "update host auth with sshctl host update <alias> --key-file <path> or --password-file <path>", Exit: ExitConnectionFailed,
	},
	SessionFailed: {
		Code: CodeSession, Stage: "session", Hint: "SSH connected but session failed; remote sshd or resources may be unhealthy", Exit: ExitConnectionFailed,
	},
	RemoteCommandFailed: {
		Code: CodeRemote, Stage: "remote_execution", Hint: "inspect stdout/stderr; SSH transport succeeded", Exit: 1,
	},
	InterpreterNotFound: {
		Code: CodeInterpreter, Stage: "interpreter", Exit: 127, Human: humanScript,
	},
	RemoteScriptFailed: {
		Code: CodeRemoteScript, Stage: "remote_execution",
		Hint: "the script reached the remote interpreter but exited non-zero; inspect stderr", Exit: 1, Human: humanScript,
	},
	ScriptSyntaxFailed: {
		Code: CodeScriptSyntax, Stage: "syntax_preflight",
		Hint: "the remote interpreter rejected the script syntax; no script body was executed and raw parser output was suppressed", Exit: 1,
	},
	HostInvalidArguments: {
		Code: CodeInvalidArgs, Stage: "validate", Hint: "review sshctl host --help and retry with explicit flags", Exit: 2,
	},
	HostApplyInvalidArguments: {
		Code: CodeInvalidArgs, Stage: "validate", Hint: "review sshctl host --help and retry with explicit flags", Exit: 2, Process: 1,
	},
	HostAliasNotFound: {
		Code: CodeAliasNotFound, Stage: "lookup", Hint: "use sshctl --json host list and retry with an exact alias",
		Exit: ExitConnectionFailed, Process: 1,
	},
	HostVerificationFailed: {
		Code: "verification_failed", Stage: "verify",
		Hint: "inspect verification.error and fix the candidate before retrying", Exit: ExitConnectionFailed, Human: humanHostVerification,
	},
	HostPushFailed: {
		Code: CodeSyncPush, Stage: "sync_push", Hint: "local changes remain pending; fix sync and retry push",
		HumanHint: "local change remains pending; inspect sshctl --json status and retry with sshctl --json push --only <transaction-id>", Exit: 1, Human: humanHostPush,
	},
	HostSyncPullFailed: {
		Code: CodeSyncPull, Stage: "sync_pull", Hint: "fix sync connectivity or retry explicitly with --offline", Exit: 1,
	},
	HostVaultFailed: {
		Code: "vault_error", Stage: "vault", Hint: "verify the encrypted vault and master pass file", Exit: 1,
	},
	HostAuthenticationRequired: {
		Code: "auth_required", Stage: "validate", Hint: "provide --key, --key-file, or --password-file", Exit: 2,
	},
	HostApplyAuthenticationRequired: {
		Code: "auth_required", Stage: "validate", Hint: "provide --key, --key-file, or --password-file", Exit: 2, Process: 1,
	},
	HostConfirmationRequired: {
		Code: "confirmation_required", Stage: "validate", Hint: "review the alias and pass --yes explicitly", Exit: 2,
	},
	HostAlreadyExists: {
		Code: "host_exists", Stage: "apply", Hint: "review the error and retry safely", Exit: 1,
	},
	HostInvalidAlias: {
		Code: "invalid_alias", Stage: "apply", Hint: "review the error and retry safely", Exit: 1,
	},
	HostSavedKeyNotFound: {
		Code: "key_not_found", Stage: "apply", Hint: "review the error and retry safely", Exit: 1,
	},
	HostInvalidAddress: {
		Code: "invalid_host", Stage: "apply", Hint: "review the error and retry safely", Exit: 1,
	},
	HostInvalidUser: {
		Code: "invalid_user", Stage: "apply", Hint: "review the error and retry safely", Exit: 1,
	},
	HostInvalidGroup: {
		Code: "invalid_group", Stage: "apply", Hint: "review the error and retry safely", Exit: 1,
	},
	HostPasswordFileFailed: {
		Code: "password_file_error", Stage: "apply", Hint: "review the error and retry safely", Exit: 1,
	},
	HostKeyFileFailed: {
		Code: "key_file_error", Stage: "apply", Hint: "review the error and retry safely", Exit: 1,
	},
	HostInvalidKey: {
		Code: "invalid_key", Stage: "apply", Hint: "review the error and retry safely", Exit: 1,
	},
	HostKeyConflict: {
		Code: "key_conflict", Stage: "apply", Hint: "review the error and retry safely", Exit: 1,
	},
	HostTransactionFailed: {
		Code: "transaction_error", Stage: "apply", Hint: "review the error and retry safely", Exit: 1,
	},
	HostInternalFailure: {
		Code: CodeInternal, Stage: "apply", Hint: "review the error and retry safely", Exit: 1,
	},
	PanicFailure: {
		Code: CodeInternal, Hint: "retry with SSM_TRACE=1 outside machine mode and report the failure", Exit: 1, Human: humanPanic,
	},
	GenericFailure: {
		Code: CodeInternal, Exit: 1, Human: humanPlain,
	},
	UpdateFailed: {
		Code: "update_failed", Stage: "update", Hint: "the prior executable was preserved; retry after resolving the reported update failure", Exit: 1, Human: humanPlain,
	},
	UpdateMigrationFailed: {
		Code: "migration_preflight_failed", Stage: "migration_preflight", Hint: "the prior executable was preserved; resolve the reported checks and rerun the migration review", Exit: 1, Human: humanPlain,
	},
	MissingCommand: {
		Code: "missing_command", Hint: "use ssm --help or sshctl --help", Exit: 2,
	},
	InvalidGlobalArguments: {
		Code: CodeInvalidArgs, Hint: "run sshctl --help for supported global options", Exit: 2,
	},
	SSHCTLCommandRequired: {
		Code: CodeInvalidArgs, Hint: "run sshctl --help for available commands", Exit: 2,
	},
	InvalidSSHCTLArguments: {
		Code: CodeInvalidArgs, Hint: "run sshctl --help for usage", Exit: 2,
	},
	RunAliasRequired: {
		Code: "missing_alias", Hint: "use sshctl --json run <exact-alias> --argv <command> [args...]", Exit: 2,
	},
	PlanAliasRequired: {
		Code: "missing_alias", Hint: "use sshctl --json plan <exact-alias> --argv <command> [args...]", Exit: 2,
	},
	CheckAliasRequired: {
		Code: "missing_alias", Hint: "use sshctl --json check <exact-alias>", Exit: 2,
	},
	UnsupportedInteractiveShell: {
		Code: "unsupported_command", Hint: "use sshctl run with --argv or a script source", Exit: 2,
	},
	InvalidStreamArguments: {
		Code: CodeInvalidArgs, Hint: "use sshctl run <alias> --stream [--refresh 30s]", Exit: 2,
	},
	MasterPassFileReadFailed: {
		Code: "master_pass_file_error", Hint: "use --master-pass-file or SSM_MASTER_PASS_FILE with a readable private file", Exit: 1,
	},
	MasterPassFileEmpty: {
		Code: "master_pass_file_error", Hint: "write the vault passphrase to the configured file", Exit: 1,
	},
	VaultCreateFailed: {
		Code: "vault_error", Hint: "verify configuration directory permissions", Exit: 1,
	},
	VaultUnlockFailed: {
		Code: "vault_unlock_failed", Hint: "verify the master pass file belongs to this encrypted vault", Exit: 1,
	},
	MasterPassFileRequiredExisting: {
		Code: "master_pass_file_required",
		Hint: "provide --master-pass-file or SSM_MASTER_PASS_FILE; credentials are never accepted inline", Exit: 2,
	},
	InvalidRequestRun: {
		Code: CodeInvalidRequest, Hint: "use exactly one of argv, shell_command, or script_file", Exit: 2,
	},
	InvalidRequestAlias: {
		Code: CodeInvalidRequest, Hint: "provide one exact inventory alias", Exit: 2,
	},
	InvalidRequestCheck: {
		Code: CodeInvalidRequest, Hint: "check accepts only version, op, and alias", Exit: 2,
	},
	InvalidRequestDoctor: {
		Code: CodeInvalidRequest, Hint: "use alias and optional deep only", Exit: 2,
	},
	InvalidRequestDoctorAlias: {
		Code: CodeInvalidRequest, Hint: "doctor alias must be an exact inventory name", Exit: 2,
	},
	InvalidRequestHost: {
		Code: CodeInvalidRequest, Hint: "host operations accept structured host fields and file-based credentials only", Exit: 2,
	},
	InvalidRequestPutFields: {
		Code: CodeInvalidRequest, Hint: "use file paths; never place file contents or credentials in the request", Exit: 2,
	},
	InvalidRequestPutPaths: {
		Code: CodeInvalidRequest, Hint: "use resume:\"v1\" explicitly for regular-file retry", Exit: 2,
	},
	InvalidRequestTimeout: {
		Code: CodeInvalidRequest, Hint: "timeout must be a positive duration", Exit: 2,
	},
	InvalidRequestOperation: {
		Code: CodeInvalidRequest,
		Hint: "use run, plan, check, doctor, put, get, or host.list/search/show/add/update/upsert/remove", Exit: 2,
	},
	StreamVaultUnlockFailed: {
		Code: "vault_unlock_failed", Stage: "vault",
		Hint: "verify the master pass file belongs to this encrypted vault", Exit: 1,
	},
	StreamDecodeFailed: {
		Code: CodeInvalidRequest, Stage: "decode", Hint: "send one non-empty JSON string array per line", Exit: 2,
	},
	StreamReadFailed: {
		Code: CodeInvalidRequest, Stage: "read", Hint: "send smaller argv arrays", Exit: 2,
	},
	RegisterArgumentsInvalid: {
		Code: CodeInvalidArgs, Hint: "use --server, --email, and --password-file", Exit: 2,
	},
	LoginArgumentsInvalid: {
		Code: CodeInvalidArgs, Hint: "use --server, --email, and --password-file", Exit: 2,
	},
	PushArgumentsInvalid: {
		Code: CodeInvalidArgs, Hint: "inspect pending_mutations with sshctl --json status", Exit: 2,
	},
	PushOnlyRequired: {
		Code: CodeInvalidArgs, Hint: "copy an exact id from sshctl --json status", Exit: 2,
	},
	PushScopeConflict: {
		Code: CodeInvalidArgs, Hint: "choose one explicit push scope", Exit: 2,
	},
	SyncPushFailed: {
		Code: CodeSyncPush, Hint: "local vault remains pending; fix sync and retry push", Exit: 1,
	},
	SyncUnconfigured: {
		Code: "sync_config_error", Hint: "configure sync or use local inventory", Exit: 1,
	},
	SyncConfigurationFailed: {
		Code: "sync_config_error", Stage: "sync_config",
		Hint: "repair sync configuration or retry explicitly with --offline", Exit: 1,
	},
	SyncPullReplaceFailed: {
		Code: CodeSyncPull, Hint: "local inventory was not replaced", Exit: 1,
	},
	TransferArgumentsInvalid: {
		Code: CodeInvalidArgs, Stage: "validate",
		Hint: "use sshctl put <alias> <local> <remote> [--resume=v1] [--sha256] [--timeout <duration>] [--json]", Exit: 2,
	},
	MapNoTargets: {
		Code: "no_targets", Hint: "refresh sshctl host list and use exact aliases or reviewed patterns", Exit: 2, Human: humanMapNoTargets,
	},
	RedirectActionRequired: {
		Code: CodeInvalidArgs, Hint: "use redirect list, set <old> <new>, or rm <old>", Exit: 2,
	},
	RedirectSetArgumentsInvalid: {
		Code: CodeInvalidArgs, Hint: "use redirect set <old-alias> <target-alias>", Exit: 2,
	},
	RedirectRemoveArgumentsInvalid: {
		Code: CodeInvalidArgs, Hint: "use redirect rm <old-alias>", Exit: 2,
	},
	RedirectActionInvalid: {
		Code: CodeInvalidArgs, Hint: "use redirect list, set, or rm", Exit: 2,
	},
	ImportArgumentsInvalid: {
		Code: CodeInvalidArgs, Hint: "use exactly one of --merge or --replace --yes", Exit: 2, Human: humanImportArguments,
	},
	ImportCountMismatch: {
		Code: "import_count_mismatch", Hint: "review the import source and expected count before retrying", Exit: 1,
	},
	MergeReportFailed: {
		Code: "merge_report_error", Hint: "vault was not changed; verify config directory permissions", Exit: 1,
	},
	RunAliasNotFound: {
		Code: CodeAliasNotFound, Stage: "lookup",
		Hint: "use sshctl host list --json and retry with an exact alias", Exit: ExitConnectionFailed,
	},
	MapAliasNotFound: {
		Code: CodeAliasNotFound, Stage: "lookup",
		Hint: "use sshctl list --json; alias may have been renamed after migration", Exit: ExitConnectionFailed,
	},
	DoctorAliasNotFound: {
		Code: CodeAliasNotFound, Stage: "lookup",
		Hint: "use sshctl --json host list and retry with an exact alias", Exit: ExitConnectionFailed,
	},
	SessionAcquisitionFailed: {
		Code: CodeSession, Stage: "session", Exit: ExitConnectionFailed,
	},
	SSHStdinFailed: {
		Code: CodeInternal, Stage: "session", Hint: "retry the operation; report the failure if it persists", Exit: 1,
	},
	InvalidRunArguments: {
		Code: CodeInvalidArgs, Exit: 2, Human: humanRunArguments, HintFromCause: true, SuppressMessage: true,
	},
	HostKeyArgumentsInvalid: {
		Code: CodeInvalidArgs,
		Hint: "use host-key inspect <alias> or host-key accept <alias> --fingerprint SHA256:... --yes", Exit: 2,
	},
	HostKeyVaultFailed: {
		Code: "vault_error", Hint: "unlock the vault and retry", Exit: 1,
	},
	HostKeyOperationFailed: {
		Code: "host_key_operation_failed", Stage: "host_key", Hint: "inspect the endpoint and retry",
		Exit: 1, Human: humanHostKeyOperation,
	},
	HostKeyScanDirectFailed: {
		Code: "host_key_scan_failed", Stage: "host_key",
		Hint: "verify the endpoint is a direct SSH service rather than an HTTP proxy", Exit: 1, Human: humanHostKeyOperation,
	},
	HostKeyScanFailed: {
		Code: "host_key_scan_failed", Stage: "host_key", Hint: "verify the SSH endpoint and retry",
		Exit: 1, Human: humanHostKeyOperation,
	},
	KnownHostsPermissionsFailed: {
		Code: "known_hosts_error", Stage: "host_key", Hint: "fix known_hosts permissions and retry",
		Exit: 1, Human: humanHostKeyOperation,
	},
	KnownHostsMalformed: {
		Code: "known_hosts_error", Stage: "host_key", Hint: "repair malformed known_hosts before accepting a key",
		Exit: 1, Human: humanHostKeyOperation,
	},
	KnownHostsInspectionFailed: {
		Code: "known_hosts_error", Stage: "host_key", Hint: "inspect known_hosts and retry",
		Exit: 1, Human: humanHostKeyOperation,
	},
	SSHDirectoryPermissionsFailed: {
		Code: "known_hosts_error", Stage: "host_key", Hint: "fix ~/.ssh permissions and retry",
		Exit: 1, Human: humanHostKeyOperation,
	},
	KnownHostsUnchanged: {
		Code: "known_hosts_error", Stage: "host_key", Hint: "known_hosts was not changed",
		Exit: 1, Human: humanHostKeyOperation,
	},
	KnownHostsUpdateFailed: {
		Code: "known_hosts_update_failed", Stage: "host_key",
		Hint: "install OpenSSH ssh-keygen or remove the exact host:port entry manually", Exit: 1, Human: humanHostKeyOperation,
	},
	HostKeyFingerprintMismatch: {
		Code: "fingerprint_mismatch", Stage: "host_key",
		Hint: "compare the fingerprint through a trusted channel; do not accept an unexpected key", Exit: 1, Human: humanHostKeyOperation,
	},
	HostKeyFingerprintChanged: {
		Code: "fingerprint_changed", Stage: "host_key",
		Hint: "known_hosts was not changed; investigate endpoint instability or a possible interception",
		Exit: 1, Human: humanHostKeyOperation,
	},
	TransferLocalFileStat: {
		Code: "local_read_failed", Stage: "local_read", Hint: "verify the local file is readable", Exit: 1,
	},
	TransferRegularFileRequired: {
		Code: "local_read_failed", Stage: "local_read", Hint: "put integrity mode supports regular files", Exit: 1,
	},
	TransferIntegritySourceRead: {
		Code: "local_read_failed", Stage: "local_read", Hint: "read the local file successfully before retrying", Exit: 1,
	},
	TransferSeekableSourceRequired: {
		Code: "local_read_failed", Stage: "local_read", Hint: "use a seekable regular source file", Exit: 1,
	},
	TransferSessionOpenFailed: {
		Code: "session_failed", Stage: "dial", Hint: "retry after checking SSH session limits", Exit: 1,
	},
	TransferStdinOpenFailed: {
		Code: "remote_write_failed", Stage: "remote_write", Hint: "retry the upload; the final destination was not replaced", Exit: 1,
	},
	TransferStartFailed: {
		Code: "remote_write_failed", Stage: "remote_write", Hint: "remote temporary file was not published", Exit: 1,
	},
	TransferTimedOut: {
		Code: "transfer_timeout", Stage: "timeout",
		Hint: "retry; the remote temporary file is cleaned and the final path is unchanged", Exit: 1,
	},
	TransferRemoteWriteFailed: {
		Code: "remote_write_failed", Stage: "remote_write",
		Hint: "retry; the remote temporary file is cleaned and the final path is unchanged", Exit: 1,
	},
	TransferRemoteCloseFailed: {
		Code: "remote_write_failed", Stage: "remote_write", Hint: "retry; the final path was not replaced", Exit: 1,
	},
	TransferIntegrityMismatch: {
		Code: "integrity_failed", Stage: "integrity",
		Hint: "source and remote temporary file differ; nothing was published", Exit: 1,
	},
	TransferRemotePermissionsFailed: {
		Code: "remote_write_failed", Stage: "remote_write",
		Hint: "check remote path permissions and available space; the final path was not replaced", Exit: 1,
	},
	TransferReceiptInvalid: {
		Code: "integrity_failed", Stage: "integrity",
		Hint: "remote receipt did not match the local file; investigate the endpoint", Exit: 1,
	},
	ResumeVersionUnsupported: {
		Code: "unsupported_resume_version", Stage: "validate", Hint: "use --resume=v1", Exit: 1,
	},
	ResumeRegularFileRequired: {
		Code: "local_read_failed", Stage: "local_read", Hint: "resume v1 supports regular files only", Exit: 1,
	},
	ResumeSourceReadFailed: {
		Code: "local_read_failed", Stage: "local_read", Hint: "read the complete source before retrying", Exit: 1,
	},
	ResumeSourceChanged: {
		Code: "local_read_failed", Stage: "local_read", Hint: "source changed or could not be re-read", Exit: 1,
	},
	ResumePartialMismatch: {
		Code: "partial_state_mismatch", Stage: "resume_validate",
		Hint: "remote partial prefix does not match the local source; remove stale state only after review or retry with non-resume put", Exit: 1,
	},
	ResumeSourceSeekFailed: {
		Code: "local_read_failed", Stage: "local_read", Hint: "source must remain seekable and unchanged", Exit: 1,
	},
	ResumeStdinOpenFailed: {
		Code: "remote_write_failed", Stage: "remote_write",
		Hint: "retry resume; existing verified prefix remains available", Exit: 1,
	},
	ResumeStartFailed: {
		Code: "remote_write_failed", Stage: "remote_write", Hint: "retry resume; final destination was not replaced", Exit: 1,
	},
	ResumeTimedOut: {
		Code: "transfer_timeout", Stage: "timeout",
		Hint: "retry with --resume=v1 to validate and reuse the remote prefix", Exit: 1,
	},
	ResumeRemoteWriteFailed: {
		Code: "remote_write_failed", Stage: "remote_write",
		Hint: "retry with --resume=v1; the destination was not replaced", Exit: 1,
	},
	ResumeRetryFailed: {
		Code: "remote_write_failed", Stage: "remote_write", Hint: "retry with --resume=v1", Exit: 1,
	},
	ResumeVerificationToolMissing: {
		Code: "verification_tool_missing", Stage: "capability",
		Hint: "install sha256sum on the remote host or use non-resume put", Exit: 1,
	},
	ResumeStateChanged: {
		Code: "partial_state_changed", Stage: "resume_validate",
		Hint: "remote partial changed during retry; do not append until investigated", Exit: 1,
	},
	ResumeIntegrityMismatch: {
		Code: "integrity_failed", Stage: "integrity",
		Hint: "completed partial failed SHA-256 verification and was not published", Exit: 1,
	},
	ResumePublishFailed: {
		Code: "publish_failed", Stage: "publish",
		Hint: "verified partial remains; fix destination permissions and retry resume", Exit: 1,
	},
	ResumeReceiptInvalid: {
		Code: "integrity_failed", Stage: "integrity", Hint: "remote completion receipt is invalid", Exit: 1,
	},
	ResumeProbeSessionFailed: {
		Code: "session_failed", Stage: "resume_probe", Hint: "retry after checking SSH session limits", Exit: 1,
	},
	ResumeStateIncompatible: {
		Code: "partial_state_incompatible", Stage: "resume_validate",
		Hint: "remote partial metadata is missing or incompatible; review and remove only the deterministic v1 partial state", Exit: 1,
	},
	ResumeProbeFailed: {
		Code: "resume_probe_failed", Stage: "resume_probe",
		Hint: "check remote path permissions and resume capability", Exit: 1,
	},
	ResumeProbeResponseInvalid: {
		Code: "resume_probe_failed", Stage: "resume_probe", Hint: "remote resume response was invalid", Exit: 1,
	},
	TransferDirectorySourceUnsupported: {
		Code: "local_read_failed", Stage: "local_read", Hint: "use a regular file or directory", Exit: 1,
	},
	TransferDirectoryOptionsUnsupported: {
		Code: "unsupported_transfer_option", Stage: "validate",
		Hint: "SHA-256, timeout, and resume v1 options support regular-file put only", Exit: 1,
	},
	TransferDownloadRemoteRead: {
		Code: "remote_read_failed", Stage: "remote_read",
		Hint: "check the remote path and read permissions; the final local path was not replaced", Exit: 1,
	},
	TransferDownloadLocalWrite: {
		Code: "local_write_failed", Stage: "local_write",
		Hint: "check local path permissions and available space; the final local path was not replaced", Exit: 1,
	},
	TransferDownloadPublish: {
		Code: "publish_failed", Stage: "publish",
		Hint: "check local destination permissions; the previous final path was preserved", Exit: 1,
	},
	TransferDownloadRestoreFailed: {
		Code: "publish_failed", Stage: "publish",
		Hint: "automatic restore failed; recover the prior directory from the retained backup path reported in the error", Exit: 1,
	},
}

// Details carries contextual, non-policy inputs used to construct a Failure.
type Details struct {
	Message           string
	Cause             error
	Alias             string
	Address           string
	Candidates        []string
	Exit              int
	Script            string
	Interpreter       string
	Line              string
	VerificationError string
	Tool              string
	Version           string
	Platform          string
	Stack             string
}

// Failure is the canonical public failure document. The field order preserves
// the existing generic JSON document and NDJSON byte layout.
type Failure struct {
	OK         bool     `json:"ok"`
	Error      string   `json:"error"`
	Message    string   `json:"message"`
	Hint       string   `json:"hint,omitempty"`
	Stage      string   `json:"stage,omitempty"`
	Alias      string   `json:"alias,omitempty"`
	Exit       int      `json:"exit"`
	Candidates []string `json:"candidates,omitempty"`

	Address           string `json:"-"`
	Script            string `json:"-"`
	VerificationError string `json:"-"`
	HumanHint         string `json:"-"`
	Tool              string `json:"-"`
	Version           string `json:"-"`
	Platform          string `json:"-"`
	Stack             string `json:"-"`
	style             humanStyle
	cause             error
	processExit       int
	humanAlias        string
	renderer          rendererPolicy
	humanProjection   *Failure
}

func (f Failure) ErrorMessage() string {
	if f.Message != "" {
		return f.Message
	}
	if f.cause != nil {
		return f.cause.Error()
	}
	return f.Error
}

func (f Failure) Unwrap() error { return f.cause }

// Classify constructs one canonical, redacted failure from a semantic kind.
func Classify(kind Kind, details Details) Failure {
	policy, ok := failurePolicies[kind]
	if !ok {
		policy = failurePolicies[InternalFailure]
	}
	message := details.Message
	if message == "" && details.Cause != nil {
		message = details.Cause.Error()
	}
	if policy.SuppressMessage {
		message = ""
	}
	exit := policy.Exit
	if details.Exit != 0 {
		exit = details.Exit
	}
	processExit := policy.Process
	if processExit == 0 {
		processExit = exit
	}
	if kind == InterpreterNotFound {
		policy.Hint = fmt.Sprintf("remote shell %q is unavailable; retry with --shell sh or install it", details.Interpreter)
	}
	if kind == ScriptSyntaxFailed && details.Line != "" {
		policy.Hint += "; line=" + RedactString(details.Line)
	}
	switch details.Tool {
	case "legacy_usage":
		policy.Human = humanLegacyUsage
		policy.Renderer = rendererHumanOnly
	case "legacy_not_found":
		policy.Human = humanLegacyNotFound
		policy.Renderer = rendererHumanOnly
	case "legacy_unknown_command":
		policy.Human = humanLegacyUnknownCommand
		policy.Renderer = rendererHumanOnly
	case "legacy_message":
		policy.Human = humanLegacyMessage
		policy.Renderer = rendererHumanOnly
	case "raw_flag_error":
		policy.Human = humanRaw
		policy.Renderer = rendererHumanOnly
	case "legacy_plain":
		policy.Human = humanPlain
		policy.Renderer = rendererHumanOnly
	case "doctor_unknown_option":
		policy.Human = humanDoctorOption
		policy.Renderer = rendererHumanOnly
	}
	if policy.HintFromCause {
		policy.Hint = details.Message
		if details.Cause != nil {
			policy.Hint = details.Cause.Error()
		}
	}
	candidates := append([]string(nil), details.Candidates...)
	for i := range candidates {
		candidates[i] = RedactString(candidates[i])
	}
	return Failure{
		OK:                false,
		Error:             policy.Code,
		Message:           RedactString(message),
		Hint:              RedactString(policy.Hint),
		Stage:             policy.Stage,
		Alias:             RedactString(details.Alias),
		Exit:              exit,
		Candidates:        candidates,
		Address:           RedactString(details.Address),
		Script:            RedactString(details.Script),
		VerificationError: RedactString(details.VerificationError),
		HumanHint:         RedactString(policy.HumanHint),
		Tool:              RedactString(details.Tool),
		Version:           RedactString(details.Version),
		Platform:          RedactString(details.Platform),
		Stack:             RedactString(details.Stack),
		style:             policy.Human,
		cause:             details.Cause,
		processExit:       processExit,
		renderer:          policy.Renderer,
	}
}

// ClassifySyncFailure keeps configuration and conflict failures canonical
// across inventory command families while retaining each command's established
// refresh fallback.
func ClassifySyncFailure(err error, fallback Kind) Failure {
	kind := fallback
	switch {
	case errors.Is(err, synctransaction.ErrConfiguration):
		kind = SyncConfigurationFailed
	case errors.Is(err, synctransaction.ErrEmptyLedgerDivergence):
		kind = EmptyLedgerSyncConflict
	case errors.Is(err, synctransaction.ErrConflict):
		kind = SyncConflict
	}
	return Classify(kind, Details{Cause: err})
}

// ResultMetadata is embedded by typed execution results whose exit field has
// an established earlier position in their serialized schema.
type ResultMetadata struct {
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
	Hint    string `json:"hint,omitempty"`
	Stage   string `json:"stage,omitempty"`
}

func (f Failure) ResultMetadata() ResultMetadata {
	return ResultMetadata{Error: f.Error, Message: f.Message, Hint: f.Hint, Stage: f.Stage}
}

// Metadata is embedded by typed command failures that serialize exit together
// with the stable failure tuple.
type Metadata struct {
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
	Hint    string `json:"hint,omitempty"`
	Exit    int    `json:"exit"`
	Stage   string `json:"stage,omitempty"`
}

func (f Failure) Metadata() Metadata {
	return Metadata{Error: f.Error, Message: f.Message, Hint: f.Hint, Exit: f.Exit, Stage: f.Stage}
}

// TransferMetadata preserves the pre-BC-7 transfer failure field order and
// required empty fields.
type TransferMetadata struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
	Exit    int    `json:"exit"`
	Stage   string `json:"stage"`
}

func (f Failure) TransferMetadata() TransferMetadata {
	return TransferMetadata{Error: f.Error, Message: f.Message, Hint: f.Hint, Exit: f.Exit, Stage: f.Stage}
}

// TransferOutcome is the shared machine representation for put and get.
// Guarantee fields contain only values reported by the selected protocol.
type TransferOutcome struct {
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
	Message       string `json:"message,omitempty"`
	Hint          string `json:"hint,omitempty"`
	Exit          int    `json:"exit,omitempty"`
	Action        string `json:"action,omitempty"`
	Direction     string `json:"direction"`
	Kind          string `json:"kind"`
	Alias         string `json:"alias"`
	Local         string `json:"local,omitempty"`
	Remote        string `json:"remote,omitempty"`
	Stage         string `json:"stage"`
	BytesSent     *int64 `json:"bytes_sent,omitempty"`
	BytesReceived *int64 `json:"bytes_received,omitempty"`
	Integrity     string `json:"integrity,omitempty"`
	LocalSHA256   string `json:"local_sha256,omitempty"`
	RemoteSHA256  string `json:"remote_sha256,omitempty"`
	Atomic        *bool  `json:"atomic,omitempty"`
	Resume        string `json:"resume,omitempty"`
	BytesReused   int64  `json:"bytes_reused,omitempty"`
}

func TransferFailureOutcome(f Failure, outcome TransferOutcome) TransferOutcome {
	outcome.OK = false
	outcome.Error, outcome.Message, outcome.Hint, outcome.Exit = f.Error, f.Message, f.Hint, f.Exit
	outcome.Stage = f.Stage
	return outcome
}

// MetadataDocument preserves the established generic typed-failure field
// order for command families that do not include alias or candidates.
type MetadataDocument struct {
	OK bool `json:"ok"`
	Metadata
}

func (f Failure) MetadataDocument() MetadataDocument {
	return MetadataDocument{OK: false, Metadata: f.Metadata()}
}

// SSHContext supplies only connection identity needed for context-sensitive
// SSH classification.
type SSHContext struct {
	Alias              string
	ResolvedAlias      string
	Host               string
	Port               int
	Stage              string
	SessionAcquisition bool
}

// InterpreterNotFoundDiagnostic returns the stable marker emitted by remote
// script runners before exit 127.
func InterpreterNotFoundDiagnostic(interpreter string) string {
	return interpreterNotFoundPrefix + interpreter
}

// IsInterpreterNotFoundDiagnostic recognizes the stable remote runner marker.
func IsInterpreterNotFoundDiagnostic(stderr string) bool {
	return strings.Contains(stderr, interpreterNotFoundPrefix)
}

// RunExecutionContext supplies the execution facts needed to distinguish
// ordinary remote failures from script and interpreter failures.
type RunExecutionContext struct {
	Cause       error
	Exit        int
	Alias       string
	HasInput    bool
	Capture     bool
	Stderr      string
	Script      string
	Interpreter string
}

// ClassifyRunExecution owns exit-127 and script-input classification policy.
func ClassifyRunExecution(context RunExecutionContext) Failure {
	if !context.HasInput {
		return Classify(RemoteCommandFailed, Details{
			Message: "remote command exited non-zero",
			Cause:   context.Cause,
			Alias:   context.Alias,
			Exit:    context.Exit,
		})
	}
	if context.Exit == 127 && (!context.Capture || IsInterpreterNotFoundDiagnostic(context.Stderr)) {
		return Classify(InterpreterNotFound, Details{
			Message:     "remote script interpreter is unavailable",
			Cause:       context.Cause,
			Alias:       context.Alias,
			Exit:        context.Exit,
			Script:      context.Script,
			Interpreter: context.Interpreter,
		})
	}
	return Classify(RemoteScriptFailed, Details{
		Message: "remote script exited non-zero",
		Cause:   context.Cause,
		Alias:   context.Alias,
		Exit:    context.Exit,
		Script:  context.Script,
	})
}

// ClassifySSH maps transport, host-key, authentication, and session errors
// into the stable public failure taxonomy.
func ClassifySSH(err error, context SSHContext) Failure {
	if err == nil {
		return Failure{}
	}
	var classified *ClassifiedError
	if errors.As(err, &classified) {
		failure := classified.Failure
		if context.Stage != "" {
			failure.Stage = context.Stage
		}
		if failure.Error == CodeInternal && isDialFailure(err, context) {
			failure.Exit = ExitConnectionFailed
			failure.processExit = ExitConnectionFailed
		}
		return failure
	}

	port := context.Port
	if port == 0 {
		port = 22
	}
	address := net.JoinHostPort(context.Host, strconv.Itoa(port))
	message := err.Error()
	lower := strings.ToLower(message)
	details := Details{Cause: err, Message: message, Alias: context.Alias, Address: address}
	kind := InternalFailure

	var keyErr *knownhosts.KeyError
	switch {
	case errors.As(err, &keyErr) && len(keyErr.Want) == 0:
		kind = HostKeyUnknown
		details.Message = "remote host key is not trusted yet"
	case errors.As(err, &keyErr) || strings.Contains(lower, "host key") || strings.Contains(lower, "knownhosts"):
		kind = HostKeyMismatch
		details.Message = "remote host key does not match known_hosts (host reinstalled or MITM)"
	case strings.Contains(lower, "no authentication configured"):
		kind = NoAuthenticationConfigured
		details.Message = "connection has no password or private key configured"
	case strings.Contains(lower, "unable to authenticate"),
		strings.Contains(lower, "no supported methods remain"),
		strings.Contains(lower, "permission denied"),
		strings.Contains(lower, "authentication failed"):
		kind = AuthenticationFailed
		details.Message = "SSH authentication failed"
	default:
		var networkError net.Error
		switch {
		case errors.As(err, &networkError) && networkError.Timeout():
			kind = DialTimeout
			details.Message = fmt.Sprintf("dial tcp %s: i/o timeout", address)
		case strings.Contains(lower, "i/o timeout") || strings.Contains(lower, "timeout"):
			kind = DialTimeout
			details.Message = fmt.Sprintf("connection timed out to %s", address)
		case strings.Contains(lower, "connection refused"):
			kind = DialRefused
			details.Message = fmt.Sprintf("connection refused by %s", address)
		case strings.Contains(lower, "no route to host"),
			strings.Contains(lower, "network is unreachable"),
			strings.Contains(lower, "connect: "):
			kind = DialNetwork
			details.Message = fmt.Sprintf("network error dialing %s: %s", address, message)
		case strings.Contains(lower, "session"):
			kind = SessionFailed
		}
	}

	if kind == InternalFailure && context.SessionAcquisition {
		kind = SessionAcquisitionFailed
	}
	failure := Classify(kind, details)
	if context.Stage != "" {
		failure.Stage = context.Stage
	}
	if failure.Error == CodeInternal && isDialFailure(err, context) {
		failure.Exit = ExitConnectionFailed
		failure.processExit = ExitConnectionFailed
	}
	return failure
}

func isDialFailure(err error, context SSHContext) bool {
	if context.Stage == "dial" {
		return true
	}
	var operationError *net.OpError
	if errors.As(err, &operationError) && strings.EqualFold(operationError.Op, "dial") {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "dial") || strings.Contains(lower, "connect")
}

// ClassifyCheck projects an execution failure into the existing check
// contract, including its historical safe stderr hint prefix.
func ClassifyCheck(failure Failure, stderr string) Failure {
	if failure.Error == "" {
		failure = Classify(RemoteCommandFailed, Details{
			Message: "remote command exited non-zero",
			Exit:    failure.Exit,
		})
	}
	if stderr != "" {
		failure.Hint = RedactString(strings.TrimSpace(stderr)) + "; " + failure.Hint
	}
	return failure
}

// ClassifyHostKeyOperation applies the established host-key command context to
// either a mechanism-classified operation failure or an SSH failure.
func ClassifyHostKeyOperation(err error) Failure {
	failure, ok := FailureFromError(err)
	if !ok {
		failure = Classify(HostKeyOperationFailed, Details{Cause: err})
	}
	failure.Stage = "host_key"
	failure.Exit = 1
	failure.processExit = 1
	failure.style = humanHostKeyOperation
	return failure
}

// ClassifyTransferOperation recovers mechanism-owned transfer policy or
// applies the established remote-write fallback for unwrapped transfer errors.
func ClassifyTransferOperation(err error, context SSHContext, carried Failure) Failure {
	if err == nil {
		return Failure{}
	}
	human := ClassifySSH(err, context)
	human.Stage = ""
	if carried.Error != "" {
		// Preserve the pre-BC-7 human guidance for regular-file remote-write
		// failures. The machine transfer tuple remains the carried policy; only
		// its historical human SSH projection used this credential-safe hint.
		if carried.Error == CodeRemoteWrite && human.Error == CodeAuth {
			human.Hint = "verify user and credential file; password/private-key contents are never shown"
		}
		carried.Exit = ExitForError(err)
		carried.processExit = carried.Exit
		carried.humanProjection = &human
		return carried
	}
	failure := human
	failure.Stage = "remote_write"
	failure.Exit = ExitForError(err)
	failure.processExit = failure.Exit
	failure.humanProjection = &human
	return failure
}

// ClassifyDownload preserves the generic pre-BC-7 download failure envelope,
// which omits stage even when its SSH classification has one.
func ClassifyDownload(err error, context SSHContext) Failure {
	classifyContext := context
	classifyContext.Stage = ""
	failure := ClassifySSH(err, classifyContext)
	human := failure
	human.Stage = ""
	if carried, ok := FailureFromError(err); ok && isDownloadOutcomeFailure(carried) {
		carried.Exit = ExitForError(err)
		carried.processExit = carried.Exit
		carried.Alias = RedactString(context.Alias)
		carried.humanAlias = RedactString(context.ResolvedAlias)
		carried.humanProjection = &human
		return carried
	}
	if failure.Stage == "" {
		failure.Stage = context.Stage
	}
	failure.Exit = ExitForError(err)
	failure.processExit = failure.Exit
	failure.Alias = RedactString(context.Alias)
	failure.humanAlias = RedactString(context.ResolvedAlias)
	humanProjection := failure
	humanProjection.Stage = ""
	failure.humanProjection = &humanProjection
	return failure
}

func isDownloadOutcomeFailure(failure Failure) bool {
	switch failure.Error {
	case "remote_read_failed", "local_write_failed", "publish_failed":
		return true
	default:
		return false
	}
}

// ClassifiedError carries a canonical failure through low-level SSH
// mechanisms without reconstructing policy.
type ClassifiedError struct {
	Failure
	Code string `json:"-"`
}

func NewClassifiedError(failure Failure) *ClassifiedError {
	return &ClassifiedError{Failure: failure, Code: failure.Error}
}

// FailureFromError recovers a canonical failure carried through a mechanism.
func FailureFromError(err error) (Failure, bool) {
	if err == nil {
		return Failure{}, false
	}
	var classified *ClassifiedError
	if errors.As(err, &classified) {
		return classified.Failure, true
	}
	var carrier interface{ ContractFailure() Failure }
	if errors.As(err, &carrier) {
		return carrier.ContractFailure(), true
	}
	return Failure{}, false
}

func (e *ClassifiedError) Error() string {
	if e == nil {
		return ""
	}
	return e.ErrorMessage()
}

func (e *ClassifiedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// ProcessExit returns the process-control exit selected by classification.
func ProcessExit(failure Failure) int {
	if failure.processExit != 0 {
		return failure.processExit
	}
	return failure.Exit
}

// ResultState is the minimal typed-result projection needed for aggregate
// process-exit selection.
type ResultState struct {
	OK   bool
	Exit int
}

// ResultExit preserves the established fallback for a failed typed result
// whose serialized exit is unexpectedly zero.
func ResultExit(result ResultState) int {
	if result.OK {
		return 0
	}
	if result.Exit != 0 {
		return result.Exit
	}
	return 1
}

// AggregateResultExit returns the first failed result's process exit.
func AggregateResultExit(results []ResultState) int {
	for _, result := range results {
		if !result.OK {
			return ResultExit(result)
		}
	}
	return 0
}

// ConnectionResultExit preserves the historical command process exit for
// check and doctor failures, independent of a nested remote program's exit.
func ConnectionResultExit(ok bool) int {
	if ok {
		return 0
	}
	return ExitConnectionFailed
}

// ExitForError preserves remote exit status and otherwise selects the
// classified connection/process exit. A remote 255 is never reclassified from
// its exit value alone.
func ExitForError(err error) int {
	if err == nil {
		return 0
	}
	var exitError *gossh.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitStatus()
	}
	var classified *ClassifiedError
	if errors.As(err, &classified) {
		return ProcessExit(classified.Failure)
	}
	failure := ClassifySSH(err, SSHContext{})
	if failure.Error != CodeInternal {
		return ProcessExit(failure)
	}
	if processExit := ProcessExit(failure); processExit != 1 {
		return processExit
	}
	return 1
}
