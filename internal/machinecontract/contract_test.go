package machinecontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssm/internal/privatepath"
	"ssm/internal/synctransaction"
)

func TestMachineContractMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		kind        Kind
		details     Details
		code        string
		stage       string
		hint        string
		exit        int
		processExit int
		alias       string
		candidates  []string
	}{
		{
			name: "internal", kind: InternalFailure,
			details: Details{Message: "unexpected failure"},
			code:    "internal", exit: 1,
		},
		{
			name: "unknown sshctl command", kind: UnknownSSHCTLCommand,
			details: Details{Message: `unknown command "not-a-command"`},
			code:    "unknown_command", hint: "use sshctl run <alias> --argv <command> or sshctl --help", exit: 2,
		},
		{
			name: "unknown ssm command", kind: UnknownSSMCommand,
			details: Details{Message: `unknown command "not-a-command"`},
			code:    "unknown_command", hint: "use ssm --help for available commands", exit: 2,
		},
		{
			name: "request validation", kind: InvalidRequestDocument,
			details: Details{Message: "json: unknown field canary"},
			code:    "invalid_request", hint: "use schema version 1 and exactly one typed operation", exit: 2,
		},
		{
			name: "unlock file required", kind: MasterPassFileRequiredCreate,
			details: Details{Message: "vault does not exist"},
			code:    "master_pass_file_required", hint: "provide --master-pass-file or SSM_MASTER_PASS_FILE to create it non-interactively", exit: 2,
		},
		{
			name: "exact alias miss", kind: AliasNotFound,
			details: Details{
				Message:    `connection "prod" not found`,
				Alias:      "prod",
				Candidates: []string{"prod-one", "prod-two"},
			},
			code: "alias_not_found", hint: "use sshctl host list --json and retry with an exact alias", exit: 255,
			alias: "prod", candidates: []string{"prod-one", "prod-two"},
		},
		{
			name: "sync conflict", kind: SyncConflict,
			details: Details{Message: "remote changed"},
			code:    "sync_conflict", stage: "sync_compare",
			hint: "local and remote blobs were preserved; inspect sshctl --offline --json doctor, then explicitly pull or push after review", exit: 1,
		},
		{
			name: "sync pull", kind: SyncPullFailed,
			details: Details{Message: "pull failed"},
			code:    "sync_pull_failed", stage: "sync_pull", hint: "fix sync connectivity or retry explicitly with --offline", exit: 1,
		},
		{
			name: "transfer local read", kind: TransferLocalRead,
			details: Details{Cause: errors.New("open artifact: file does not exist"), Alias: "transfer"},
			code:    "local_read_failed", stage: "local_read", hint: "verify the local path and read permissions", exit: 1,
			alias: "transfer",
		},
		{
			name: "host key unknown", kind: HostKeyUnknown,
			details: Details{Message: "remote host key is not trusted yet", Alias: "host-key"},
			code:    "host_key_unknown", stage: "dial",
			hint: "run sshctl host-key inspect <alias> --json, verify the observed fingerprint through a trusted channel, then use fingerprint-bound host-key accept",
			exit: 255, alias: "host-key",
		},
		{
			name: "host key mismatch", kind: HostKeyMismatch,
			details: Details{Message: "host key mismatch", Alias: "host-key"},
			code:    "host_key_mismatch", stage: "dial",
			hint: "do not remove or rescan automatically; run sshctl host-key inspect <alias> --json, verify out-of-band, then accept the exact observed fingerprint",
			exit: 255, alias: "host-key",
		},
		{
			name: "dial timeout", kind: DialTimeout,
			details: Details{Message: "dial timeout", Alias: "timeout"},
			code:    "dial_timeout", stage: "dial",
			hint: "network/host unreachable or filtered; verify host online/firewall/IPv6. Not an ssm quote bug.",
			exit: 255, alias: "timeout",
		},
		{
			name: "dial refused", kind: DialRefused,
			details: Details{Message: "connection refused by 127.0.0.1:22", Alias: "refused"},
			code:    "dial_refused", stage: "dial", hint: "sshd not listening or wrong port; not an ssm quote bug",
			exit: 255, alias: "refused",
		},
		{
			name: "dial network", kind: DialNetwork,
			details: Details{Message: "network unreachable", Alias: "network"},
			code:    "dial_network", stage: "dial", hint: "routing/DNS/firewall issue; not an ssm quote bug",
			exit: 255, alias: "network",
		},
		{
			name: "authentication", kind: AuthenticationFailed,
			details: Details{Message: "SSH authentication failed", Alias: "auth"},
			code:    "auth_failed", stage: "dial", hint: "check password/key in vault; not a quote or SSM client bug",
			exit: 255, alias: "auth",
		},
		{
			name: "no authentication", kind: NoAuthenticationConfigured,
			details: Details{Message: "no authentication configured", Alias: "auth"},
			code:    "no_auth_configured", stage: "dial",
			hint: "update host auth with sshctl host update <alias> --key-file <path> or --password-file <path>",
			exit: 255, alias: "auth",
		},
		{
			name: "session", kind: SessionFailed,
			details: Details{Message: "ssh: rejected session", Alias: "session"},
			code:    "session_failed", stage: "session", hint: "SSH connected but session failed; remote sshd or resources may be unhealthy",
			exit: 255, alias: "session",
		},
		{
			name: "remote exit 255", kind: RemoteCommandFailed,
			details: Details{Message: "remote command exited non-zero", Alias: "remote-255", Exit: 255},
			code:    "remote_failed", stage: "remote_execution", hint: "inspect stdout/stderr; SSH transport succeeded",
			exit: 255, alias: "remote-255",
		},
		{
			name: "interpreter", kind: InterpreterNotFound,
			details: Details{Message: "remote script interpreter is unavailable", Alias: "script", Interpreter: "bash", Exit: 127},
			code:    "interpreter_not_found", stage: "interpreter",
			hint: "remote shell \"bash\" is unavailable; retry with --shell sh or install it", exit: 127, alias: "script",
		},
		{
			name: "remote script", kind: RemoteScriptFailed,
			details: Details{Message: "remote script exited non-zero", Alias: "script", Exit: 23},
			code:    "remote_script_failed", stage: "remote_execution",
			hint: "the script reached the remote interpreter but exited non-zero; inspect stderr", exit: 23, alias: "script",
		},
		{
			name: "script syntax", kind: ScriptSyntaxFailed,
			details: Details{Message: "remote interpreter rejected script syntax", Alias: "script", Exit: 2, Line: "9"},
			code:    "script_syntax_error", stage: "syntax_preflight",
			hint: "the remote interpreter rejected the script syntax; no script body was executed and raw parser output was suppressed; line=9",
			exit: 2, alias: "script",
		},
		{
			name: "stream refresh", kind: StreamSyncPullFailed,
			details: Details{Message: "sync endpoint failed"},
			code:    "sync_pull_failed", stage: "sync_pull", hint: "fix sync connectivity or restart explicitly with --offline", exit: 1,
		},
		{
			name: "host validation", kind: HostInvalidArguments,
			details: Details{Message: "bad host option"},
			code:    "invalid_arguments", stage: "validate", hint: "review sshctl host --help and retry with explicit flags", exit: 2,
		},
		{
			name: "host apply validation", kind: HostApplyInvalidArguments,
			details: Details{Message: "bad host value"},
			code:    "invalid_arguments", stage: "validate", hint: "review sshctl host --help and retry with explicit flags", exit: 2,
			processExit: 1,
		},
		{
			name: "host alias lookup", kind: HostAliasNotFound,
			details: Details{Message: `host "missing" not found`, Alias: "missing"},
			code:    "alias_not_found", stage: "lookup", hint: "use sshctl --json host list and retry with an exact alias", exit: 255,
			processExit: 1, alias: "missing",
		},
		{
			name: "host verification", kind: HostVerificationFailed,
			details: Details{Message: "candidate host failed SSH verification; vault was not changed", Alias: "candidate"},
			code:    "verification_failed", stage: "verify", hint: "inspect verification.error and fix the candidate before retrying", exit: 255,
			alias: "candidate",
		},
		{
			name: "host push", kind: HostPushFailed,
			details: Details{Cause: errors.New("push rejected"), Alias: "candidate"},
			code:    "sync_push_failed", stage: "sync_push", hint: "local changes remain pending; fix sync and retry push", exit: 1,
			alias: "candidate",
		},
		{
			name: "host sync pull", kind: HostSyncPullFailed,
			details: Details{Cause: errors.New("refresh rejected")},
			code:    "sync_pull_failed", stage: "sync_pull", hint: "fix sync connectivity or retry explicitly with --offline", exit: 1,
		},
		{
			name: "host vault", kind: HostVaultFailed,
			details: Details{Cause: errors.New("vault rejected")},
			code:    "vault_error", stage: "vault", hint: "verify the encrypted vault and master pass file", exit: 1,
		},
		{
			name: "host auth required", kind: HostAuthenticationRequired,
			details: Details{Message: "host requires authentication"},
			code:    "auth_required", stage: "validate", hint: "provide --key, --key-file, or --password-file", exit: 2,
		},
		{
			name: "host apply auth required", kind: HostApplyAuthenticationRequired,
			details: Details{Message: "host requires authentication"},
			code:    "auth_required", stage: "validate", hint: "provide --key, --key-file, or --password-file", exit: 2,
			processExit: 1,
		},
		{
			name: "host confirmation", kind: HostConfirmationRequired,
			details: Details{Message: "host remove requires --yes"},
			code:    "confirmation_required", stage: "validate", hint: "review the alias and pass --yes explicitly", exit: 2,
		},
		{
			name: "host already exists", kind: HostAlreadyExists,
			details: Details{Message: "host already exists"},
			code:    "host_exists", stage: "apply", hint: "review the error and retry safely", exit: 1,
		},
		{
			name: "host invalid alias", kind: HostInvalidAlias,
			details: Details{Message: "invalid alias"},
			code:    "invalid_alias", stage: "apply", hint: "review the error and retry safely", exit: 1,
		},
		{
			name: "host key missing", kind: HostSavedKeyNotFound,
			details: Details{Message: "saved key missing"},
			code:    "key_not_found", stage: "apply", hint: "review the error and retry safely", exit: 1,
		},
		{
			name: "host invalid address", kind: HostInvalidAddress,
			details: Details{Message: "invalid host"},
			code:    "invalid_host", stage: "apply", hint: "review the error and retry safely", exit: 1,
		},
		{
			name: "host invalid user", kind: HostInvalidUser,
			details: Details{Message: "invalid user"},
			code:    "invalid_user", stage: "apply", hint: "review the error and retry safely", exit: 1,
		},
		{
			name: "host invalid group", kind: HostInvalidGroup,
			details: Details{Message: "invalid group"},
			code:    "invalid_group", stage: "apply", hint: "review the error and retry safely", exit: 1,
		},
		{
			name: "host password file", kind: HostPasswordFileFailed,
			details: Details{Message: "password file rejected"},
			code:    "password_file_error", stage: "apply", hint: "review the error and retry safely", exit: 1,
		},
		{
			name: "host key file", kind: HostKeyFileFailed,
			details: Details{Message: "key file rejected"},
			code:    "key_file_error", stage: "apply", hint: "review the error and retry safely", exit: 1,
		},
		{
			name: "host invalid key", kind: HostInvalidKey,
			details: Details{Message: "invalid key"},
			code:    "invalid_key", stage: "apply", hint: "review the error and retry safely", exit: 1,
		},
		{
			name: "host key conflict", kind: HostKeyConflict,
			details: Details{Message: "key conflict"},
			code:    "key_conflict", stage: "apply", hint: "review the error and retry safely", exit: 1,
		},
		{
			name: "host transaction", kind: HostTransactionFailed,
			details: Details{Message: "transaction rejected"},
			code:    "transaction_error", stage: "apply", hint: "review the error and retry safely", exit: 1,
		},
		{
			name: "host internal", kind: HostInternalFailure,
			details: Details{Message: "host failure"},
			code:    "internal", stage: "apply", hint: "review the error and retry safely", exit: 1,
		},
		{
			name: "panic", kind: PanicFailure,
			details: Details{Message: "ssm crashed"},
			code:    "internal", hint: "retry with SSM_TRACE=1 outside machine mode and report the failure", exit: 1,
		},
		{
			name: "generic failure", kind: GenericFailure,
			details: Details{Message: "operation failed"},
			code:    "internal", exit: 1,
		},
		{
			name: "ordinary update failure", kind: UpdateFailed,
			details: Details{Message: "update failed"},
			code:    "update_failed", stage: "update",
			hint: "the prior executable was preserved; retry after resolving the reported update failure", exit: 1,
		},
		{
			name: "major migration failure", kind: UpdateMigrationFailed,
			details: Details{Message: "migration failed"},
			code:    "migration_preflight_failed", stage: "migration_preflight",
			hint: "the prior executable was preserved; resolve the reported checks and rerun the migration review", exit: 1,
		},
		{
			name: "missing command", kind: MissingCommand,
			details: Details{Message: "command required"},
			code:    "missing_command", hint: "use ssm --help or sshctl --help", exit: 2,
		},
		{
			name: "sshctl global arguments", kind: InvalidGlobalArguments,
			details: Details{Message: "bad global option"},
			code:    "invalid_arguments", hint: "run sshctl --help for supported global options", exit: 2,
		},
		{
			name: "sshctl command required", kind: SSHCTLCommandRequired,
			details: Details{Message: "sshctl command is required"},
			code:    "invalid_arguments", hint: "run sshctl --help for available commands", exit: 2,
		},
		{
			name: "sshctl usage", kind: InvalidSSHCTLArguments,
			details: Details{Message: "invalid sshctl arguments"},
			code:    "invalid_arguments", hint: "run sshctl --help for usage", exit: 2,
		},
		{
			name: "run alias required", kind: RunAliasRequired,
			details: Details{Message: "missing alias"},
			code:    "missing_alias", hint: "use sshctl --json run <exact-alias> --argv <command> [args...]", exit: 2,
		},
		{
			name: "plan alias required", kind: PlanAliasRequired,
			details: Details{Message: "missing alias"},
			code:    "missing_alias", hint: "use sshctl --json plan <exact-alias> --argv <command> [args...]", exit: 2,
		},
		{
			name: "check alias required", kind: CheckAliasRequired,
			details: Details{Message: "check requires an exact host alias"},
			code:    "missing_alias", hint: "use sshctl --json check <exact-alias>", exit: 2,
		},
		{
			name: "interactive shell removed", kind: UnsupportedInteractiveShell,
			details: Details{Message: "interactive shell support has been removed"},
			code:    "unsupported_command", hint: "use sshctl run with --argv or a script source", exit: 2,
		},
		{
			name: "stream arguments", kind: InvalidStreamArguments,
			details: Details{Message: "bad refresh"},
			code:    "invalid_arguments", hint: "use sshctl run <alias> --stream [--refresh 30s]", exit: 2,
		},
		{
			name: "master pass read", kind: MasterPassFileReadFailed,
			details: Details{Message: "master pass file: permission denied"},
			code:    "master_pass_file_error", hint: "use --master-pass-file or SSM_MASTER_PASS_FILE with a readable private file", exit: 1,
		},
		{
			name: "master pass empty", kind: MasterPassFileEmpty,
			details: Details{Message: "master pass file is empty"},
			code:    "master_pass_file_error", hint: "write the vault passphrase to the configured file", exit: 1,
		},
		{
			name: "vault create", kind: VaultCreateFailed,
			details: Details{Message: "save vault failed"},
			code:    "vault_error", hint: "verify configuration directory permissions", exit: 1,
		},
		{
			name: "vault unlock", kind: VaultUnlockFailed,
			details: Details{Message: "decrypt failed"},
			code:    "vault_unlock_failed", hint: "verify the master pass file belongs to this encrypted vault", exit: 1,
		},
		{
			name: "master pass required", kind: MasterPassFileRequiredExisting,
			details: Details{Message: "vault passphrase is required"},
			code:    "master_pass_file_required", hint: "provide --master-pass-file or SSM_MASTER_PASS_FILE; credentials are never accepted inline", exit: 2,
		},
		{
			name: "request run validation", kind: InvalidRequestRun,
			details: Details{Message: "invalid run request", Alias: "prod"},
			code:    "invalid_request", hint: "use exactly one of argv, shell_command, or script_file", exit: 2, alias: "prod",
		},
		{
			name: "request alias validation", kind: InvalidRequestAlias,
			details: Details{Message: "invalid alias", Alias: "prod"},
			code:    "invalid_request", hint: "provide one exact inventory alias", exit: 2, alias: "prod",
		},
		{
			name: "request check validation", kind: InvalidRequestCheck,
			details: Details{Message: "invalid check request", Alias: "prod"},
			code:    "invalid_request", hint: "check accepts only version, op, and alias", exit: 2, alias: "prod",
		},
		{
			name: "request doctor validation", kind: InvalidRequestDoctor,
			details: Details{Message: "invalid doctor request", Alias: "prod"},
			code:    "invalid_request", hint: "use alias and optional deep only", exit: 2, alias: "prod",
		},
		{
			name: "request doctor alias", kind: InvalidRequestDoctorAlias,
			details: Details{Message: "invalid doctor alias", Alias: "prod"},
			code:    "invalid_request", hint: "doctor alias must be an exact inventory name", exit: 2, alias: "prod",
		},
		{
			name: "request host validation", kind: InvalidRequestHost,
			details: Details{Message: "invalid host request", Alias: "prod"},
			code:    "invalid_request", hint: "host operations accept structured host fields and file-based credentials only", exit: 2, alias: "prod",
		},
		{
			name: "request put fields", kind: InvalidRequestPutFields,
			details: Details{Message: "invalid put fields", Alias: "prod"},
			code:    "invalid_request", hint: "use file paths; never place file contents or credentials in the request", exit: 2, alias: "prod",
		},
		{
			name: "request put paths", kind: InvalidRequestPutPaths,
			details: Details{Message: "invalid put paths", Alias: "prod"},
			code:    "invalid_request", hint: "use resume:\"v1\" explicitly for regular-file retry", exit: 2, alias: "prod",
		},
		{
			name: "request timeout", kind: InvalidRequestTimeout,
			details: Details{Message: "invalid timeout", Alias: "prod"},
			code:    "invalid_request", hint: "timeout must be a positive duration", exit: 2, alias: "prod",
		},
		{
			name: "request operation", kind: InvalidRequestOperation,
			details: Details{Message: "invalid operation", Alias: "prod"},
			code:    "invalid_request", hint: "use run, plan, check, doctor, put, get, or host.list/search/show/add/update/upsert/remove", exit: 2, alias: "prod",
		},
		{
			name: "stream vault unlock", kind: StreamVaultUnlockFailed,
			details: Details{Message: "decrypt failed"},
			code:    "vault_unlock_failed", stage: "vault", hint: "verify the master pass file belongs to this encrypted vault", exit: 1,
		},
		{
			name: "stream decode", kind: StreamDecodeFailed,
			details: Details{Message: "invalid line"},
			code:    "invalid_request", stage: "decode", hint: "send one non-empty JSON string array per line", exit: 2,
		},
		{
			name: "stream read", kind: StreamReadFailed,
			details: Details{Message: "stream line exceeds 1 MiB or could not be read"},
			code:    "invalid_request", stage: "read", hint: "send smaller argv arrays", exit: 2,
		},
		{
			name: "register arguments", kind: RegisterArgumentsInvalid,
			details: Details{Message: "register requires explicit flags"},
			code:    "invalid_arguments", hint: "use --server, --email, and --password-file", exit: 2,
		},
		{
			name: "login arguments", kind: LoginArgumentsInvalid,
			details: Details{Message: "login requires explicit flags"},
			code:    "invalid_arguments", hint: "use --server, --email, and --password-file", exit: 2,
		},
		{
			name: "push arguments", kind: PushArgumentsInvalid,
			details: Details{Message: "invalid push scope"},
			code:    "invalid_arguments", hint: "inspect pending_mutations with sshctl --json status", exit: 2,
		},
		{
			name: "push only required", kind: PushOnlyRequired,
			details: Details{Message: "empty transaction"},
			code:    "invalid_arguments", hint: "copy an exact id from sshctl --json status", exit: 2,
		},
		{
			name: "push scope conflict", kind: PushScopeConflict,
			details: Details{Message: "conflicting scope"},
			code:    "invalid_arguments", hint: "choose one explicit push scope", exit: 2,
		},
		{
			name: "sync push", kind: SyncPushFailed,
			details: Details{Message: "push failed"},
			code:    "sync_push_failed", hint: "local vault remains pending; fix sync and retry push", exit: 1,
		},
		{
			name: "sync unconfigured", kind: SyncUnconfigured,
			details: Details{Message: "not logged in (run: ssm login)"},
			code:    "sync_config_error", hint: "configure sync or use local inventory", exit: 1,
		},
		{
			name: "sync configuration", kind: SyncConfigurationFailed,
			details: Details{Message: "bad sync config"},
			code:    "sync_config_error", stage: "sync_config",
			hint: "repair sync configuration or retry explicitly with --offline", exit: 1,
		},
		{
			name: "sync pull replacement", kind: SyncPullReplaceFailed,
			details: Details{Message: "pull failed"},
			code:    "sync_pull_failed", hint: "local inventory was not replaced", exit: 1,
		},
		{
			name: "transfer arguments", kind: TransferArgumentsInvalid,
			details: Details{Message: "bad transfer option"},
			code:    "invalid_arguments", stage: "validate",
			hint: "use sshctl put <alias> <local> <remote> [--resume=v1] [--sha256] [--timeout <duration>] [--json]", exit: 2,
		},
		{
			name: "map targets", kind: MapNoTargets,
			details: Details{Message: "no aliases matched the requested map targets", Alias: "prod-*"},
			code:    "no_targets", hint: "refresh sshctl host list and use exact aliases or reviewed patterns", exit: 2, alias: "prod-*",
		},
		{
			name: "redirect action", kind: RedirectActionRequired,
			details: Details{Message: "redirect action required"},
			code:    "invalid_arguments", hint: "use redirect list, set <old> <new>, or rm <old>", exit: 2,
		},
		{
			name: "redirect set", kind: RedirectSetArgumentsInvalid,
			details: Details{Message: "redirect set requires aliases"},
			code:    "invalid_arguments", hint: "use redirect set <old-alias> <target-alias>", exit: 2,
		},
		{
			name: "redirect remove", kind: RedirectRemoveArgumentsInvalid,
			details: Details{Message: "redirect remove requires alias"},
			code:    "invalid_arguments", hint: "use redirect rm <old-alias>", exit: 2,
		},
		{
			name: "redirect action unknown", kind: RedirectActionInvalid,
			details: Details{Message: "unknown redirect action"},
			code:    "invalid_arguments", hint: "use redirect list, set, or rm", exit: 2,
		},
		{
			name: "import arguments", kind: ImportArgumentsInvalid,
			details: Details{Message: "invalid import arguments"},
			code:    "invalid_arguments", hint: "use exactly one of --merge or --replace --yes", exit: 2,
		},
		{
			name: "import count", kind: ImportCountMismatch,
			details: Details{Message: "count mismatch"},
			code:    "import_count_mismatch", hint: "review the import source and expected count before retrying", exit: 1,
		},
		{
			name: "merge report", kind: MergeReportFailed,
			details: Details{Message: "report failed"},
			code:    "merge_report_error", hint: "vault was not changed; verify config directory permissions", exit: 1,
		},
		{
			name: "run alias lookup", kind: RunAliasNotFound,
			details: Details{Message: `connection "missing" not found`, Alias: "missing"},
			code:    "alias_not_found", stage: "lookup", hint: "use sshctl host list --json and retry with an exact alias", exit: 255,
			alias: "missing",
		},
		{
			name: "map alias lookup", kind: MapAliasNotFound,
			details: Details{Message: "requested alias was not found", Alias: "missing"},
			code:    "alias_not_found", stage: "lookup", hint: "use sshctl list --json; alias may have been renamed after migration", exit: 255,
			alias: "missing",
		},
		{
			name: "doctor alias lookup", kind: DoctorAliasNotFound,
			details: Details{Message: "requested alias was not found", Alias: "missing"},
			code:    "alias_not_found", stage: "lookup", hint: "use sshctl --json host list and retry with an exact alias", exit: 255,
			alias: "missing",
		},
		{
			name: "session acquisition fallback", kind: SessionAcquisitionFailed,
			details: Details{Message: "failed to acquire session", Alias: "prod"},
			code:    "session_failed", stage: "session", exit: 255, alias: "prod",
		},
		{
			name: "SSH stdin", kind: SSHStdinFailed,
			details: Details{Message: "failed to open SSH stdin", Alias: "prod"},
			code:    "internal", stage: "session", hint: "retry the operation; report the failure if it persists", exit: 1, alias: "prod",
		},
		{
			name: "run arguments", kind: InvalidRunArguments,
			details: Details{Cause: errors.New("unknown run option"), Alias: "prod", Tool: "sshctl"},
			code:    "invalid_arguments", hint: "unknown run option", exit: 2, alias: "prod",
		},
		{
			name: "host-key arguments", kind: HostKeyArgumentsInvalid,
			details: Details{Message: "invalid host-key arguments"},
			code:    "invalid_arguments",
			hint:    "use host-key inspect <alias> or host-key accept <alias> --fingerprint SHA256:... --yes", exit: 2,
		},
		{
			name: "host-key vault", kind: HostKeyVaultFailed,
			details: Details{Message: "vault failed"},
			code:    "vault_error", hint: "unlock the vault and retry", exit: 1,
		},
		{
			name: "host-key operation", kind: HostKeyOperationFailed,
			details: Details{Message: "operation failed"},
			code:    "host_key_operation_failed", stage: "host_key", hint: "inspect the endpoint and retry", exit: 1,
		},
		{
			name: "host-key scan direct", kind: HostKeyScanDirectFailed,
			details: Details{Message: "scan failed"},
			code:    "host_key_scan_failed", stage: "host_key",
			hint: "verify the endpoint is a direct SSH service rather than an HTTP proxy", exit: 1,
		},
		{
			name: "host-key scan", kind: HostKeyScanFailed,
			details: Details{Message: "scan failed"},
			code:    "host_key_scan_failed", stage: "host_key", hint: "verify the SSH endpoint and retry", exit: 1,
		},
		{
			name: "known-hosts permissions", kind: KnownHostsPermissionsFailed,
			details: Details{Message: "known_hosts failed"},
			code:    "known_hosts_error", stage: "host_key", hint: "fix known_hosts permissions and retry", exit: 1,
		},
		{
			name: "known-hosts malformed", kind: KnownHostsMalformed,
			details: Details{Message: "known_hosts malformed"},
			code:    "known_hosts_error", stage: "host_key", hint: "repair malformed known_hosts before accepting a key", exit: 1,
		},
		{
			name: "known-hosts inspect", kind: KnownHostsInspectionFailed,
			details: Details{Message: "known_hosts inspect failed"},
			code:    "known_hosts_error", stage: "host_key", hint: "inspect known_hosts and retry", exit: 1,
		},
		{
			name: "SSH directory permissions", kind: SSHDirectoryPermissionsFailed,
			details: Details{Message: "SSH directory failed"},
			code:    "known_hosts_error", stage: "host_key", hint: "fix ~/.ssh permissions and retry", exit: 1,
		},
		{
			name: "known-hosts unchanged", kind: KnownHostsUnchanged,
			details: Details{Message: "known_hosts update failed"},
			code:    "known_hosts_error", stage: "host_key", hint: "known_hosts was not changed", exit: 1,
		},
		{
			name: "known-hosts update", kind: KnownHostsUpdateFailed,
			details: Details{Message: "ssh-keygen failed"},
			code:    "known_hosts_update_failed", stage: "host_key",
			hint: "install OpenSSH ssh-keygen or remove the exact host:port entry manually", exit: 1,
		},
		{
			name: "host-key fingerprint mismatch", kind: HostKeyFingerprintMismatch,
			details: Details{Message: "fingerprint mismatch"},
			code:    "fingerprint_mismatch", stage: "host_key",
			hint: "compare the fingerprint through a trusted channel; do not accept an unexpected key", exit: 1,
		},
		{
			name: "host-key fingerprint changed", kind: HostKeyFingerprintChanged,
			details: Details{Message: "fingerprint changed"},
			code:    "fingerprint_changed", stage: "host_key",
			hint: "known_hosts was not changed; investigate endpoint instability or a possible interception", exit: 1,
		},
		{
			name: "transfer local file stat", kind: TransferLocalFileStat,
			details: Details{Message: "stat failed"},
			code:    "local_read_failed", stage: "local_read", hint: "verify the local file is readable", exit: 1,
		},
		{
			name: "transfer regular file required", kind: TransferRegularFileRequired,
			details: Details{Message: "not a regular file"},
			code:    "local_read_failed", stage: "local_read", hint: "put integrity mode supports regular files", exit: 1,
		},
		{
			name: "transfer integrity source read", kind: TransferIntegritySourceRead,
			details: Details{Message: "read failed"},
			code:    "local_read_failed", stage: "local_read", hint: "read the local file successfully before retrying", exit: 1,
		},
		{
			name: "transfer seekable source", kind: TransferSeekableSourceRequired,
			details: Details{Message: "seek failed"},
			code:    "local_read_failed", stage: "local_read", hint: "use a seekable regular source file", exit: 1,
		},
		{
			name: "transfer session", kind: TransferSessionOpenFailed,
			details: Details{Message: "session failed"},
			code:    "session_failed", stage: "dial", hint: "retry after checking SSH session limits", exit: 1,
		},
		{
			name: "transfer stdin", kind: TransferStdinOpenFailed,
			details: Details{Message: "stdin failed"},
			code:    "remote_write_failed", stage: "remote_write", hint: "retry the upload; the final destination was not replaced", exit: 1,
		},
		{
			name: "transfer start", kind: TransferStartFailed,
			details: Details{Message: "start failed"},
			code:    "remote_write_failed", stage: "remote_write", hint: "remote temporary file was not published", exit: 1,
		},
		{
			name: "transfer timeout", kind: TransferTimedOut,
			details: Details{Message: "timeout"},
			code:    "transfer_timeout", stage: "timeout", hint: "retry; the remote temporary file is cleaned and the final path is unchanged", exit: 1,
		},
		{
			name: "transfer write", kind: TransferRemoteWriteFailed,
			details: Details{Message: "copy failed"},
			code:    "remote_write_failed", stage: "remote_write", hint: "retry; the remote temporary file is cleaned and the final path is unchanged", exit: 1,
		},
		{
			name: "transfer close", kind: TransferRemoteCloseFailed,
			details: Details{Message: "close failed"},
			code:    "remote_write_failed", stage: "remote_write", hint: "retry; the final path was not replaced", exit: 1,
		},
		{
			name: "transfer integrity mismatch", kind: TransferIntegrityMismatch,
			details: Details{Message: "integrity failed"},
			code:    "integrity_failed", stage: "integrity", hint: "source and remote temporary file differ; nothing was published", exit: 1,
		},
		{
			name: "transfer remote permissions", kind: TransferRemotePermissionsFailed,
			details: Details{Message: "remote failed"},
			code:    "remote_write_failed", stage: "remote_write", hint: "check remote path permissions and available space; the final path was not replaced", exit: 1,
		},
		{
			name: "transfer receipt", kind: TransferReceiptInvalid,
			details: Details{Message: "receipt failed"},
			code:    "integrity_failed", stage: "integrity", hint: "remote receipt did not match the local file; investigate the endpoint", exit: 1,
		},
		{
			name: "resume unsupported version", kind: ResumeVersionUnsupported,
			details: Details{Message: "unsupported version"},
			code:    "unsupported_resume_version", stage: "validate", hint: "use --resume=v1", exit: 1,
		},
		{
			name: "resume regular file required", kind: ResumeRegularFileRequired,
			details: Details{Message: "not a regular file"},
			code:    "local_read_failed", stage: "local_read", hint: "resume v1 supports regular files only", exit: 1,
		},
		{
			name: "resume source read", kind: ResumeSourceReadFailed,
			details: Details{Message: "read failed"},
			code:    "local_read_failed", stage: "local_read", hint: "read the complete source before retrying", exit: 1,
		},
		{
			name: "resume source changed", kind: ResumeSourceChanged,
			details: Details{Message: "source changed"},
			code:    "local_read_failed", stage: "local_read", hint: "source changed or could not be re-read", exit: 1,
		},
		{
			name: "resume partial mismatch", kind: ResumePartialMismatch,
			details: Details{Message: "partial mismatch"},
			code:    "partial_state_mismatch", stage: "resume_validate",
			hint: "remote partial prefix does not match the local source; remove stale state only after review or retry with non-resume put", exit: 1,
		},
		{
			name: "resume source seek", kind: ResumeSourceSeekFailed,
			details: Details{Message: "seek failed"},
			code:    "local_read_failed", stage: "local_read", hint: "source must remain seekable and unchanged", exit: 1,
		},
		{
			name: "resume stdin", kind: ResumeStdinOpenFailed,
			details: Details{Message: "stdin failed"},
			code:    "remote_write_failed", stage: "remote_write", hint: "retry resume; existing verified prefix remains available", exit: 1,
		},
		{
			name: "resume start", kind: ResumeStartFailed,
			details: Details{Message: "start failed"},
			code:    "remote_write_failed", stage: "remote_write", hint: "retry resume; final destination was not replaced", exit: 1,
		},
		{
			name: "resume timeout", kind: ResumeTimedOut,
			details: Details{Message: "timeout"},
			code:    "transfer_timeout", stage: "timeout", hint: "retry with --resume=v1 to validate and reuse the remote prefix", exit: 1,
		},
		{
			name: "resume write", kind: ResumeRemoteWriteFailed,
			details: Details{Message: "write failed"},
			code:    "remote_write_failed", stage: "remote_write", hint: "retry with --resume=v1; the destination was not replaced", exit: 1,
		},
		{
			name: "resume retry", kind: ResumeRetryFailed,
			details: Details{Message: "retry failed"},
			code:    "remote_write_failed", stage: "remote_write", hint: "retry with --resume=v1", exit: 1,
		},
		{
			name: "resume verification tool", kind: ResumeVerificationToolMissing,
			details: Details{Message: "sha256sum missing"},
			code:    "verification_tool_missing", stage: "capability", hint: "install sha256sum on the remote host or use non-resume put", exit: 1,
		},
		{
			name: "resume state changed", kind: ResumeStateChanged,
			details: Details{Message: "state changed"},
			code:    "partial_state_changed", stage: "resume_validate", hint: "remote partial changed during retry; do not append until investigated", exit: 1,
		},
		{
			name: "resume integrity mismatch", kind: ResumeIntegrityMismatch,
			details: Details{Message: "digest mismatch"},
			code:    "integrity_failed", stage: "integrity", hint: "completed partial failed SHA-256 verification and was not published", exit: 1,
		},
		{
			name: "resume publish", kind: ResumePublishFailed,
			details: Details{Message: "publish failed"},
			code:    "publish_failed", stage: "publish", hint: "verified partial remains; fix destination permissions and retry resume", exit: 1,
		},
		{
			name: "resume receipt", kind: ResumeReceiptInvalid,
			details: Details{Message: "receipt invalid"},
			code:    "integrity_failed", stage: "integrity", hint: "remote completion receipt is invalid", exit: 1,
		},
		{
			name: "resume probe session", kind: ResumeProbeSessionFailed,
			details: Details{Message: "session failed"},
			code:    "session_failed", stage: "resume_probe", hint: "retry after checking SSH session limits", exit: 1,
		},
		{
			name: "resume state incompatible", kind: ResumeStateIncompatible,
			details: Details{Message: "state incompatible"},
			code:    "partial_state_incompatible", stage: "resume_validate",
			hint: "remote partial metadata is missing or incompatible; review and remove only the deterministic v1 partial state", exit: 1,
		},
		{
			name: "resume probe", kind: ResumeProbeFailed,
			details: Details{Message: "probe failed"},
			code:    "resume_probe_failed", stage: "resume_probe", hint: "check remote path permissions and resume capability", exit: 1,
		},
		{
			name: "resume probe receipt", kind: ResumeProbeResponseInvalid,
			details: Details{Message: "probe response invalid"},
			code:    "resume_probe_failed", stage: "resume_probe", hint: "remote resume response was invalid", exit: 1,
		},
		{
			name: "directory source type", kind: TransferDirectorySourceUnsupported,
			details: Details{Message: "unsupported source"},
			code:    "local_read_failed", stage: "local_read", hint: "use a regular file or directory", exit: 1,
		},
		{
			name: "directory options", kind: TransferDirectoryOptionsUnsupported,
			details: Details{Message: "unsupported options"},
			code:    "unsupported_transfer_option", stage: "validate",
			hint: "SHA-256, timeout, and resume v1 options support regular-file put only", exit: 1,
		},
		{
			name: "download remote read", kind: TransferDownloadRemoteRead,
			details: Details{Message: "remote read failed"},
			code:    "remote_read_failed", stage: "remote_read",
			hint: "check the remote path and read permissions; the final local path was not replaced", exit: 1,
		},
		{
			name: "download local write", kind: TransferDownloadLocalWrite,
			details: Details{Message: "local write failed"},
			code:    "local_write_failed", stage: "local_write",
			hint: "check local path permissions and available space; the final local path was not replaced", exit: 1,
		},
		{
			name: "download publish", kind: TransferDownloadPublish,
			details: Details{Message: "publish failed"},
			code:    "publish_failed", stage: "publish",
			hint: "check local destination permissions; the previous final path was preserved", exit: 1,
		},
		{
			name: "download restore", kind: TransferDownloadRestoreFailed,
			details: Details{Message: "publish and restore failed"},
			code:    "publish_failed", stage: "publish",
			hint: "automatic restore failed; recover the prior directory from the retained backup path reported in the error", exit: 1,
		},
	}

	seen := make(map[Kind]bool, len(tests))
	for _, test := range tests {
		if seen[test.kind] {
			t.Fatalf("duplicate machine contract matrix kind %q", test.kind)
		}
		seen[test.kind] = true
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := Classify(test.kind, test.details)
			if got.OK || got.Error != test.code || got.Stage != test.stage || got.Hint != test.hint ||
				got.Exit != test.exit || got.Alias != test.alias {
				t.Fatalf("Classify(%q) = %+v", test.kind, got)
			}
			if strings.Join(got.Candidates, "\x00") != strings.Join(test.candidates, "\x00") {
				t.Fatalf("Classify(%q) candidates = %q, want %q", test.kind, got.Candidates, test.candidates)
			}
			wantProcessExit := test.processExit
			if wantProcessExit == 0 {
				wantProcessExit = test.exit
			}
			if ProcessExit(got) != wantProcessExit {
				t.Fatalf("ProcessExit(%q) = %d, want %d", test.kind, ProcessExit(got), wantProcessExit)
			}
		})
	}

	t.Run("all registered kinds have complete stable policy", func(t *testing.T) {
		for kind, policy := range failurePolicies {
			if kind == "" || policy.Code == "" || policy.Exit < 0 {
				t.Fatalf("incomplete policy %q: %+v", kind, policy)
			}
			if !seen[kind] {
				t.Errorf("registered kind %q has no matrix row", kind)
			}
		}
	})
}

func TestClassifySyncFailureUsesCanonicalPolicy(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		fallback  Kind
		wantCode  string
		wantStage string
	}{
		{
			name: "configuration overrides command fallback", err: synctransaction.ErrConfiguration,
			fallback: StreamSyncPullFailed, wantCode: "sync_config_error", wantStage: "sync_config",
		},
		{
			name: "conflict overrides command fallback", err: synctransaction.ErrConflict,
			fallback: SyncPushFailed, wantCode: "sync_conflict", wantStage: "sync_compare",
		},
		{
			name: "refresh retains command fallback", err: synctransaction.ErrRefresh,
			fallback: StreamSyncPullFailed, wantCode: "sync_pull_failed", wantStage: "sync_pull",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			failure := ClassifySyncFailure(test.err, test.fallback)
			if failure.Error != test.wantCode || failure.Stage != test.wantStage {
				t.Fatalf("failure = %+v", failure)
			}
		})
	}
}

func TestMachineContractRedaction(t *testing.T) {
	t.Parallel()

	privateKey := "-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE_KEY_CANARY\n-----END OPENSSH PRIVATE KEY-----"
	failure := Classify(InternalFailure, Details{
		Message: strings.Join([]string{
			"password=CREDENTIAL_CANARY",
			`password=\"OUTER_ESCAPED_PASSWORD_CANARY WITH SPACES\"`,
			`{\"password\":\"OUTER_ESCAPED_KEY_CANARY WITH SPACES,AND,COMMAS\"}`,
			"token=TOKEN_CANARY",
			"passphrase=PASSPHRASE_CANARY",
			"master_pass=MASTER_PASS_SNAKE_CANARY",
			"masterPass=MASTER_PASS_CAMEL_CANARY",
			`config={"secret":"CONFIG_CANARY"}`,
			`config="{\"token\":\"ESCAPED_CONFIG_CANARY\"}"`,
			"private_key=" + privateKey,
			"request_body=REQUEST_BODY_CANARY",
			`request_body={"argv":["echo", "SPACED_REQUEST_BODY_CANARY"]}`,
			`request_body="{\"argv\":[\"ESCAPED_REQUEST_BODY_CANARY\"]}"`,
			"decrypted_inventory=DECRYPTED_INVENTORY_CANARY",
			`decrypted_inventory={"hosts":[{"name": "SPACED_INVENTORY_CANARY"}]}`,
			`decrypted_inventory="{\"hosts\":[\"ESCAPED_INVENTORY_CANARY\"]}"`,
		}, " "),
		Candidates: []string{"password=CANDIDATE_CREDENTIAL_CANARY"},
	})
	// Inject after classification to prove every renderer independently applies
	// the redaction boundary.
	failure.Message += " token=RENDER_BOUNDARY_TOKEN_CANARY"
	canaries := []string{
		"CREDENTIAL_CANARY",
		"OUTER_ESCAPED_PASSWORD_CANARY",
		"OUTER_ESCAPED_KEY_CANARY",
		"TOKEN_CANARY",
		"PASSPHRASE_CANARY",
		"MASTER_PASS_SNAKE_CANARY",
		"MASTER_PASS_CAMEL_CANARY",
		"CONFIG_CANARY",
		"ESCAPED_CONFIG_CANARY",
		"PRIVATE_KEY_CANARY",
		"REQUEST_BODY_CANARY",
		"SPACED_REQUEST_BODY_CANARY",
		"ESCAPED_REQUEST_BODY_CANARY",
		"DECRYPTED_INVENTORY_CANARY",
		"SPACED_INVENTORY_CANARY",
		"ESCAPED_INVENTORY_CANARY",
		"CANDIDATE_CREDENTIAL_CANARY",
		"RENDER_BOUNDARY_TOKEN_CANARY",
	}

	tests := []struct {
		name   string
		format Format
	}{
		{name: "json document", format: JSONDocument},
		{name: "compact ndjson", format: NDJSON},
		{name: "human diagnostic", format: Human},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if err := Render(test.format, Streams{Stdout: &stdout, Stderr: &stderr}, failure); err != nil {
				t.Fatalf("Render(%v): %v", test.format, err)
			}
			output := stdout.String() + stderr.String()
			for _, canary := range canaries {
				if strings.Contains(output, canary) {
					t.Fatalf("Render(%v) leaked %q in %q", test.format, canary, output)
				}
			}
			switch test.format {
			case JSONDocument:
				if stdout.Len() == 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "\n  \"error\":") {
					t.Fatalf("JSON placement/framing stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
			case NDJSON:
				if stdout.Len() == 0 || stderr.Len() != 0 || strings.Count(strings.TrimSpace(stdout.String()), "\n") != 0 {
					t.Fatalf("NDJSON placement/framing stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
			case Human:
				if stdout.Len() != 0 || stderr.Len() == 0 {
					t.Fatalf("human placement stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
			}
		})
	}

	t.Run("typed failure sensitive fields and map keys", func(t *testing.T) {
		t.Parallel()
		value := struct {
			OK                 bool              `json:"ok"`
			Safe               string            `json:"safe"`
			Token              string            `json:"token"`
			Password           string            `json:"password"`
			Passphrase         string            `json:"passphrase"`
			MasterPass         string            `json:"masterPass"`
			PrivateKey         string            `json:"private_key"`
			RequestBody        string            `json:"request_body"`
			Config             string            `json:"config"`
			DecryptedInventory string            `json:"decrypted_inventory"`
			Metadata           map[string]string `json:"metadata"`
		}{
			OK:                 false,
			Safe:               "SAFE_VALUE",
			Token:              "FIELD_TOKEN_CANARY",
			Password:           "FIELD_PASSWORD_CANARY",
			Passphrase:         "FIELD_PASSPHRASE_CANARY",
			MasterPass:         "FIELD_MASTER_PASS_CANARY",
			PrivateKey:         "FIELD_PRIVATE_KEY_CANARY",
			RequestBody:        "FIELD_REQUEST_BODY_CANARY",
			Config:             "FIELD_CONFIG_CANARY",
			DecryptedInventory: "FIELD_INVENTORY_CANARY",
			Metadata: map[string]string{ //nolint:gosec // deliberate fake canaries prove field-name redaction
				"token": "MAP_TOKEN_CANARY",
				"safe":  "MAP_SAFE_VALUE",
			},
		}
		var stdout, stderr bytes.Buffer
		if err := RenderFailure(JSONDocument, Streams{Stdout: &stdout, Stderr: &stderr}, value); err != nil {
			t.Fatal(err)
		}
		output := stdout.String() + stderr.String()
		for _, canary := range []string{
			"FIELD_TOKEN_CANARY",
			"FIELD_PASSWORD_CANARY",
			"FIELD_PASSPHRASE_CANARY",
			"FIELD_MASTER_PASS_CANARY",
			"FIELD_PRIVATE_KEY_CANARY",
			"FIELD_REQUEST_BODY_CANARY",
			"FIELD_CONFIG_CANARY",
			"FIELD_INVENTORY_CANARY",
			"MAP_TOKEN_CANARY",
		} {
			if strings.Contains(output, canary) {
				t.Errorf("typed renderer leaked %q in %q", canary, output)
			}
		}
		if !strings.Contains(output, `"safe": "SAFE_VALUE"`) ||
			!strings.Contains(output, `"safe": "MAP_SAFE_VALUE"`) {
			t.Fatalf("safe typed values changed in %q", output)
		}
	})

	t.Run("typed success fields are unchanged", func(t *testing.T) {
		t.Parallel()
		value := struct {
			OK     bool   `json:"ok"`
			Stdout string `json:"stdout"`
			Token  string `json:"token"`
		}{
			OK:     true,
			Stdout: "token=<tokentoken ' exact>\n",
			Token:  "SUCCESS_TOKEN_FIELD_CANARY",
		}
		var stdout, stderr bytes.Buffer
		if err := Render(JSONDocument, Streams{Stdout: &stdout, Stderr: &stderr}, value); err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Stdout string `json:"stdout"`
			Token  string `json:"token"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Stdout != value.Stdout || decoded.Token != value.Token || stderr.Len() != 0 {
			t.Fatalf("typed success=%+v stderr=%q, want stdout=%q token=%q", decoded, stderr.String(), value.Stdout, value.Token)
		}
	})

	t.Run("explicit short sensitive values are removed in every failure mode", func(t *testing.T) {
		t.Parallel()
		failure := Redact(Classify(InternalFailure, Details{
			Message: "remote diagnostic got abc before failure",
		}), "abc")
		for _, format := range []Format{JSONDocument, NDJSON, Human} {
			var stdout, stderr bytes.Buffer
			if err := Render(format, Streams{Stdout: &stdout, Stderr: &stderr}, failure); err != nil {
				t.Fatalf("Render(%v): %v", format, err)
			}
			if output := stdout.String() + stderr.String(); strings.Contains(output, "abc") {
				t.Fatalf("Render(%v) leaked short known secret in %q", format, output)
			}
		}
	})
}

func TestRedactingWriterCoversSplitValuesAndPrivateKeyBlocks(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	writer := NewRedactingWriter(&output, "OPAQUE_STREAM_CANARY", "abc")
	for _, fragment := range []string{
		"safe line\n",
		"OPAQUE_",
		"STREAM_CANARY\n",
		"token=SPLIT_",
		"TOKEN_CANARY\n",
		"-----BEGIN OPENSSH PRIVATE KEY-----\n",
		"PRIVATE_KEY_BODY_CANARY\n",
		"-----END OPENSSH PRIVATE KEY-----\n",
		"config={\n",
		"  \"endpoint\": \"STRUCTURED_CONFIG_CANARY\"\n",
		"}\n",
		`con`,
		`fig="{\"token\":\"SPLIT_CONFIG_CANARY\"}"` + "\n",
		`request_body="{\"argv\":[\"SPLIT_REQUEST_`,
		`BODY_CANARY\"]}"` + "\n",
		`decrypted_inven`,
		`tory="{\"hosts\":[\"SPLIT_INVENTORY_CANARY\"]}"` + "\n",
		`password=\"OUTER_ESCAPED_PASSWORD_CANARY WITH SPACES,AND,COMMAS\"` + "\n",
		`{\"masterPass\":\"OUTER_ESCAPED_MASTER_PASS_CANARY WITH SPACES\"}` + "\n",
		"config={\n",
		`  "first": "FIRST_STRUCTURE_CANARY"` + "\n",
		"}\nrequest_body={\n",
		`  "argv": ["SECOND_STRUCTURE_CANARY"]` + "\n",
		"}\n",
		"short known value: abc\n",
		"safe tail",
	} {
		if _, err := writer.Write([]byte(fragment)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "safe line\n***\ntoken=<redacted>\n<redacted-private-key>\nconfig=<redacted>\nconfig=<redacted>\nrequest_body=<redacted>\ndecrypted_inventory=<redacted>\npassword=<redacted>\n{\\\"masterPass\\\":<redacted>}\nconfig=<redacted>\nrequest_body=<redacted>\nshort known value: ***\nsafe tail" {
		t.Fatalf("redacted stream = %q", got)
	}
}

func TestDiagnosticSpoolReplaysSuccessfulBytesUnchanged(t *testing.T) {
	t.Parallel()

	const diagnostic = "config=\"{\\\"token\\\":\\\"SUCCESS_DIAGNOSTIC_CANARY\\\"}\"\n"
	var output bytes.Buffer
	spool, err := NewDiagnosticSpool(&output)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"config=\"{\\\"to",
		"ken\\\":\\\"SUCCESS_",
		"DIAGNOSTIC_CANARY\\\"}\"\n",
	} {
		if _, err := spool.Write([]byte(fragment)); err != nil {
			t.Fatal(err)
		}
	}
	if err := spool.Replay(true); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != diagnostic {
		t.Fatalf("successful diagnostic replay=%q, want exact bytes %q", got, diagnostic)
	}
}

func TestDiagnosticSpoolRedactsFailedBytes(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	spool, err := NewDiagnosticSpool(&output)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		`request_body="{\"argv\":[\"FAILED_`,
		`DIAGNOSTIC_CANARY\"]}"` + "\n",
		"safe diagnostic\n",
	} {
		if _, err := spool.Write([]byte(fragment)); err != nil {
			t.Fatal(err)
		}
	}
	if err := spool.Replay(false); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "request_body=<redacted>\nsafe diagnostic\n" {
		t.Fatalf("failed diagnostic replay=%q", got)
	}
}

func TestDiagnosticSpoolUsesPrivateTemporaryFileAndCleansUp(t *testing.T) {
	tempDir := t.TempDir()
	payload := bytes.Repeat([]byte("large safe diagnostic payload\n"), 200_000)
	var output bytes.Buffer
	spool, err := newDiagnosticSpool(&output, tempDir)
	if err != nil {
		t.Fatal(err)
	}
	for offset := 0; offset < len(payload); {
		end := offset + 32*1024
		if end > len(payload) {
			end = len(payload)
		}
		if _, err := spool.Write(payload[offset:end]); err != nil {
			t.Fatal(err)
		}
		offset = end
	}
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("diagnostic spool temp entries = %d, want 1", len(entries))
	}
	if err := privatepath.VerifyFile(filepath.Join(tempDir, entries[0].Name())); err != nil {
		t.Fatalf("diagnostic spool privacy: %v", err)
	}
	if err := spool.Replay(true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), payload) {
		t.Fatalf("large diagnostic replay bytes changed: got=%d want=%d", output.Len(), len(payload))
	}
	entries, err = os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("diagnostic spool retained %d temp entries after replay", len(entries))
	}
}

func TestDiagnosticSpoolCleansUpWhenReplayFails(t *testing.T) {
	tempDir := t.TempDir()
	spool, err := newDiagnosticSpool(errorWriter{}, tempDir, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Write([]byte("got abc\n")); err != nil {
		t.Fatal(err)
	}
	if err := spool.Replay(false); err == nil {
		t.Fatal("failed diagnostic replay unexpectedly succeeded")
	}
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("diagnostic spool retained %d temp entries after replay failure", len(entries))
	}
}

func TestDiagnosticSpoolAcceptsExactByteBoundAndPreservesBytes(t *testing.T) {
	tempDir := t.TempDir()
	payload := []byte("12345678")
	var output bytes.Buffer
	spool, err := newDiagnosticSpoolWithLimit(&output, tempDir, int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := spool.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("exact-bound write = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	if err := spool.Replay(true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), payload) {
		t.Fatalf("exact-bound replay = %q, want %q", output.Bytes(), payload)
	}
	if entries, err := os.ReadDir(tempDir); err != nil || len(entries) != 0 {
		t.Fatalf("exact-bound cleanup entries=%v err=%v", entries, err)
	}
}

func TestDiagnosticSpoolOverflowFailsWithoutOutputOrRetainedFile(t *testing.T) {
	tempDir := t.TempDir()
	const secret = "OVERFLOW_SECRET_CANARY"
	var output bytes.Buffer
	spool, err := newDiagnosticSpoolWithLimit(&output, tempDir, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Write([]byte("safe")); err != nil {
		t.Fatal(err)
	}
	if n, err := spool.Write([]byte(secret)); err == nil || n != 0 {
		t.Fatalf("over-bound write = (%d, %v), want (0, error)", n, err)
	}
	if entries, err := os.ReadDir(tempDir); err != nil || len(entries) != 0 {
		t.Fatalf("overflow cleanup entries=%v err=%v", entries, err)
	}
	if err := spool.Replay(false); err == nil {
		t.Fatal("overflow replay unexpectedly succeeded")
	}
	if strings.Contains(output.String(), secret) || output.Len() != 0 {
		t.Fatalf("overflow leaked buffered diagnostics: %q", output.String())
	}
	if err := spool.Close(); err != nil {
		t.Fatalf("close after overflow: %v", err)
	}
}

func TestDiagnosticSpoolCloseRetriesFailedRemoval(t *testing.T) {
	tempDir := t.TempDir()
	var output bytes.Buffer
	spool, err := newDiagnosticSpoolWithLimit(&output, tempDir, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Write([]byte("private")); err != nil {
		t.Fatal(err)
	}
	path := spool.path
	removeCalls := 0
	spool.remove = func(name string) error {
		removeCalls++
		if removeCalls == 1 {
			return errors.New("fixture removal failed")
		}
		return os.Remove(name)
	}
	if err := spool.Replay(true); err == nil {
		t.Fatal("replay unexpectedly ignored removal failure")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("spool path unavailable for cleanup retry: %v", err)
	}
	if err := spool.Close(); err != nil {
		t.Fatalf("retry cleanup: %v", err)
	}
	if removeCalls != 2 {
		t.Fatalf("remove calls = %d, want 2", removeCalls)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("spool path retained after cleanup retry: %v", err)
	}
}

func TestDiagnosticSpoolPublishedLimitIsPractical(t *testing.T) {
	if DiagnosticSpoolByteLimit != 8<<20 {
		t.Fatalf("DiagnosticSpoolByteLimit = %d, want 8 MiB", DiagnosticSpoolByteLimit)
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("fixture output rejected")
}

func TestMachineContractRendering(t *testing.T) {
	t.Parallel()

	failure := Classify(AliasNotFound, Details{
		Message:    `connection "prod" not found`,
		Alias:      "prod",
		Candidates: []string{"prod-one", "prod-two"},
	})
	wantJSON := "{\n" +
		"  \"ok\": false,\n" +
		"  \"error\": \"alias_not_found\",\n" +
		"  \"message\": \"connection \\\"prod\\\" not found\",\n" +
		"  \"hint\": \"use sshctl host list --json and retry with an exact alias\",\n" +
		"  \"alias\": \"prod\",\n" +
		"  \"exit\": 255,\n" +
		"  \"candidates\": [\n" +
		"    \"prod-one\",\n" +
		"    \"prod-two\"\n" +
		"  ]\n" +
		"}\n"
	wantNDJSON := "{\"ok\":false,\"error\":\"alias_not_found\",\"message\":\"connection \\\"prod\\\" not found\",\"hint\":\"use sshctl host list --json and retry with an exact alias\",\"alias\":\"prod\",\"exit\":255,\"candidates\":[\"prod-one\",\"prod-two\"]}\n"

	for _, test := range []struct {
		name   string
		format Format
		want   string
	}{
		{name: "indented JSON document", format: JSONDocument, want: wantJSON},
		{name: "compact NDJSON line", format: NDJSON, want: wantNDJSON},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if err := Render(test.format, Streams{Stdout: &stdout, Stderr: &stderr}, failure); err != nil {
				t.Fatal(err)
			}
			if stdout.String() != test.want || stderr.Len() != 0 {
				t.Fatalf("stdout=%q stderr=%q, want stdout=%q", stdout.String(), stderr.String(), test.want)
			}
		})
	}

	transfer := Classify(TransferLocalRead, Details{Message: "open artifact: file does not exist"})
	transferDocument := struct {
		OK bool `json:"ok"`
		TransferMetadata
		Alias     string `json:"alias"`
		BytesSent int64  `json:"bytes_sent"`
		Integrity string `json:"integrity"`
		Atomic    bool   `json:"atomic"`
		Resume    string `json:"resume"`
	}{
		OK: false, TransferMetadata: transfer.TransferMetadata(), Alias: "transfer",
		BytesSent: 0, Integrity: "not_checked", Atomic: false, Resume: "unsupported",
	}
	var stdout, stderr bytes.Buffer
	if err := RenderFailure(JSONDocument, Streams{Stdout: &stdout, Stderr: &stderr}, transferDocument); err != nil {
		t.Fatal(err)
	}
	wantTransfer := "{\n" +
		"  \"ok\": false,\n" +
		"  \"error\": \"local_read_failed\",\n" +
		"  \"message\": \"open artifact: file does not exist\",\n" +
		"  \"hint\": \"verify the local path and read permissions\",\n" +
		"  \"exit\": 1,\n" +
		"  \"stage\": \"local_read\",\n" +
		"  \"alias\": \"transfer\",\n" +
		"  \"bytes_sent\": 0,\n" +
		"  \"integrity\": \"not_checked\",\n" +
		"  \"atomic\": false,\n" +
		"  \"resume\": \"unsupported\"\n" +
		"}\n"
	if stdout.String() != wantTransfer || stderr.Len() != 0 {
		t.Fatalf("transfer stdout=%q stderr=%q, want stdout=%q", stdout.String(), stderr.String(), wantTransfer)
	}
}

func TestConcreteHumanFailureRenderersPreserveLayoutsAndPlacement(t *testing.T) {
	t.Parallel()

	t.Run("raw flag help", func(t *testing.T) {
		t.Parallel()
		var stdout, stderr bytes.Buffer
		if err := RenderFlagHelp(Streams{Stdout: &stdout, Stderr: &stderr}, "Usage of login:\n  -email string\n"); err != nil {
			t.Fatal(err)
		}
		if stdout.Len() != 0 || stderr.String() != "Usage of login:\n  -email string\n" {
			t.Fatalf("flag help stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	})

	t.Run("run", func(t *testing.T) {
		t.Parallel()
		var stdout, stderr bytes.Buffer
		err := RenderRunFailure(Streams{Stdout: &stdout, Stderr: &stderr}, RunFailureView{
			Plan: true, Alias: "requested", ResolvedAlias: "resolved", Exit: 7,
			RemoteCommand: "false", Script: "script.sh", Interpreter: "sh",
			InputBytes: 4, ScriptSHA256: "digest", Mode: "script", Transport: "ssh_stdin",
			Preflight: "failed", Risk: "low", LatencyMS: 3,
			Error: "remote_script_failed", Message: "remote script exited non-zero",
			Hint: "inspect stderr", Stage: "remote_execution",
			Stdout: "safe\n",
		})
		if err != nil {
			t.Fatal(err)
		}
		want := "plan=1\nok=0\nalias=requested\nresolved_alias=resolved\nexit=7\n" +
			"remote_command=false\nscript=script.sh\ninterpreter=sh\nstdin_bytes=4\n" +
			"script_sha256=digest\nmode=script\ntransport=ssh_stdin\npreflight=failed\nrisk=low\n" +
			"latency_ms=3\nerror=remote_script_failed\nmessage=remote script exited non-zero\n" +
			"hint=inspect stderr\nstage=remote_execution\nstdout=safe\\n\n"
		if stdout.String() != want || stderr.Len() != 0 {
			t.Fatalf("run stdout=%q stderr=%q, want stdout=%q", stdout.String(), stderr.String(), want)
		}
	})

	t.Run("check", func(t *testing.T) {
		t.Parallel()
		var stdout, stderr bytes.Buffer
		err := RenderCheckFailure(Streams{Stdout: &stdout, Stderr: &stderr}, CheckFailureView{
			Alias: "host", User: "root", Host: "192.0.2.1", Port: 22,
			Address: "root@192.0.2.1:22", LatencyMS: 4,
			Error: "dial_refused", Message: "connection refused", Hint: "check sshd", Stage: "dial",
		})
		if err != nil {
			t.Fatal(err)
		}
		want := "ok=0\nalias=host\nuser=root\nhost=192.0.2.1\nport=22\n" +
			"address=root@192.0.2.1:22\nlatency_ms=4\nerror=dial_refused\n" +
			"message=connection refused\nhint=check sshd\nstage=dial\n"
		if stdout.String() != want || stderr.Len() != 0 {
			t.Fatalf("check stdout=%q stderr=%q, want stdout=%q", stdout.String(), stderr.String(), want)
		}
	})

	t.Run("doctor", func(t *testing.T) {
		t.Parallel()
		var stdout, stderr bytes.Buffer
		err := RenderDoctorFailure(Streams{Stdout: &stdout, Stderr: &stderr}, DoctorFailureView{
			Vault: "present", Sync: "configured", LocalVault: "local_ahead", RemoteVault: "cached_behind",
			Pending: true, Hosts: 2, Redirects: 1, Reuse: "on",
			Alias: "old", ResolvedAlias: "new", Candidates: []string{"one"},
			MergeConflicts: []DoctorMergeConflict{{Kind: "host", Name: "prod", Winner: "remote"}},
			Check:          &DoctorCheckView{OK: false, Hostname: "remote", Uname: "Linux", LatencyMS: 5},
			Deep:           map[string]string{"probe": "failed"},
			Error:          "internal", Message: "doctor failed", Hint: "retry", Stage: "diagnose", LatencyMS: 6,
		})
		if err != nil {
			t.Fatal(err)
		}
		want := "ok=0\nvault=present\nsync=configured\nlocal_vault_state=local_ahead\n" +
			"remote_vault_state=cached_behind\npending_changes=1\nhosts=2\nredirects=1\nreuse=on\n" +
			"alias=old\nresolved_alias=new\ncandidate=one\nmerge_conflict=host:prod:remote\n" +
			"check_ok=0\nhostname=remote\nuname=Linux\ncheck_latency_ms=5\n" +
			"deep_probe=failed\nerror=internal\nmessage=doctor failed\nhint=retry\nstage=diagnose\nlatency_ms=6\n"
		if stdout.String() != want || stderr.Len() != 0 {
			t.Fatalf("doctor stdout=%q stderr=%q, want stdout=%q", stdout.String(), stderr.String(), want)
		}
	})

	t.Run("map", func(t *testing.T) {
		t.Parallel()
		var stdout, stderr bytes.Buffer
		err := RenderMapFailure(Streams{Stdout: &stdout, Stderr: &stderr}, []MapResultView{
			{OK: true, Alias: "ok", Exit: 0, LatencyMS: 1, Stdout: "success\n"},
			{Alias: "bad", Script: "script.sh", Exit: 7, LatencyMS: 2, Stderr: "got abc", SensitiveValues: []string{"abc"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		wantStdout := "ok\tok\texit=0\tlatency_ms=1\nsuccess\n" +
			"bad/script.sh\tfail\texit=7\tlatency_ms=2\terror=exit_7\n" +
			"summary\tok=1\tfail=1\ttotal=2\n"
		if stdout.String() != wantStdout || stderr.String() != "got ***\n" {
			t.Fatalf("map stdout=%q stderr=%q, want stdout=%q stderr=%q", stdout.String(), stderr.String(), wantStdout, "got ***\\n")
		}
	})
}

func TestMachineContractHostHumanRendering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		kind    Kind
		details Details
		want    string
	}{
		{
			name: "verification",
			kind: HostVerificationFailed,
			details: Details{
				Message:           "candidate host failed SSH verification; vault was not changed",
				Alias:             "candidate",
				VerificationError: "auth_failed",
			},
			want: "ssm: error=verification_failed alias=candidate\n" +
				"Error: candidate host failed SSH verification; vault was not changed\n" +
				"ssm: verification_error=auth_failed\n",
		},
		{
			name: "push",
			kind: HostPushFailed,
			details: Details{
				Message: "push rejected",
				Alias:   "candidate",
			},
			want: "ssm: error=sync_push_failed alias=candidate\n" +
				"Error: push rejected\n" +
				"ssm: hint=local change remains pending; fix sync and retry sshctl push\n",
		},
		{
			name: "map no targets",
			kind: MapNoTargets,
			details: Details{
				Message: "no aliases matched the requested map targets",
				Alias:   "prod-*",
			},
			want: "sshctl map: no targets matched\n",
		},
		{
			name: "run arguments",
			kind: InvalidRunArguments,
			details: Details{
				Cause: errors.New("unknown run option"),
				Alias: "prod",
				Tool:  "sshctl",
			},
			want: "sshctl: error=invalid_arguments alias=prod\n" +
				"sshctl: unknown run option\n",
		},
		{
			name: "panic",
			kind: PanicFailure,
			details: Details{
				Message:  "boom",
				Version:  "1.2.3",
				Platform: "linux/amd64",
				Stack:    "goroutine 1 [running]:\nmain.main()",
			},
			want: "\n\x1b[1;31mssm crashed!\x1b[0m\n\n" +
				"Version: 1.2.3\n" +
				"OS:      linux/amd64\n" +
				"Error:   boom\n\n" +
				"Stack trace:\n" +
				"goroutine 1 [running]:\nmain.main()\n\n" +
				"Please include the info above when reporting this issue.\n",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if err := Render(Human, Streams{Stdout: &stdout, Stderr: &stderr}, Classify(test.kind, test.details)); err != nil {
				t.Fatal(err)
			}
			if stdout.Len() != 0 || stderr.String() != test.want {
				t.Fatalf("stdout=%q stderr=%q, want stderr=%q", stdout.String(), stderr.String(), test.want)
			}
		})
	}
}

func TestLegacyHumanFailureBytesRemainStable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		failure    Failure
		wantStdout string
		wantStderr string
	}{
		{
			name: "usage stays on stdout",
			failure: Classify(GenericFailure, Details{
				Message: "remove requires a name", Tool: "legacy_usage", Script: "remove",
			}),
			wantStdout: "Usage: ssm remove <name>\n",
		},
		{
			name: "legacy connection miss stays on stdout",
			failure: Classify(GenericFailure, Details{
				Message: `connection "missing" not found`, Alias: "missing",
				Tool: "legacy_not_found", Script: "connection",
			}),
			wantStdout: "Connection \"missing\" not found.\n",
		},
		{
			name: "legacy unknown command keeps two lines",
			failure: Classify(GenericFailure, Details{
				Message: `unknown command "bad"`, Alias: "bad",
				Tool: "legacy_unknown_command", Script: "ssm",
			}),
			wantStdout: "Unknown command: bad\nUsage: ssm [host|remove|list|keys|exec|put|get|import-json|server|update|login|register|push|pull|pull-if-changed|remote-hash|logout]\n",
		},
		{
			name: "logout stays message-only on stderr",
			failure: Classify(GenericFailure, Details{
				Cause: errors.New("missing cloud config"), Tool: "legacy_message", Script: "logout",
			}),
			wantStderr: "Not logged in.\n",
		},
		{
			name: "doctor option stays before help on stderr",
			failure: Classify(InvalidSSHCTLArguments, Details{
				Message: "unknown doctor option", Alias: "--bad", Tool: "doctor_unknown_option",
			}),
			wantStderr: "sshctl doctor: unknown option --bad\n",
		},
		{
			name:    "import usage remains appended",
			failure: Classify(ImportArgumentsInvalid, Details{Cause: errors.New("choose one mode")}),
			wantStderr: "ssm: error=invalid_arguments\n" +
				"Error: choose one mode\n" +
				"ssm: hint=use exactly one of --merge or --replace --yes\n" +
				"Usage: ssm import-json <path> (--merge | --replace --yes) [--manifest <path>] [--expect-count <n>] [--json]\n",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if err := Render(Human, Streams{Stdout: &stdout, Stderr: &stderr}, test.failure); err != nil {
				t.Fatal(err)
			}
			if stdout.String() != test.wantStdout || stderr.String() != test.wantStderr {
				t.Fatalf("stdout=%q stderr=%q, want stdout=%q stderr=%q", stdout.String(), stderr.String(), test.wantStdout, test.wantStderr)
			}
		})
	}
}

func TestMachineContractCheckClassification(t *testing.T) {
	t.Parallel()

	runFailure := Classify(RemoteCommandFailed, Details{
		Message: "remote command exited non-zero",
		Alias:   "prod",
		Exit:    23,
	})
	got := ClassifyCheck(runFailure, "remote stderr\n")
	if got.Error != "remote_failed" || got.Stage != "remote_execution" || got.Exit != 23 ||
		got.Hint != "remote stderr; inspect stdout/stderr; SSH transport succeeded" {
		t.Fatalf("check failure = %+v", got)
	}
}

func TestMachineContractHostKeyContext(t *testing.T) {
	t.Parallel()

	connectionFailure := Classify(DialRefused, Details{
		Message: "connection refused",
		Alias:   "host-key",
	})
	got := ClassifyHostKeyOperation(NewClassifiedError(connectionFailure))
	if got.Error != "dial_refused" || got.Stage != "host_key" || got.Exit != 1 ||
		got.Hint != "sshd not listening or wrong port; not an ssm quote bug" {
		t.Fatalf("host-key failure = %+v", got)
	}

	var stdout, stderr bytes.Buffer
	if err := Render(Human, Streams{Stdout: &stdout, Stderr: &stderr}, got); err != nil {
		t.Fatal(err)
	}
	want := "ssm: error=dial_refused\n" +
		"Error: connection refused\n" +
		"ssm: hint=sshd not listening or wrong port; not an ssm quote bug\n"
	if stdout.Len() != 0 || stderr.String() != want {
		t.Fatalf("stdout=%q stderr=%q, want stderr=%q", stdout.String(), stderr.String(), want)
	}
}

func TestMachineContractTransferContext(t *testing.T) {
	t.Parallel()

	carried := Classify(ResumePartialMismatch, Details{Message: "partial mismatch"})
	got := ClassifyTransferOperation(errors.New("partial mismatch"), SSHContext{
		Alias: "transfer", Host: "192.0.2.1", Port: 22,
	}, carried)
	if got.Error != carried.Error || got.Stage != carried.Stage || got.Hint != carried.Hint || got.Exit != carried.Exit {
		t.Fatalf("carried transfer failure = %+v, want %+v", got, carried)
	}

	sessionCarried := Classify(TransferSessionOpenFailed, Details{Message: "session rejected"})
	session := ClassifyTransferOperation(errors.New("ssh: rejected: fixture session rejected"), SSHContext{
		Alias: "transfer", Host: "192.0.2.1", Port: 22,
	}, sessionCarried)
	if session.Error != sessionCarried.Error || session.Stage != sessionCarried.Stage ||
		session.Hint != sessionCarried.Hint || session.Exit != ExitConnectionFailed ||
		ProcessExit(session) != ExitConnectionFailed {
		t.Fatalf("carried session transfer failure = %+v", session)
	}

	permissionCarried := Classify(TransferRemotePermissionsFailed, Details{Message: "permission denied"})
	permission := ClassifyTransferOperation(errors.New("remote write: permission denied"), SSHContext{
		Alias: "transfer", Host: "192.0.2.1", Port: 22,
	}, permissionCarried)
	if permission.Error != permissionCarried.Error || permission.Stage != permissionCarried.Stage ||
		permission.Hint != permissionCarried.Hint || permission.Exit != ExitConnectionFailed ||
		ProcessExit(permission) != ExitConnectionFailed {
		t.Fatalf("carried permission transfer failure = %+v", permission)
	}

	fallback := ClassifyTransferOperation(errors.New("remote tar failed"), SSHContext{
		Alias: "transfer", Host: "192.0.2.1", Port: 22,
	}, Failure{})
	if fallback.Error != "internal" || fallback.Stage != "remote_write" || fallback.Exit != 1 || fallback.Alias != "transfer" {
		t.Fatalf("transfer fallback = %+v", fallback)
	}

	resolvedDial := NewClassifiedError(Classify(DialRefused, Details{
		Message: "connection refused", Alias: "transfer-resolved",
	}))
	download := ClassifyDownload(resolvedDial, SSHContext{
		Alias: "transfer", ResolvedAlias: "transfer-resolved", Host: "192.0.2.1", Port: 22,
	})
	if download.Error != "dial_refused" || download.Stage != "dial" || download.Exit != 255 || download.Alias != "transfer" {
		t.Fatalf("download context = %+v", download)
	}
	var stdout, stderr bytes.Buffer
	if err := Render(Human, Streams{Stdout: &stdout, Stderr: &stderr}, download); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), " alias=transfer-resolved") ||
		strings.Contains(stderr.String(), " stage=") {
		t.Fatalf("download human context stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestMachineContractRunExecutionContext(t *testing.T) {
	t.Parallel()

	marker := InterpreterNotFoundDiagnostic("bash")
	if marker != "ssm: error=interpreter_not_found interpreter=bash" {
		t.Fatalf("interpreter marker = %q", marker)
	}
	if !IsInterpreterNotFoundDiagnostic("prefix\n" + marker + "\nsuffix") {
		t.Fatal("interpreter marker was not detected")
	}
	cause := errors.New("remote process exited")
	tests := []struct {
		name    string
		context RunExecutionContext
		code    string
		stage   string
		hint    string
	}{
		{
			name: "command failure",
			context: RunExecutionContext{
				Cause: cause, Exit: 23, Alias: "run",
			},
			code: CodeRemote, stage: "remote_execution",
			hint: "inspect stdout/stderr; SSH transport succeeded",
		},
		{
			name: "captured interpreter marker",
			context: RunExecutionContext{
				Cause: cause, Exit: 127, Alias: "run", HasInput: true, Capture: true,
				Stderr: marker, Script: "script.sh", Interpreter: "bash",
			},
			code: CodeInterpreter, stage: "interpreter",
			hint: `remote shell "bash" is unavailable; retry with --shell sh or install it`,
		},
		{
			name: "captured 127 without marker is script failure",
			context: RunExecutionContext{
				Cause: cause, Exit: 127, Alias: "run", HasInput: true, Capture: true,
				Stderr: "ordinary exit 127", Script: "script.sh", Interpreter: "bash",
			},
			code: CodeRemoteScript, stage: "remote_execution",
			hint: "the script reached the remote interpreter but exited non-zero; inspect stderr",
		},
		{
			name: "uncaptured 127 preserves interpreter classification",
			context: RunExecutionContext{
				Cause: cause, Exit: 127, Alias: "run", HasInput: true,
				Script: "script.sh", Interpreter: "bash",
			},
			code: CodeInterpreter, stage: "interpreter",
			hint: `remote shell "bash" is unavailable; retry with --shell sh or install it`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := ClassifyRunExecution(test.context)
			if got.Error != test.code || got.Stage != test.stage || got.Hint != test.hint ||
				got.Exit != test.context.Exit || got.Alias != test.context.Alias {
				t.Fatalf("run execution classification = %+v", got)
			}
		})
	}
}

func TestMachineContractResultExit(t *testing.T) {
	t.Parallel()

	if got := ResultExit(ResultState{OK: false}); got != 1 {
		t.Fatalf("zero failed result exit = %d, want 1", got)
	}
	if got := ResultExit(ResultState{OK: false, Exit: 255}); got != 255 {
		t.Fatalf("classified failed result exit = %d, want 255", got)
	}
	if got := AggregateResultExit([]ResultState{{OK: true}, {OK: false, Exit: 23}, {OK: false, Exit: 7}}); got != 23 {
		t.Fatalf("aggregate result exit = %d, want first failure 23", got)
	}
	if ConnectionResultExit(true) != 0 || ConnectionResultExit(false) != ExitConnectionFailed {
		t.Fatalf("connection result exits = success %d, failure %d", ConnectionResultExit(true), ConnectionResultExit(false))
	}

	remote255 := Classify(RemoteCommandFailed, Details{
		Message: "remote command exited non-zero",
		Exit:    255,
	})
	if remote255.Error != "remote_failed" || remote255.Stage != "remote_execution" ||
		ExitForError(NewClassifiedError(remote255)) != 255 {
		t.Fatalf("remote exit 255 was reclassified: %+v", remote255)
	}
}

func TestUnknownDialFailurePreservesHistoricalConnectionExit(t *testing.T) {
	t.Parallel()

	windowsDial := errors.New("dial tcp 127.0.0.1:22: connectex: No connection could be made because the target machine actively refused it")
	failure := ClassifySSH(windowsDial, SSHContext{
		Alias: "refused",
		Host:  "127.0.0.1",
		Port:  22,
		Stage: "dial",
	})
	if failure.Error != "internal" || failure.Stage != "dial" || failure.Hint != "" ||
		failure.Exit != ExitConnectionFailed || ProcessExit(failure) != ExitConnectionFailed {
		t.Fatalf("Windows dial classification = %+v, process exit %d", failure, ProcessExit(failure))
	}
	if got := ExitForError(windowsDial); got != ExitConnectionFailed {
		t.Fatalf("Windows dial process exit = %d, want %d", got, ExitConnectionFailed)
	}

	remote255 := Classify(RemoteCommandFailed, Details{
		Message: "remote command exited non-zero",
		Exit:    255,
	})
	if remote255.Error != "remote_failed" || remote255.Stage != "remote_execution" ||
		ProcessExit(remote255) != 255 {
		t.Fatalf("remote exit 255 was inferred as a connection failure: %+v", remote255)
	}
}

func TestMachineContractHasExclusiveFailurePolicyOwnership(t *testing.T) {
	t.Parallel()

	root := filepath.Clean(filepath.Join("..", ".."))
	for path, forbidden := range map[string][]string{
		"internal/ssh/errors.go": {
			"ErrCodeAliasNotFound",
			"ExitConnectionFailed = machinecontract.",
			"type ClassifiedError = machinecontract.",
		},
		"internal/ssh/dirsync.go": {
			"NewRedactingWriter",
		},
		"internal/ssh/filecopy.go": {
			"NewRedactingWriter",
		},
		"internal/ssh/run.go": {
			`fmt.Printf("error=%s`,
			`fmt.Printf("message=%s`,
			`fmt.Printf("hint=%s`,
			`fmt.Printf("stage=%s`,
		},
		"internal/ssh/check.go": {
			`fmt.Printf("error=%s`,
			`fmt.Printf("message=%s`,
			`fmt.Printf("hint=%s`,
			`fmt.Printf("stage=%s`,
		},
		"internal/ssh/doctor.go": {
			`fmt.Printf("error=%s`,
			`fmt.Printf("message=%s`,
			`fmt.Printf("hint=%s`,
			`fmt.Printf("stage=%s`,
		},
		"internal/ssh/map.go": {
			`fmt.Sprintf("exit_%d"`,
			`status = "fail"`,
		},
		"cmd/ssm/machine.go": {
			"type machineErrorOutput",
			"func writeMachineFailure",
			"func writeContractFailure",
		},
		"cmd/ssm/hosts.go": {
			"type hostCLIError",
			"func writeHostVerificationFailure",
			"func writeHostPushFailure",
			"func writeHostCommandError",
		},
		"cmd/ssm/sshctl.go": {
			"func printError",
		},
		"cmd/ssm/connections.go": {
			"os.Exit(machinecontract.ExitConnectionFailed)",
			"ssh.ErrCodeAliasNotFound",
			"WriteHuman(machinecontract.ClassifySSH(err, context))",
			"os.Exit(machinecontract.ExitForError(err))",
			"humanContext := machinecontract.SSHContext",
			"WriteHuman(machinecontract.ClassifySSH(err, humanContext))",
		},
		"cmd/ssm/stream.go": {
			"ssh.ErrCodeAliasNotFound",
		},
	} {
		source, err := os.ReadFile(filepath.Join(root, path)) //nolint:gosec // paths come from the fixed reviewed source allowlist above
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, needle := range forbidden {
			if bytes.Contains(source, []byte(needle)) {
				t.Errorf("%s retains failure-policy residue %q", path, needle)
			}
		}
	}

	for path, required := range map[string]string{
		"internal/ssh/run.go":    "machinecontract.RenderRunFailure",
		"internal/ssh/check.go":  "machinecontract.RenderCheckFailure",
		"internal/ssh/doctor.go": "machinecontract.RenderDoctorFailure",
		"internal/ssh/map.go":    "machinecontract.RenderMapFailure",
	} {
		source, err := os.ReadFile(filepath.Join(root, path)) //nolint:gosec // paths come from the fixed reviewed source allowlist above
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !bytes.Contains(source, []byte(required)) {
			t.Errorf("%s does not delegate human failure rendering to %q", path, required)
		}
	}

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if relative == filepath.Join("internal", "machinecontract") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		source, err := os.ReadFile(path) //nolint:gosec // WalkDir is constrained to the repository root
		if err != nil {
			return err
		}
		if bytes.Contains(source, []byte("ssm: error=interpreter_not_found interpreter=")) {
			t.Errorf("%s owns the stable interpreter marker outside machinecontract", relative)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan stable interpreter marker ownership: %v", err)
	}
}
