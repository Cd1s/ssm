package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"ssm/internal/config"
	"ssm/internal/update"
)

var (
	masterPass     string
	masterPassFile string
	offlineMode    bool
	unlockedVault  *config.Vault
	version        = "1.4.4"
)

func main() {
	machineJSON = hasJSONFlagBeforeDash(os.Args[1:])
	if err := update.CleanupPreviousExecutable(); err != nil {
		failure := classifyUpdateFailure(err, "update_failed", "update_recovery")
		writeCLIErrorStage(failure.Error, "startup executable recovery failed: "+failure.Message, failure.Hint, failure.Stage, failure.Exit)
		os.Exit(failure.Exit)
	}
	defer func() {
		if r := recover(); r != nil {
			if machineJSON {
				writeMachineError("internal", "ssm crashed", "retry with SSM_TRACE=1 outside machine mode and report the failure", "", 1, nil)
				os.Exit(1)
			}
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			fmt.Fprintf(os.Stderr, "\n\033[1;31mssm crashed!\033[0m\n\n")
			fmt.Fprintf(os.Stderr, "Version: %s\n", version)
			fmt.Fprintf(os.Stderr, "OS:      %s/%s\n", runtime.GOOS, runtime.GOARCH)
			fmt.Fprintf(os.Stderr, "Error:   %s\n\n", redactString(fmt.Sprint(r)))
			fmt.Fprintf(os.Stderr, "Stack trace:\n%s\n\n", buf[:n])
			fmt.Fprintf(os.Stderr, "Please include the info above when reporting this issue.\n")
			os.Exit(1)
		}
	}()

	if version == "dev" {
		config.EnableDebug()
	}
	if !isInformationalInvocation(os.Args[1:]) {
		checkUpdate()
	}

	if strings.EqualFold(filepath.Base(os.Args[0]), "sshctl") {
		runSSHCTL(os.Args[1:])
		return
	}

	args, err := parseGlobalArgs(os.Args[1:])
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	if len(args) < 1 {
		writeCLIError("missing_command", "command required", "use ssm --help or sshctl --help", 2)
		os.Exit(2)
	}

	switch args[0] {
	case "--version", "-v":
		fmt.Printf("ssm %s\n", version)
		return
	case "--help", "-h", "help":
		fmt.Printf("ssm %s - SSH connection manager\n", version)
		fmt.Print(`
Usage:
  sshctl --json status          preferred machine-readable discovery
  sshctl run <alias> --argv ... fast one-shot literal command
  sshctl run <alias> --stream   persistent NDJSON argv stream
  sshctl request --file <json>  typed dynamic/complex operation
  ssm host ...         host list/show/add/update/upsert/remove
  ssm list [--json]    list all connections
  ssm exec/run <name> ...   remote command (--json/--plan/--secret NAME=@file/-s/-f)
  ssm plan <name> ...       dry-run: show remote_command + risk (no dial)
  ssm map <targets> ...     parallel multi-host/script fleet
  ssm put/get               file or directory tree
  ssm check/doctor          triage / deep health
  ssm redirect list|set|rm  alias soft-links after migration
  ssm keys             list saved SSH keys
  ssm keys remove <n>  remove a SSH key
  ssm update                  update only within the installed major version
  ssm update --major [--yes]  review/authorize a provenance-verified major migration
  ssm import-json <path> (--merge | --replace --yes) import reviewed JSON connections
  ssm server           run the headless encrypted sync server

Cloud (optional):
  ssm login            authenticate with sync server
  ssm register         create a sync account
  ssm push --only <transaction-id>  publish one reviewed mutation
  ssm push --all       deliberately publish all pending mutations
  ssm pull             download encrypted vault
  ssm pull-if-changed  download encrypted vault only if remote changed
  ssm remote-hash      print remote encrypted vault hash
  ssm logout           remove sync credentials

`)
		return
	case "update":
		runUpdate(args[1:])
		return
	case "host", "hosts":
		machineJSON = machineJSON || hasJSONFlagBeforeDash(args[1:])
		unlock()
		runHostCommand(args[1:])
	case "remove":
		if len(args) < 2 {
			fmt.Println("Usage: ssm remove <name>")
			os.Exit(1)
		}
		unlock()
		runRemove(args[1])
	case "keys":
		unlock()
		if len(args) >= 2 {
			switch args[1] {
			case "remove":
				if len(args) < 3 {
					fmt.Println("Usage: ssm keys remove <name>")
					os.Exit(1)
				}
				runKeysRemove(args[2])
			default:
				fmt.Printf("Unknown keys command: %s\n", args[1])
				os.Exit(1)
			}
		} else {
			runKeysList()
		}
	case "list", "ls":
		jsonFlag := len(args) > 1 && args[1] == "--json"
		unlock()
		runList(jsonFlag)
	case "exec", "run":
		if len(args) < 2 {
			fmt.Println("Usage: ssm exec <name> <command...>")
			os.Exit(1)
		}
		unlock()
		spec, err := parseRemoteRunArgs(args[2:])
		if err != nil {
			exitRemoteRunArgError("ssm", args[1], args[2:], err)
		}
		if len(spec.Scripts) > 1 {
			runMap([]string{args[1]}, spec)
			return
		}
		runExecSpec(args[1], spec)
	case "plan":
		if len(args) < 2 {
			fmt.Println("Usage: ssm plan <name> <command...>")
			os.Exit(1)
		}
		unlock()
		spec, err := parseRemoteRunArgs(args[2:])
		if err != nil {
			exitRemoteRunArgError("ssm", args[1], args[2:], err)
		}
		spec.Plan = true
		runExecSpec(args[1], spec)
	case "map":
		if len(args) < 2 {
			fmt.Println("Usage: ssm map <targets> [options] <command...>")
			os.Exit(1)
		}
		unlock()
		runSSHCTLMap(args[1:])
	case "check":
		jsonFlag := false
		if len(args) < 2 {
			fmt.Println("Usage: ssm check <name> [--json]")
			os.Exit(1)
		}
		if len(args) >= 3 {
			if args[2] != "--json" || len(args) > 3 {
				fmt.Println("Usage: ssm check <name> [--json]")
				os.Exit(1)
			}
			jsonFlag = true
		}
		unlock()
		runCheck(args[1], jsonFlag)
	case "doctor":
		unlock()
		runSSHCTLDoctor(args[1:])
	case "redirect", "alias-link":
		// redirects are plaintext config; still unlock so path is consistent
		unlock()
		runRedirect(args[1:])
	case "put":
		machineJSON = machineJSON || hasJSONFlagBeforeDash(args[1:])
		unlock()
		runPutArgs(args[1:])
	case "get":
		if len(args) != 4 {
			fmt.Println("Usage: ssm get <name> <remote> <local>")
			os.Exit(1)
		}
		unlock()
		runGet(args[1], args[2], args[3])
	case "import-json":
		machineJSON = machineJSON || hasJSONFlagBeforeDash(args[1:])
		unlock()
		runImportJSON(args[1:])
	case "server":
		runServer(args[1:])
	case "register":
		runRegister(args[1:])
	case "login":
		runLogin(args[1:])
	case "logout":
		runLogout()
	case "push":
		runPush(args[1:])
	case "pull":
		runPull()
	case "pull-if-changed":
		runPullIfChanged()
	case "remote-hash":
		runRemoteHash()
	default:
		if machineJSON {
			writeCLIError("unknown_command", fmt.Sprintf("unknown command %q", args[0]), "use ssm --help for available commands", 2)
			os.Exit(2)
		}
		fmt.Printf("Unknown command: %s\n", args[0])
		fmt.Println("Usage: ssm [host|remove|list|keys|exec|put|get|import-json|server|update|login|register|push|pull|pull-if-changed|remote-hash|logout]")
		os.Exit(1)
	}
}

type updateCommandFailure struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Stage   string `json:"stage"`
	Hint    string `json:"hint"`
	Exit    int    `json:"exit"`
}

func parseUpdateArgs(args []string) (major, yes bool, err error) {
	for _, arg := range args {
		switch arg {
		case "--major":
			major = true
		case "--yes":
			yes = true
		default:
			return false, false, fmt.Errorf("unknown update option %q", arg)
		}
	}
	if yes && !major {
		return false, false, fmt.Errorf("--yes is valid only with update --major")
	}
	return major, yes, nil
}

func runUpdate(args []string) {
	major, yes, err := parseUpdateArgs(args)
	if err != nil {
		writeCLIError("invalid_arguments", err.Error(), "use ssm update or ssm update --major [--yes]", 2)
		os.Exit(2)
	}
	if major {
		runMajorUpdate(yes)
		return
	}
	if !machineJSON {
		fmt.Println("Checking for updates...")
	}
	result, err := update.Download(version)
	if err != nil {
		failure := classifyUpdateFailure(err, "update_failed", "update")
		writeCLIErrorStage(failure.Error, failure.Message, failure.Hint, failure.Stage, failure.Exit)
		os.Exit(failure.Exit)
	}
	if result.Installed != "" && !machineJSON {
		fmt.Printf("Updated to %s\n", result.Installed)
	}
	if result.CrossMajorAvailable != "" {
		if machineJSON {
			writeMachineValue(map[string]any{
				"ok": true, "installed": result.Installed,
				"cross_major_available": result.CrossMajorAvailable,
				"migration_required":    true,
			})
		} else {
			fmt.Printf("Major release %s is available; review with ssm update --major.\n", result.CrossMajorAvailable)
		}
	} else if machineJSON {
		writeMachineValue(map[string]any{"ok": true, "installed": result.Installed})
	}
}

func runMajorUpdate(yes bool) {
	review, err := update.ReviewMajor(version, yes, masterPassFile)
	if err != nil {
		failure := migrationFailure(err)
		review.OK = false
		review.Error = failure.Error
		review.Message = failure.Message
		review.Stage = failure.Stage
		review.Hint = failure.Hint
		review.Exit = failure.Exit
		if machineJSON {
			writeMachineValue(review)
		} else {
			if review.Target != "" {
				printMigrationReview(review)
			}
			writeCLIErrorStage(failure.Error, failure.Message, failure.Hint, failure.Stage, failure.Exit)
		}
		os.Exit(failure.Exit)
	}
	if !yes {
		if machineJSON {
			writeMachineValue(review)
		} else {
			printMigrationReview(review)
		}
		return
	}

	reviewRendered := false
	var finishMachineReview func(bool, updateCommandFailure) error
	err = update.DownloadVersionBeforeReplace(review.Target, false, func() error {
		reviewRendered = true
		if machineJSON {
			var beginErr error
			finishMachineReview, beginErr = beginMigrationJSON(review)
			return beginErr
		}
		printMigrationReviewBeforeReplacement(review)
		return nil
	})
	if err != nil {
		failure := migrationFailure(err)
		switch {
		case !reviewRendered:
			review.OK = false
			review.Error = failure.Error
			review.Message = failure.Message
			review.Stage = failure.Stage
			review.Hint = failure.Hint
			review.Exit = failure.Exit
			if machineJSON {
				writeMachineValue(review)
			} else {
				printMigrationReview(review)
				writeCLIErrorStage(failure.Error, failure.Message, failure.Hint, failure.Stage, failure.Exit)
			}
		case machineJSON:
			if finishMachineReview != nil {
				_ = finishMachineReview(false, failure)
			}
		default:
			fmt.Println("Installed: false")
			writeCLIErrorStage(failure.Error, failure.Message, failure.Hint, failure.Stage, failure.Exit)
		}
		os.Exit(failure.Exit)
	}
	if machineJSON {
		if err := finishMachineReview(true, updateCommandFailure{}); err != nil {
			os.Exit(1)
		}
	} else {
		fmt.Println("Installed: true")
	}
}

func migrationFailure(err error) updateCommandFailure {
	return classifyUpdateFailure(err, "update_migration_failed", "update_migration")
}

func classifyUpdateFailure(err error, code, stage string) updateCommandFailure {
	failure := updateCommandFailure{
		Error:   "update_migration_failed",
		Message: redactError(err),
		Stage:   stage,
		Hint:    "the v1 executable and encrypted state were preserved; resolve the reported review or trust failure and retry",
		Exit:    1,
	}
	failure.Error = code
	if update.IsRecoveryRequired(err) {
		failure.Error = "update_recovery_required"
		failure.Stage = "update_recovery"
		failure.Hint = "authenticated original evidence was preserved but canonical restoration remains required; rerun this exact executable path to recover"
	} else if update.IsRecoveryBlocked(err) {
		failure.Error = "update_recovery_failed"
		failure.Stage = "update_recovery"
		failure.Hint = "executable recovery evidence could not be authenticated or cleared; preserve the installation directory and obtain reviewed recovery"
	}
	return failure
}

func printMigrationReview(review update.MigrationReview) {
	printMigrationReviewBeforeReplacement(review)
	fmt.Printf("Installed: %t\n", review.Installed)
}

func printMigrationReviewBeforeReplacement(review update.MigrationReview) {
	fmt.Printf("Major update review: %s -> %s\n", review.Current, review.Target)
	fmt.Println("Authorization:", review.AuthorizationState)
	fmt.Printf("Release notes:\n%s\n", review.ReleaseNotes)
	fmt.Println("Approved breaking changes:")
	for _, change := range review.BreakingChanges {
		fmt.Printf("  %s: %s\n", change.ID, change.Description)
	}
	fmt.Println("Automated preflight:")
	for _, check := range review.AutomatedChecks {
		fmt.Printf("  %s: %s - %s\n", check.ID, check.Status, check.Description)
		if check.Remediation != "" {
			fmt.Printf("    remediation: %s\n", check.Remediation)
		}
	}
	fmt.Println("Manual external-consumer checks:")
	for _, check := range review.ManualChecks {
		fmt.Printf("  %s: %s - %s\n", check.ID, check.Status, check.Description)
	}
	fmt.Printf("Rollback: %s\n", review.RollbackGuidance)
	fmt.Printf("Remediation: %s\n", review.Remediation)
}

func beginMigrationJSON(review update.MigrationReview) (func(bool, updateCommandFailure) error, error) {
	preamble := struct {
		Current            string                  `json:"current"`
		Target             string                  `json:"target"`
		ReleaseName        string                  `json:"release_name,omitempty"`
		ReleaseNotes       string                  `json:"release_notes"`
		BreakingChanges    []update.BreakingChange `json:"breaking_changes"`
		AutomatedChecks    []update.MigrationCheck `json:"automated_checks"`
		ManualChecks       []update.MigrationCheck `json:"manual_consumer_checks"`
		Authorized         bool                    `json:"authorized"`
		AuthorizationState string                  `json:"authorization_state"`
		RollbackGuidance   string                  `json:"rollback_guidance"`
		Remediation        string                  `json:"remediation"`
	}{
		Current: review.Current, Target: review.Target, ReleaseName: review.ReleaseName,
		ReleaseNotes: review.ReleaseNotes, BreakingChanges: review.BreakingChanges,
		AutomatedChecks: review.AutomatedChecks, ManualChecks: review.ManualChecks,
		Authorized: review.Authorized, AuthorizationState: review.AuthorizationState,
		RollbackGuidance: review.RollbackGuidance, Remediation: review.Remediation,
	}
	prefix, err := json.Marshal(preamble)
	if err != nil {
		return nil, err
	}
	if len(prefix) < 2 || prefix[0] != '{' || prefix[len(prefix)-1] != '}' {
		return nil, fmt.Errorf("migration review must be a JSON object")
	}
	if _, err := os.Stdout.Write(prefix[:len(prefix)-1]); err != nil {
		return nil, err
	}
	finished := false
	return func(ok bool, failure updateCommandFailure) error {
		if finished {
			return fmt.Errorf("migration JSON document already finished")
		}
		finished = true
		outcome := map[string]any{"installed": ok, "ok": ok}
		if !ok {
			outcome["error"] = failure.Error
			outcome["message"] = failure.Message
			outcome["stage"] = failure.Stage
			outcome["hint"] = failure.Hint
			outcome["exit"] = failure.Exit
		}
		encoded, err := json.Marshal(outcome)
		if err != nil {
			return err
		}
		if _, err := os.Stdout.Write(append([]byte{','}, encoded[1:]...)); err != nil {
			return err
		}
		_, err = os.Stdout.Write([]byte("\n"))
		return err
	}, nil
}

func isInformationalInvocation(args []string) bool {
	command := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return false
		}
		switch arg {
		case "--help", "-h", "help", "--version", "-v":
			return true
		case "--json", "--offline":
			continue
		case "--master-pass-file":
			i++
			continue
		}
		if strings.HasPrefix(arg, "--master-pass-file=") || strings.HasPrefix(arg, "-") {
			continue
		}
		if command == "" {
			command = arg
		}
	}
	return command == "update"
}

func parseGlobalArgs(args []string) ([]string, error) {
	if masterPassFile == "" {
		masterPassFile = os.Getenv("SSM_MASTER_PASS_FILE")
	}

	out := make([]string, 0, len(args))
	seenCommand := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case !seenCommand && arg == "--json":
			machineJSON = true
		case !seenCommand && arg == "--offline":
			offlineMode = true
		case !seenCommand && arg == "--master-pass-file":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--master-pass-file requires a path")
			}
			masterPassFile = args[i+1]
			i++
		case !seenCommand && strings.HasPrefix(arg, "--master-pass-file="):
			masterPassFile = strings.TrimPrefix(arg, "--master-pass-file=")
			if masterPassFile == "" {
				return nil, fmt.Errorf("--master-pass-file requires a path")
			}
		default:
			out = append(out, arg)
			if !seenCommand && (arg == "--version" || arg == "-v" || arg == "--help" || arg == "-h" || arg == "help" || !strings.HasPrefix(arg, "-")) {
				seenCommand = true
			}
		}
	}
	return out, nil
}

func checkUpdate() {
	settings := config.LoadSettings()
	if settings.AutoUpdate && version != "dev" {
		if err := update.Auto(version); update.IsRecoveryRequired(err) || update.IsRecoveryBlocked(err) {
			failure := classifyUpdateFailure(err, "update_failed", "update")
			writeCLIErrorStage(failure.Error, failure.Message, failure.Hint, failure.Stage, failure.Exit)
			os.Exit(failure.Exit)
		}
	}
}

func unlock() {
	if masterPassFile != "" {
		data, err := os.ReadFile(masterPassFile)
		if err != nil {
			writeCLIError("master_pass_file_error", fmt.Sprintf("master pass file: %v", err), "use --master-pass-file or SSM_MASTER_PASS_FILE with a readable private file", 1)
			os.Exit(1)
		}
		pass := strings.TrimRight(string(data), "\r\n")
		if pass == "" {
			writeCLIError("master_pass_file_error", "master pass file is empty", "write the vault passphrase to the configured file", 1)
			os.Exit(1)
		}

		if !config.Exists() {
			masterPass = pass
			unlockedVault = &config.Vault{}
			if err := config.Save(unlockedVault, masterPass); err != nil {
				unlockedVault = nil
				writeCLIError("vault_error", err.Error(), "verify configuration directory permissions", 1)
				os.Exit(1)
			}
			return
		}

		v, err := config.Load(pass)
		if err != nil {
			writeCLIError("vault_unlock_failed", err.Error(), "verify the master pass file belongs to this encrypted vault", 1)
			os.Exit(1)
		}
		masterPass = pass
		unlockedVault = v
		return
	}

	if !config.Exists() {
		writeCLIError("master_pass_file_required", "vault does not exist", "provide --master-pass-file or SSM_MASTER_PASS_FILE to create it non-interactively", 2)
		os.Exit(2)
	}

	settings := config.LoadSettings()
	if settings.PasswordCache == "session" {
		if cached := config.GetCachedPassword(); cached != "" {
			if v, err := config.Load(cached); err == nil {
				masterPass = cached
				unlockedVault = v
				return
			}
			config.ClearPasswordCache()
		}
	}

	writeCLIError("master_pass_file_required", "vault passphrase is required", "provide --master-pass-file or SSM_MASTER_PASS_FILE; credentials are never accepted inline", 2)
	os.Exit(2)
}

// loadVault consumes the vault already decrypted by unlock. Commands used to
// decrypt once in unlock and immediately decrypt the same unchanged file
// again. Consuming the snapshot avoids that duplicate Argon2 operation while
// ensuring a later load in the same process observes any intervening save.
func loadVault() (*config.Vault, error) {
	if unlockedVault != nil {
		v := unlockedVault
		unlockedVault = nil
		return v, nil
	}
	v, err := config.Load(masterPass)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func invalidateVaultCache() {
	unlockedVault = nil
}
