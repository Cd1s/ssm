package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
	"ssm/internal/update"
)

var (
	masterPass     string
	masterPassFile string
	offlineMode    bool
	unlockedVault  *config.Vault
	streamMachine  bool
	version        = "2.0.1"
)

func isSSHCTLInvocation(path string) bool {
	base := filepath.Base(strings.ReplaceAll(path, `\`, "/"))
	if strings.EqualFold(filepath.Ext(base), ".exe") {
		base = strings.TrimSuffix(base, filepath.Ext(base))
	}
	return strings.EqualFold(base, "sshctl")
}

// startupOutputMode selects only the renderer needed before command dispatch.
// It deliberately avoids the stateful global parser so executable recovery
// cannot cause config, vault, or network work before a startup failure is
// rendered.
func startupOutputMode(executable string, rawArgs []string) (jsonMode, streamMode bool) {
	jsonMode = hasJSONFlagBeforeDash(rawArgs)
	if !isSSHCTLInvocation(executable) {
		return jsonMode, false
	}

	args := make([]string, 0, len(rawArgs))
	seenCommand := false
	for i := 0; i < len(rawArgs); i++ {
		arg := rawArgs[i]
		switch {
		case !seenCommand && (arg == "--json" || arg == "--offline"):
			continue
		case !seenCommand && arg == "--master-pass-file":
			if i+1 < len(rawArgs) {
				i++
			}
			continue
		case !seenCommand && strings.HasPrefix(arg, "--master-pass-file="):
			continue
		default:
			args = append(args, arg)
			if !seenCommand && (arg == "--version" || arg == "-v" ||
				arg == "--help" || arg == "-h" || arg == "help" ||
				!strings.HasPrefix(arg, "-")) {
				seenCommand = true
			}
		}
	}
	if len(args) == 0 {
		return jsonMode, false
	}
	if _, _, help := sshctlHelpRequest(args); help {
		return jsonMode, false
	}

	var runArgs []string
	switch args[0] {
	case "run", "exec":
		if runStreamRequested(args[1:]) {
			return true, true
		}
		_, parsedRunArgs, err := splitRunAlias(args[1:])
		if err != nil {
			return jsonMode, false
		}
		runArgs = parsedRunArgs
	default:
		if len(args) == 1 {
			return jsonMode, false
		}
		runArgs = args[1:]
	}
	_, streamMode, _ = parseRunStreamArgs(runArgs)
	if streamMode {
		jsonMode = true
	}
	return jsonMode, streamMode
}

func main() {
	rawArgs := os.Args[1:]
	machineJSON, streamMachine = startupOutputMode(os.Args[0], rawArgs)
	if err := update.CleanupPreviousExecutable(); err != nil {
		failure := machinecontract.Classify(
			updateFailureKind(err, machinecontract.UpdateFailed),
			machinecontract.Details{
				Message: fmt.Sprintf("startup executable recovery failed: %v", err),
				Cause:   err,
			},
		)
		if streamMachine {
			os.Exit(writeStreamFailure(os.Stdout, failure))
		}
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	defer func() {
		if r := recover(); r != nil {
			if streamMachine {
				failure := machinecontract.Classify(machinecontract.PanicFailure, machinecontract.Details{Message: "ssm crashed"})
				os.Exit(writeStreamFailure(os.Stdout, failure))
			}
			if machineJSON {
				os.Exit(machinecontract.WriteClassified(true, machinecontract.PanicFailure, machinecontract.Details{Message: "ssm crashed"}))
			}
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			failure := machinecontract.Classify(machinecontract.PanicFailure, machinecontract.Details{
				Message:  fmt.Sprint(r),
				Version:  version,
				Platform: runtime.GOOS + "/" + runtime.GOARCH,
				Stack:    string(buf[:n]),
			})
			_ = machinecontract.WriteHuman(failure)
			os.Exit(machinecontract.ProcessExit(failure))
		}
	}()

	if version == "dev" {
		config.EnableDebug()
	}
	sshctlInvocation := isSSHCTLInvocation(os.Args[0])
	args, err := parseGlobalArgs(rawArgs)
	if err != nil {
		kind := machinecontract.GenericFailure
		if sshctlInvocation {
			kind = machinecontract.InvalidGlobalArguments
		}
		os.Exit(machinecontract.WriteClassified(machineJSON, kind, machinecontract.Details{Cause: err}))
	}
	if !offlineMode && !isInformationalInvocation(rawArgs) {
		if err := checkUpdate(); err != nil {
			failure := machinecontract.Classify(
				updateFailureKind(err, machinecontract.UpdateFailed),
				machinecontract.Details{Cause: err},
			)
			if streamMachine {
				os.Exit(writeStreamFailure(os.Stdout, failure))
			}
			os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
		}
	}

	if sshctlInvocation {
		runSSHCTLParsed(args)
		return
	}

	if len(args) < 1 {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.MissingCommand, machinecontract.Details{Message: "command required"}))
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
  ssm update           update within the installed major version
  ssm update --major [--yes]  review or explicitly authorize a major migration
                       digest and provenance verification are never bypassed
  ssm import-json <path> (--merge | --replace --yes) import reviewed JSON connections
  ssm server           run the headless encrypted sync server

Cloud (optional):
  ssm login            authenticate with sync server
  ssm register         create a sync account
  ssm --json push --only <transaction-id>  publish one reviewed mutation
  ssm --json push --all       publish the invocation-start pending set
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
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
				Message: "remove requires a name", Tool: "legacy_usage", Script: "remove",
			}))
		}
		unlock()
		runRemove(args[1])
	case "keys":
		unlock()
		if len(args) >= 2 {
			switch args[1] {
			case "remove":
				if len(args) < 3 {
					os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
						Message: "keys remove requires a name", Tool: "legacy_usage", Script: "keys_remove",
					}))
				}
				runKeysRemove(args[2])
			default:
				os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
					Message: fmt.Sprintf("unknown keys command %q", args[1]),
					Alias:   args[1],
					Tool:    "legacy_unknown_command",
					Script:  "keys",
				}))
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
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
				Message: "exec requires a name", Tool: "legacy_usage", Script: "exec",
			}))
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
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
				Message: "plan requires a name", Tool: "legacy_usage", Script: "plan",
			}))
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
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
				Message: "map requires targets", Tool: "legacy_usage", Script: "map",
			}))
		}
		unlock()
		runSSHCTLMap(args[1:])
	case "check":
		jsonFlag := false
		if len(args) < 2 {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
				Message: "check requires a name", Tool: "legacy_usage", Script: "check",
			}))
		}
		if len(args) >= 3 {
			if args[2] != "--json" || len(args) > 3 {
				os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
					Message: "invalid check arguments", Tool: "legacy_usage", Script: "check",
				}))
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
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
				Message: "invalid get arguments", Tool: "legacy_usage", Script: "get",
			}))
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
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.UnknownSSMCommand, machinecontract.Details{Message: fmt.Sprintf("unknown command %q", args[0])}))
		}
		os.Exit(machinecontract.WriteClassified(false, machinecontract.GenericFailure, machinecontract.Details{
			Message: fmt.Sprintf("unknown command %q", args[0]),
			Alias:   args[0],
			Tool:    "legacy_unknown_command",
			Script:  "ssm",
		}))
	}
}

func runUpdate(args []string) {
	major := false
	yes := false
	for _, arg := range args {
		switch arg {
		case "--major":
			major = true
		case "--yes":
			yes = true
		default:
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.InvalidGlobalArguments, machinecontract.Details{
				Message: fmt.Sprintf("unknown update option %q", arg),
			}))
		}
	}
	if yes && !major {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.InvalidGlobalArguments, machinecontract.Details{
			Message: "--yes is valid only with update --major",
		}))
	}
	if major {
		review, err := update.ReviewMajor(version, yes, masterPassFile)
		renderFailure := func(cause error) {
			failure := machinecontract.Classify(machinecontract.UpdateMigrationFailed, machinecontract.Details{Cause: cause})
			review.OK = false
			review.Error = failure.Error
			review.Message = failure.Message
			review.Stage = failure.Stage
			review.Hint = failure.Hint
			review.Exit = failure.Exit
			if machineJSON {
				_ = machinecontract.RenderFailure(machinecontract.JSONDocument, machinecontract.Streams{Stdout: os.Stdout, Stderr: os.Stderr}, review)
			} else {
				printMigrationReview(review)
				_ = machinecontract.WriteHuman(failure)
			}
			os.Exit(machinecontract.ProcessExit(failure))
		}
		if err != nil {
			renderFailure(err)
		}
		renderReview := func() error {
			if machineJSON {
				return machinecontract.Render(machinecontract.JSONDocument, machinecontract.Streams{Stdout: os.Stdout, Stderr: os.Stderr}, review)
			}
			printMigrationReview(review)
			return nil
		}
		if !yes {
			if err := renderReview(); err != nil {
				renderFailure(err)
			}
			return
		}
		reviewRendered := false
		var finishMachineReview func(bool, machinecontract.Failure) error
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
			if !reviewRendered {
				renderFailure(err)
			}
			failure := machinecontract.Classify(updateFailureKind(err, machinecontract.UpdateMigrationFailed), machinecontract.Details{Cause: err})
			if machineJSON {
				if finishMachineReview != nil {
					_ = finishMachineReview(false, failure)
				}
			} else {
				fmt.Println("Installed: false")
				_ = machinecontract.WriteHuman(failure)
			}
			os.Exit(machinecontract.ProcessExit(failure))
		}
		if machineJSON {
			if err := finishMachineReview(true, machinecontract.Failure{}); err != nil {
				failure := machinecontract.Classify(machinecontract.UpdateMigrationFailed, machinecontract.Details{Cause: err})
				os.Exit(machinecontract.ProcessExit(failure))
			}
		} else {
			fmt.Println("Installed: true")
		}
		return
	}
	if !machineJSON {
		fmt.Println("Checking for updates...")
	}
	result, err := update.Download(version)
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, updateFailureKind(err, machinecontract.UpdateFailed), machinecontract.Details{Cause: err}))
	}
	if result.Installed != "" && !machineJSON {
		fmt.Printf("Updated to %s\n", result.Installed)
	}
	if result.CrossMajorAvailable != "" {
		if machineJSON {
			_ = machinecontract.WriteJSON(map[string]any{
				"ok": true, "installed": result.Installed,
				"cross_major_available": result.CrossMajorAvailable,
				"migration_required":    true,
			})
		} else {
			fmt.Printf("Major release %s is available; review with ssm update --major.\n", result.CrossMajorAvailable)
		}
	} else if machineJSON {
		_ = machinecontract.WriteJSON(map[string]any{"ok": true, "installed": result.Installed})
	}
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

func beginMigrationJSON(review update.MigrationReview) (func(bool, machinecontract.Failure) error, error) {
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
	stream, err := machinecontract.BeginJSONDocument(machinecontract.Streams{Stdout: os.Stdout, Stderr: os.Stderr}, preamble)
	if err != nil {
		return nil, err
	}
	return func(ok bool, failure machinecontract.Failure) error {
		outcome := map[string]any{"installed": ok, "ok": ok}
		if !ok {
			outcome["error"] = failure.Error
			outcome["message"] = failure.Message
			outcome["stage"] = failure.Stage
			outcome["hint"] = failure.Hint
			outcome["exit"] = failure.Exit
		}
		return stream.Finish(outcome)
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

func updateFailureKind(err error, fallback machinecontract.Kind) machinecontract.Kind {
	if update.IsRecoveryRequired(err) {
		return machinecontract.UpdateRecoveryRequired
	}
	if update.IsRecoveryBlocked(err) {
		return machinecontract.InternalFailure
	}
	return fallback
}

func checkUpdate() error {
	settings := config.LoadSettings()
	if settings.AutoUpdate && version != "dev" {
		if err := update.Auto(version); err != nil {
			if update.IsRecoveryRequired(err) || update.IsRecoveryBlocked(err) {
				return err
			}
		}
	}
	return nil
}

func unlock() {
	failure, failed := unlockVault()
	if failed {
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
}

// unlockVault performs the non-interactive vault initialization without
// choosing a renderer. Normal commands and run --stream render the same
// classified failure through their respective machine-contract framing.
func unlockVault() (machinecontract.Failure, bool) {
	if masterPassFile != "" {
		data, err := os.ReadFile(masterPassFile)
		if err != nil {
			return machinecontract.Classify(machinecontract.MasterPassFileReadFailed, machinecontract.Details{
				Message: fmt.Sprintf("master pass file: %v", err), Cause: err,
			}), true
		}
		pass := strings.TrimRight(string(data), "\r\n")
		if pass == "" {
			return machinecontract.Classify(
				machinecontract.MasterPassFileEmpty,
				machinecontract.Details{Message: "master pass file is empty"},
			), true
		}

		if !config.Exists() {
			masterPass = pass
			unlockedVault = &config.Vault{}
			if err := config.Save(unlockedVault, masterPass); err != nil {
				unlockedVault = nil
				return machinecontract.Classify(machinecontract.VaultCreateFailed, machinecontract.Details{Cause: err}), true
			}
			return machinecontract.Failure{}, false
		}

		v, err := config.Load(pass)
		if err != nil {
			return machinecontract.Classify(machinecontract.VaultUnlockFailed, machinecontract.Details{Cause: err}), true
		}
		masterPass = pass
		unlockedVault = v
		return machinecontract.Failure{}, false
	}

	if !config.Exists() {
		return machinecontract.Classify(
			machinecontract.MasterPassFileRequiredCreate,
			machinecontract.Details{Message: "vault does not exist"},
		), true
	}

	settings := config.LoadSettings()
	if settings.PasswordCache == "session" {
		if cached := config.GetCachedPassword(); cached != "" {
			if v, err := config.Load(cached); err == nil {
				masterPass = cached
				unlockedVault = v
				return machinecontract.Failure{}, false
			}
			config.ClearPasswordCache()
		}
	}

	return machinecontract.Classify(
		machinecontract.MasterPassFileRequiredExisting,
		machinecontract.Details{Message: "vault passphrase is required"},
	), true
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
