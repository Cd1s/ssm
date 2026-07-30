package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ssm/internal/config"
	"ssm/internal/inventorytransaction"
	"ssm/internal/machinecontract"
	"ssm/internal/synctransaction"
)

func runSSHCTL(args []string) {
	if hasJSONFlagBeforeDash(args) && len(args) > 0 && args[0] == "--json" {
		machineJSON = true
	}
	parsed, err := parseGlobalArgs(args)
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.InvalidGlobalArguments, machinecontract.Details{Cause: err}))
	}
	runSSHCTLParsed(parsed)
}

func runSSHCTLParsed(args []string) {
	if masterPassFile == "" {
		masterPassFile = os.Getenv("SSM_MASTER_PASS_FILE")
	}
	if masterPassFile == "" {
		masterPassFile = filepath.Join(config.Dir(), "master.pass")
	}

	if len(args) == 0 {
		if machineJSON {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.SSHCTLCommandRequired, machinecontract.Details{Message: "sshctl command is required"}))
		}
		sshctlUsage()
		return
	}
	if command, rest, ok := sshctlHelpRequest(args); ok {
		sshctlCommandUsage(command, rest)
		return
	}

	switch args[0] {
	case "request":
		runAgentRequest(args[1:])
	case "sync", "pull":
		if len(args) != 1 {
			sshctlUsageExit()
		}
		runPull()
	case "push":
		runPush(args[1:])
	case "list":
		jsonFlag := machineJSON
		switch len(args) {
		case 1:
		case 2:
			if args[1] != "--json" {
				sshctlUsageExit()
			}
			jsonFlag = true
		default:
			sshctlUsageExit()
		}
		machineJSON = machineJSON || jsonFlag
		unlock()
		if jsonFlag {
			runList(true)
		} else {
			runSSHCTLList()
		}
	case "host", "hosts":
		machineJSON = machineJSON || hasJSONFlagBeforeDash(args[1:])
		unlock()
		runHostCommand(args[1:])
	case "host-key", "known-hosts":
		machineJSON = machineJSON || hasJSONFlagBeforeDash(args[1:])
		unlock()
		runHostKeyCommand(args[1:])
	case "run", "exec":
		machineJSON = machineJSON || hasJSONFlagBeforeDash(args[1:])
		alias, runArgs, err := splitRunAlias(args[1:])
		if err != nil {
			if runStreamRequested(args[1:]) {
				exitStreamFailure(machinecontract.Classify(machinecontract.RunAliasRequired, machinecontract.Details{Cause: err}))
			}
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.RunAliasRequired, machinecontract.Details{Cause: err}))
		}
		runSSHCTLRunInvocation(alias, runArgs)
	case "plan":
		machineJSON = machineJSON || hasJSONFlagBeforeDash(args[1:])
		alias, runArgs, err := splitRunAlias(args[1:])
		if err != nil {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.PlanAliasRequired, machinecontract.Details{Cause: err}))
		}
		unlock()
		runSSHCTLPlan(alias, runArgs)
	case "map":
		// sshctl map <targets> [options] [--] <command...>
		// targets: comma-separated aliases and/or globs
		machineJSON = machineJSON || hasJSONFlagBeforeDash(args[1:])
		if len(args) < 2 {
			sshctlUsageExit()
		}
		unlock()
		runSSHCTLMap(args[1:])
	case "check":
		machineJSON = machineJSON || hasJSONFlagBeforeDash(args[1:])
		if len(args) < 2 || strings.HasPrefix(args[1], "-") {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.CheckAliasRequired, machinecontract.Details{Message: "check requires an exact host alias"}))
		}
		jsonFlag := machineJSON
		switch len(args) {
		case 2:
		case 3:
			if args[2] != "--json" {
				sshctlUsageExit()
			}
			jsonFlag = true
		default:
			sshctlUsageExit()
		}
		machineJSON = machineJSON || jsonFlag
		unlock()
		runCheck(args[1], jsonFlag)
	case "doctor":
		machineJSON = machineJSON || hasJSONFlagBeforeDash(args[1:])
		unlock()
		runSSHCTLDoctor(args[1:])
	case "put":
		machineJSON = machineJSON || hasJSONFlagBeforeDash(args[1:])
		unlock()
		runPutArgs(args[1:])
	case "get":
		if len(args) != 4 {
			sshctlUsageExit()
		}
		unlock()
		runGet(args[1], args[2], args[3])
	case "redirect", "alias-link":
		machineJSON = machineJSON || hasJSONFlagBeforeDash(args[1:])
		unlock()
		runRedirect(args[1:])
	case "shell":
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.UnsupportedInteractiveShell, machinecontract.Details{Message: "interactive shell support has been removed"}))
	case "status":
		if len(args) == 2 && args[1] == "--offline" {
			offlineMode = true
		} else if len(args) != 1 {
			sshctlUsageExit()
		}
		unlock()
		runSSHCTLStatus()
	case "--version", "-v":
		if len(args) != 1 {
			sshctlUsageExit()
		}
		if machineJSON {
			writeMachineValue(struct {
				OK      bool   `json:"ok"`
				Version string `json:"version"`
			}{OK: true, Version: version})
			return
		}
		fmt.Printf("sshctl %s\n", version)
	case "-h", "--help", "help":
		sshctlUsage()
	default:
		if len(args) == 1 {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.UnknownSSHCTLCommand, machinecontract.Details{Message: fmt.Sprintf("unknown command %q", args[0])}))
		}
		runSSHCTLRunInvocation(args[0], args[1:])
	}
}

func runSSHCTLRunInvocation(alias string, cmdArgs []string) {
	streamOpts, stream, err := parseRunStreamArgs(cmdArgs)
	if stream {
		machineJSON = true
		streamMachine = true
		if err != nil {
			exitStreamFailure(machinecontract.Classify(machinecontract.InvalidStreamArguments, machinecontract.Details{Cause: err}))
		}
		streamTransaction, err := syncTransaction(false).BeginStream(streamOpts.refresh)
		if err != nil {
			exitStreamFailure(machinecontract.Classify(machinecontract.InvalidStreamArguments, machinecontract.Details{Cause: err}))
		}
		if failure, failed := unlockVault(); failed {
			exitStreamFailure(failure)
		}
		exitRunArgvStream(alias, streamTransaction)
	}
	unlock()
	runSSHCTLRun(alias, cmdArgs)
}

func runSSHCTLRun(alias string, cmdArgs []string) {
	spec, err := parseRemoteRunArgs(cmdArgs)
	if err != nil {
		if err.Error() == "help" {
			sshctlUsage()
			os.Exit(0)
		}
		exitRemoteRunArgError("sshctl", alias, cmdArgs, err)
	}
	machineJSON = machineJSON || spec.JSON
	if len(spec.Scripts) > 1 {
		// Multi-script on one host: use map
		runMap([]string{alias}, spec)
		return
	}
	runExecSpec(alias, spec)
}

func runStreamRequested(args []string) bool {
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != "--json" {
			filtered = append(filtered, arg)
		}
	}
	return len(filtered) > 0 && filtered[0] == "--stream"
}

func runSSHCTLPlan(alias string, cmdArgs []string) {
	spec, err := parseRemoteRunArgs(cmdArgs)
	if err != nil {
		if err.Error() == "help" {
			sshctlUsage()
			os.Exit(0)
		}
		exitRemoteRunArgError("sshctl", alias, cmdArgs, err)
	}
	machineJSON = machineJSON || spec.JSON
	spec.Plan = true
	runExecSpec(alias, spec)
}

func runSSHCTLMap(args []string) {
	// First non-flag token(s) until options: allow
	//   map host1,host2 -- cmd
	//   map 'web-*' -j 4 hostname
	//   map a,b --scripts s1.sh,s2.sh
	if len(args) == 0 {
		sshctlUsageExit()
	}
	// Collect targets until we hit a flag or --
	var targets []string
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" || strings.HasPrefix(a, "-") {
			break
		}
		targets = append(targets, a)
	}
	if len(targets) == 0 {
		exitRemoteRunArgError("sshctl map", "", args, fmt.Errorf("missing target alias/pattern"))
	}
	spec, err := parseRemoteRunArgs(args[i:])
	if err != nil {
		if err.Error() == "help" {
			sshctlUsage()
			os.Exit(0)
		}
		exitRemoteRunArgError("sshctl map", strings.Join(targets, ","), args[i:], err)
	}
	// Single -f becomes scripts for multi or command for one - already handled in parse
	if len(spec.Scripts) == 0 && strings.TrimSpace(spec.Command) == "" {
		exitRemoteRunArgError("sshctl map", strings.Join(targets, ","), args[i:], fmt.Errorf("missing command or --scripts"))
	}
	runMap(targets, spec)
}

func runSSHCTLDoctor(args []string) {
	alias := ""
	deep := false
	asJSON := machineJSON
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			asJSON = true
		case "--deep":
			deep = true
		case "-h", "--help":
			sshctlUsage()
			os.Exit(0)
		default:
			if strings.HasPrefix(args[i], "-") {
				asJSON = asJSON || hasJSONFlag(args)
				exit := machinecontract.WriteClassified(asJSON, machinecontract.InvalidSSHCTLArguments, machinecontract.Details{
					Message: fmt.Sprintf("unknown doctor option %q", args[i]),
					Alias:   args[i],
					Tool:    "doctor_unknown_option",
				})
				if !asJSON {
					sshctlUsage()
				}
				os.Exit(exit)
			}
			if alias != "" {
				sshctlUsageExit()
			}
			alias = args[i]
		}
	}
	runDoctor(alias, deep, asJSON)
}

func runSSHCTLList() {
	pullIfChanged()
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}
	for _, c := range v.Connections {
		fmt.Printf("%s\t%s@%s:%d\n", c.Name, c.User, c.Host, c.Port)
	}
	r := config.LoadRedirects()
	for old, neu := range r {
		fmt.Printf("%s\t->\t%s\n", old, neu)
	}
}

type statusResult struct {
	OK         bool                                      `json:"ok"`
	Version    string                                    `json:"version"`
	Hosts      int                                       `json:"hosts"`
	Vault      string                                    `json:"vault"`
	Sync       string                                    `json:"sync"`
	Redirects  int                                       `json:"redirects"`
	Reuse      string                                    `json:"reuse"`
	ReuseScope string                                    `json:"reuse_scope"`
	LastPull   string                                    `json:"last_pull,omitempty"`
	LastPush   string                                    `json:"last_push,omitempty"`
	LastSync   string                                    `json:"last_sync,omitempty"`
	Freshness  string                                    `json:"freshness"`
	Remote     string                                    `json:"remote_state"`
	Pending    bool                                      `json:"pending_changes"`
	Mutations  []pendingMutationView                     `json:"pending_mutations"`
	Offline    bool                                      `json:"offline"`
	CacheAge   int64                                     `json:"cache_age_seconds,omitempty"`
	Conflict   *synctransaction.SyncConflict             `json:"sync_conflict,omitempty"`
	Recovery   *inventorytransaction.PublicationRecovery `json:"publication_recovery,omitempty"`
}

func runSSHCTLStatus() {
	recovery, recoveryErr := inventorytransaction.New(inventorytransaction.Options{
		MasterPass: masterPass,
		Sync:       syncTransaction(false),
	}).ReconcilePublishingIntent()
	if recoveryErr == nil {
		// Reconciliation waits for any in-flight publisher. Discard the vault
		// snapshot loaded before that wait so status cannot report its stale
		// pending ledger after the other process finalizes.
		invalidateVaultCache()
		pullIfChanged()
	}
	count := 0
	v, err := loadVault()
	if err == nil {
		count = len(v.Connections)
	}
	vaultStatus := "missing"
	if config.Exists() {
		vaultStatus = "present"
	}
	reuse := map[bool]string{true: "on", false: "off"}[os.Getenv("SSM_REUSE") != "0" && os.Getenv("SSM_REUSE") != "off"]
	syncFacts := syncTransaction(false).Facts()
	cloudStatus := "missing"
	switch syncFacts.Configuration {
	case synctransaction.ConfigurationConfigured:
		cloudStatus = "configured"
	case synctransaction.ConfigurationOffline:
		cloudStatus = "offline"
	}
	freshness := string(syncFacts.Freshness)
	pending := false
	pendingMutations := []pendingMutationView{}
	if v != nil {
		pendingMutations = inventorytransaction.Pending(v)
		pending = len(pendingMutations) > 0
	}
	if syncFacts.Freshness == synctransaction.FreshnessLocalAhead {
		pending = true
	}
	remoteState := string(syncFacts.Remote)
	if machineJSON {
		result := statusResult{
			OK: err == nil && recoveryErr == nil, Version: version, Hosts: count, Vault: vaultStatus, Sync: cloudStatus,
			Redirects: len(config.LoadRedirects()), Reuse: reuse, ReuseScope: "process",
			LastPull: syncFacts.LastPull, LastPush: syncFacts.LastPush, LastSync: syncFacts.LastSync,
			Freshness: freshness, Remote: remoteState, Pending: pending, Mutations: pendingMutations,
			Offline: syncFacts.Offline, CacheAge: syncFacts.CacheAge, Conflict: syncFacts.Conflict,
			Recovery: recovery,
		}
		if recoveryErr != nil {
			failure := machinecontract.ClassifySyncFailure(recoveryErr, machinecontract.SyncPushFailed)
			os.Exit(machinecontract.WriteFailure(true, failure, result))
		}
		if err != nil {
			failure := machinecontract.Classify(machinecontract.GenericFailure, machinecontract.Details{Cause: err})
			os.Exit(machinecontract.WriteFailure(true, failure, result))
		}
		writeMachineValue(result)
		return
	}
	if recoveryErr != nil {
		failure := machinecontract.ClassifySyncFailure(recoveryErr, machinecontract.SyncPushFailed)
		os.Exit(machinecontract.WriteFailure(false, failure, failure))
	}
	fmt.Printf("version=%s\nhosts=%d\nvault=%s\nsync=%s\nredirects=%d\nreuse=%s\nreuse_scope=process\nfreshness=%s\nremote_state=%s\npending_changes=%t\noffline=%t\ncache_age_seconds=%d\n",
		version, count, vaultStatus, cloudStatus, len(config.LoadRedirects()), reuse, freshness, remoteState, pending, syncFacts.Offline, syncFacts.CacheAge)
}

func sshctlUsage() {
	fmt.Print(`Usage:
	  # Agent discovery and typed operations
	  sshctl --json status
	  sshctl --json host list
	  sshctl request --file <request.json>  # argv, script_file, secret_files paths

	  sshctl [--json] <command> ...
	  sshctl sync | pull
	  sshctl --json push --only <transaction-id>
	  sshctl --json push --all
  sshctl list [--json]
	  sshctl host list|show|add|update|upsert|remove ...
	  sshctl host-key inspect <alias> [--json]
	  sshctl host-key accept <alias> --fingerprint SHA256:... --yes [--json]
  sshctl status [--offline]
  sshctl check <alias> [--json]
	  sshctl doctor [alias] [--deep] [--json]
	  sshctl request [--file <request.json>|-]

  # Single host agent-safe forms
  sshctl --json run <alias> --argv <command...>  # fastest one-shot literal argv
  sshctl run <alias> --stream [--refresh 30s]    # JSON argv lines; NDJSON results
  sshctl run <alias> --plan <command...>     # dry-run: show remote_command + risk
  sshctl plan <alias> <command...>          # same as run --plan
  sshctl run <alias> --secret NAME=@file ...
  sshctl run <alias> --timeout 10s ...
	  sshctl run <alias> --no-reuse ...
	  sshctl run <alias> --preflight -f script.sh
  sshctl run <alias> --argv <command> [args...]  # force literal argv mode
  sshctl run <alias> -s [--shell sh|bash] [-- args...]
  sshctl run <alias> -f script.sh [-- args...]   # script body goes over stdin
  sshctl run <alias> --scripts a.sh,b.sh    # parallel scripts on one host

  # Compatibility only: remote shell parsing has quoting/expansion risk
  sshctl run <alias> '<shell command string>'

  # Multi-host / multi-script parallel fleet
  sshctl map <alias|pattern>[,more...] [options] <command...>
  sshctl map 'web-*','api-*' -j 8 hostname
  sshctl map host1,host2 --scripts s1.sh,s2.sh   # host×script jobs in parallel
  sshctl map host --plan -j 4 'uname -s'

  sshctl put <alias> <local> <remote> [--resume=v1] [--sha256] [--timeout 2m] [--json]
  sshctl get <alias> <remote> <local>
  sshctl redirect list|set <old> <new>|rm <old>
Env: SSM_TRACE=1  SSM_TIMEOUT=10s  SSM_REUSE=0  SSM_FORWARD_STDIN=1
`)
}

func sshctlUsageExit() {
	if machineJSON {
		os.Exit(machinecontract.WriteClassified(true, machinecontract.InvalidSSHCTLArguments, machinecontract.Details{Message: "invalid sshctl arguments"}))
	}
	sshctlUsage()
	os.Exit(machinecontract.ProcessExit(machinecontract.Classify(machinecontract.InvalidSSHCTLArguments, machinecontract.Details{Message: "invalid sshctl arguments"})))
}

func redactError(err error) string {
	return machinecontract.RedactError(err)
}

func redactString(value string) string {
	return machinecontract.RedactString(value)
}

// splitRunAlias accepts the canonical global form (`sshctl --json run host`)
// and the common command-local form (`sshctl run --json host`). Other run
// options remain after the exact alias so option values cannot be mistaken for
// inventory names.
func splitRunAlias(args []string) (string, []string, error) {
	if len(args) == 0 {
		return "", nil, fmt.Errorf("run requires an exact host alias")
	}
	prefix := make([]string, 0, 1)
	if args[0] == "--json" {
		prefix = append(prefix, "--json")
		args = args[1:]
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", nil, fmt.Errorf("run requires an exact host alias before run-mode options")
	}
	rest := make([]string, 0, len(prefix)+len(args)-1)
	rest = append(rest, prefix...)
	rest = append(rest, args[1:]...)
	return args[0], rest, nil
}
