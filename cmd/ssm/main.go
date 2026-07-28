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
	version        = "1.4.3"
)

func isSSHCTLInvocation(path string) bool {
	base := filepath.Base(strings.ReplaceAll(path, `\`, "/"))
	if strings.EqualFold(filepath.Ext(base), ".exe") {
		base = strings.TrimSuffix(base, filepath.Ext(base))
	}
	return strings.EqualFold(base, "sshctl")
}

func main() {
	defer func() {
		if r := recover(); r != nil {
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
	if !isInformationalInvocation(os.Args[1:]) {
		checkUpdate()
	}

	if isSSHCTLInvocation(os.Args[0]) {
		runSSHCTL(os.Args[1:])
		return
	}

	args, err := parseGlobalArgs(os.Args[1:])
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
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
  ssm update           update ssm to the latest version
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
		fmt.Println("Checking for updates...")
		if err := update.Download(); err != nil {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
		}
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

func isInformationalInvocation(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		switch arg {
		case "--help", "-h", "help", "--version", "-v":
			return true
		}
	}
	return false
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
		_ = update.Auto(version)
	}
}

func unlock() {
	if masterPassFile != "" {
		data, err := os.ReadFile(masterPassFile)
		if err != nil {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.MasterPassFileReadFailed, machinecontract.Details{
				Message: fmt.Sprintf("master pass file: %v", err), Cause: err,
			}))
		}
		pass := strings.TrimRight(string(data), "\r\n")
		if pass == "" {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.MasterPassFileEmpty, machinecontract.Details{Message: "master pass file is empty"}))
		}

		if !config.Exists() {
			masterPass = pass
			unlockedVault = &config.Vault{}
			if err := config.Save(unlockedVault, masterPass); err != nil {
				unlockedVault = nil
				os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.VaultCreateFailed, machinecontract.Details{Cause: err}))
			}
			return
		}

		v, err := config.Load(pass)
		if err != nil {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.VaultUnlockFailed, machinecontract.Details{Cause: err}))
		}
		masterPass = pass
		unlockedVault = v
		return
	}

	if !config.Exists() {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.MasterPassFileRequiredCreate, machinecontract.Details{Message: "vault does not exist"}))
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

	os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.MasterPassFileRequiredExisting, machinecontract.Details{Message: "vault passphrase is required"}))
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
