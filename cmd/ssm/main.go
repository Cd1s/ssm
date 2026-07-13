package main

import (
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
	version        = "1.4.0"
)

func main() {
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
	checkUpdate()

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
  sshctl request --file <json>  preferred typed agent operation
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
			printError(err)
			os.Exit(1)
		}
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
			if err := config.Save(&config.Vault{}, masterPass); err != nil {
				writeCLIError("vault_error", err.Error(), "verify configuration directory permissions", 1)
				os.Exit(1)
			}
			return
		}

		if _, err := config.Load(pass); err != nil {
			writeCLIError("vault_unlock_failed", err.Error(), "verify the master pass file belongs to this encrypted vault", 1)
			os.Exit(1)
		}
		masterPass = pass
		return
	}

	if !config.Exists() {
		writeCLIError("master_pass_file_required", "vault does not exist", "provide --master-pass-file or SSM_MASTER_PASS_FILE to create it non-interactively", 2)
		os.Exit(2)
	}

	settings := config.LoadSettings()
	if settings.PasswordCache == "session" {
		if cached := config.GetCachedPassword(); cached != "" {
			if _, err := config.Load(cached); err == nil {
				masterPass = cached
				return
			}
			config.ClearPasswordCache()
		}
	}

	writeCLIError("master_pass_file_required", "vault passphrase is required", "provide --master-pass-file or SSM_MASTER_PASS_FILE; credentials are never accepted inline", 2)
	os.Exit(2)
}
