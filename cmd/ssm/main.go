package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"ssm/internal/config"
	"ssm/internal/tui"
	"ssm/internal/update"
	"ssm/internal/vault"
)

var (
	masterPass     string
	masterPassFile string
	version        = "1.0.3"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			fmt.Fprintf(os.Stderr, "\n\033[1;31mssm crashed!\033[0m\n\n")
			fmt.Fprintf(os.Stderr, "Version: %s\n", version)
			fmt.Fprintf(os.Stderr, "OS:      %s/%s\n", runtime.GOOS, runtime.GOARCH)
			fmt.Fprintf(os.Stderr, "Error:   %s\n\n", redactString(fmt.Sprint(r)))
			fmt.Fprintf(os.Stderr, "Stack trace:\n%s\n\n", buf[:n])
			fmt.Fprintf(os.Stderr, "Please include the info above when reporting this issue.\n")
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
		unlock()
		runTUI()
		return
	}

	switch args[0] {
	case "--version", "-v":
		fmt.Printf("ssm %s\n", version)
		return
	case "--help", "-h", "help":
		fmt.Printf("ssm %s - SSH connection manager\n", version)
		fmt.Print(`
Usage:
  ssm                  open interactive connection list
  ssm add              add a new connection
  ssm edit <name>      edit a connection
  ssm remove <name>    remove a connection
  ssm list [--json]    list all connections
  ssm exec <name> <cmd> run a command on a remote server
  ssm put <name> <local> <remote> upload a local file to a remote server
  ssm keys             list saved SSH keys
  ssm keys add         add a new SSH key
  ssm keys remove <n>  remove a SSH key
  ssm update           update ssm to the latest version
  ssm shell <name>     open an interactive shell
  ssm import-json <path> import headless JSON connections
  ssm server           run the headless encrypted sync server

Cloud (optional):
  ssm login            authenticate with sync server
  ssm register         create a sync account
  ssm push             upload encrypted vault
  ssm pull             download encrypted vault
  ssm pull-if-changed  download encrypted vault only if remote changed
  ssm remote-hash      print remote encrypted vault hash
  ssm logout           remove sync credentials

Shortcuts (in TUI):
  enter       connect        /    search
  a           add            e    edit
  d           delete         K/k  manage keys
  s           settings
  Ctrl+T n    new tab        Ctrl+T 1-9  switch tab
  Ctrl+T w    close tab      Ctrl+T d    detach
`)
		return
	case "update":
		fmt.Println("Checking for updates...")
		if err := update.Download(); err != nil {
			printError(err)
			os.Exit(1)
		}
		return
	case "add":
		unlock()
		runAdd()
	case "remove":
		if len(args) < 2 {
			fmt.Println("Usage: ssm remove <name>")
			os.Exit(1)
		}
		unlock()
		runRemove(args[1])
	case "edit":
		if len(args) < 2 {
			fmt.Println("Usage: ssm edit <name>")
			os.Exit(1)
		}
		unlock()
		runEdit(args[1])
	case "keys":
		unlock()
		if len(args) >= 2 {
			switch args[1] {
			case "add":
				runKeysAdd()
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
	case "exec":
		if len(args) < 3 {
			fmt.Println("Usage: ssm exec <name> <command>")
			os.Exit(1)
		}
		unlock()
		runExec(args[1], strings.Join(args[2:], " "))
	case "put":
		if len(args) != 4 {
			fmt.Println("Usage: ssm put <name> <local> <remote>")
			os.Exit(1)
		}
		unlock()
		runPut(args[1], args[2], args[3])
	case "shell":
		if len(args) < 2 {
			fmt.Println("Usage: ssm shell <name>")
			os.Exit(1)
		}
		unlock()
		runShell(args[1])
	case "import-json":
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
		runPush()
	case "pull":
		runPull()
	case "pull-if-changed":
		runPullIfChanged()
	case "remote-hash":
		runRemoteHash()
	default:
		fmt.Printf("Unknown command: %s\n", args[0])
		fmt.Println("Usage: ssm [add|remove|edit|list|keys|exec|put|shell|import-json|server|update|login|register|push|pull|pull-if-changed|remote-hash|logout]")
		os.Exit(1)
	}
}

func parseGlobalArgs(args []string) ([]string, error) {
	if masterPassFile == "" {
		masterPassFile = os.Getenv("SSM_MASTER_PASS_FILE")
	}

	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--master-pass-file":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--master-pass-file requires a path")
			}
			masterPassFile = args[i+1]
			i++
		case strings.HasPrefix(arg, "--master-pass-file="):
			masterPassFile = strings.TrimPrefix(arg, "--master-pass-file=")
			if masterPassFile == "" {
				return nil, fmt.Errorf("--master-pass-file requires a path")
			}
		default:
			out = append(out, arg)
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
			fmt.Fprintf(os.Stderr, "Error: master pass file: %v\n", err)
			os.Exit(1)
		}
		pass := strings.TrimRight(string(data), "\r\n")
		if pass == "" {
			fmt.Fprintln(os.Stderr, "Error: master pass file is empty")
			os.Exit(1)
		}

		if !config.Exists() {
			masterPass = pass
			if err := config.Save(&config.Vault{}, masterPass); err != nil {
				printError(err)
				os.Exit(1)
			}
			return
		}

		if _, err := config.Load(pass); err != nil {
			printError(err)
			os.Exit(1)
		}
		masterPass = pass
		return
	}

	if !config.Exists() {
		p := tea.NewProgram(tui.NewUnlockModel(tui.UnlockCreate), tea.WithAltScreen())
		result, err := p.Run()
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		m := result.(tui.UnlockModel)
		if m.Canceled {
			os.Exit(0)
		}
		masterPass = m.Password
		_ = config.Save(&config.Vault{}, masterPass)
		settings := config.LoadSettings()
		if settings.PasswordCache == "session" {
			config.CachePassword(masterPass)
		}
		return
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

	for attempts := 0; attempts < 3; attempts++ {
		m := tui.NewUnlockModel(tui.UnlockLogin)
		p := tea.NewProgram(m, tea.WithAltScreen())
		result, err := p.Run()
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		um := result.(tui.UnlockModel)
		if um.Canceled {
			os.Exit(0)
		}

		_, err = config.Load(um.Password)
		if err == nil {
			masterPass = um.Password
			if settings.PasswordCache == "session" {
				config.CachePassword(masterPass)
			}
			return
		}
		if err != vault.ErrWrongPassword {
			printError(err)
			os.Exit(1)
		}
	}

	fmt.Fprintln(os.Stderr, "Too many attempts.")
	os.Exit(1)
}
