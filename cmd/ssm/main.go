package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"ssm/internal/config"
	"ssm/internal/tui"
	"ssm/internal/update"
	"ssm/internal/vault"
)

var (
	masterPass string
	version    = "dev"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			fmt.Fprintf(os.Stderr, "\n\033[1;31mssm crashed!\033[0m\n\n")
			fmt.Fprintf(os.Stderr, "Version: %s\n", version)
			fmt.Fprintf(os.Stderr, "OS:      %s/%s\n", runtime.GOOS, runtime.GOARCH)
			fmt.Fprintf(os.Stderr, "Error:   %v\n\n", r)
			fmt.Fprintf(os.Stderr, "Stack trace:\n%s\n\n", buf[:n])
			fmt.Fprintf(os.Stderr, "Please report this at:\n")
			fmt.Fprintf(os.Stderr, "  https://github.com/Dilgo-dev/ssm/issues\n\n")
			fmt.Fprintf(os.Stderr, "Include the info above in your report.\n")
		}
	}()

	if version == "dev" {
		config.EnableDebug()
	}

	if len(os.Args) < 2 {
		checkUpdate()
		unlock()
		runTUI()
		showUpdateNotice()
		return
	}

	switch os.Args[1] {
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
  ssm keys             list saved SSH keys
  ssm keys add         add a new SSH key
  ssm keys remove <n>  remove a SSH key
  ssm update           update ssm to the latest version

Cloud (optional):
  ssm login            authenticate with sync server
  ssm register         create a sync account
  ssm push             upload encrypted vault
  ssm pull             download encrypted vault
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
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	case "add":
		unlock()
		runAdd()
	case "remove":
		if len(os.Args) < 3 {
			fmt.Println("Usage: ssm remove <name>")
			os.Exit(1)
		}
		unlock()
		runRemove(os.Args[2])
	case "edit":
		if len(os.Args) < 3 {
			fmt.Println("Usage: ssm edit <name>")
			os.Exit(1)
		}
		unlock()
		runEdit(os.Args[2])
	case "keys":
		unlock()
		if len(os.Args) >= 3 {
			switch os.Args[2] {
			case "add":
				runKeysAdd()
			case "remove":
				if len(os.Args) < 4 {
					fmt.Println("Usage: ssm keys remove <name>")
					os.Exit(1)
				}
				runKeysRemove(os.Args[3])
			default:
				fmt.Printf("Unknown keys command: %s\n", os.Args[2])
				os.Exit(1)
			}
		} else {
			runKeysList()
		}
	case "list", "ls":
		jsonFlag := len(os.Args) > 2 && os.Args[2] == "--json"
		unlock()
		runList(jsonFlag)
	case "exec":
		if len(os.Args) < 4 {
			fmt.Println("Usage: ssm exec <name> <command>")
			os.Exit(1)
		}
		unlock()
		runExec(os.Args[2], strings.Join(os.Args[3:], " "))
	case "register":
		runRegister()
	case "login":
		runLogin()
	case "logout":
		runLogout()
	case "push":
		runPush()
	case "pull":
		runPull()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		fmt.Println("Usage: ssm [add|remove|edit|list|keys|exec|update|login|register|push|pull|logout]")
		os.Exit(1)
	}
}

func checkUpdate() {
	settings := config.LoadSettings()
	if settings.AutoUpdate && version != "dev" {
		update.CheckInBackground(version)
	}
}

func showUpdateNotice() {
	if version == "dev" {
		return
	}
	if v := update.GetAvailable(version); v != "" {
		fmt.Printf("\nssm %s available. Run 'ssm update' to upgrade.\n", v)
	}
}

func unlock() {
	if !config.Exists() {
		p := tea.NewProgram(tui.NewUnlockModel(tui.UnlockCreate), tea.WithAltScreen())
		result, err := p.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Fprintln(os.Stderr, "Too many attempts.")
	os.Exit(1)
}
