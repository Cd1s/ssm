package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"ssm/internal/cloud"
	"ssm/internal/config"
)

const defaultServer = ""

func runRegister(args []string) {
	opts, ok := parseCloudAuthFlags("register", args)
	if ok {
		if opts.passwordFile == "" {
			fmt.Fprintln(os.Stderr, "Error: --password-file required for noninteractive register")
			os.Exit(1)
		}
		password := readSecretFile(opts.passwordFile, "password")
		fmt.Println("Creating account...")
		token, err := cloud.Register(opts.server, opts.email, password)
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		cfg := &cloud.CloudConfig{Server: opts.server, Token: token, Email: opts.email}
		if err := cloud.SaveCloud(cfg); err != nil {
			printError(err)
			os.Exit(1)
		}
		fmt.Println("Account registered.")
		return
	}
	writeCLIError("invalid_arguments", "register requires explicit flags", "use --server, --email, and --password-file", 2)
	os.Exit(2)
}

func runLogin(args []string) {
	opts, ok := parseCloudAuthFlags("login", args)
	if ok {
		if opts.passwordFile == "" {
			fmt.Fprintln(os.Stderr, "Error: --password-file required for noninteractive login")
			os.Exit(1)
		}
		password := readSecretFile(opts.passwordFile, "password")
		fmt.Println("Logging in...")
		token, err := cloud.Login(opts.server, opts.email, password)
		if err != nil {
			printError(err)
			os.Exit(1)
		}

		cfg := &cloud.CloudConfig{Server: opts.server, Token: token, Email: opts.email}
		if err := cloud.SaveCloud(cfg); err != nil {
			printError(err)
			os.Exit(1)
		}
		fmt.Println("Logged in.")
		return
	}
	writeCLIError("invalid_arguments", "login requires explicit flags", "use --server, --email, and --password-file", 2)
	os.Exit(2)
}

type cloudAuthFlags struct {
	server       string
	email        string
	passwordFile string
}

func parseCloudAuthFlags(name string, args []string) (cloudAuthFlags, bool) {
	if len(args) == 0 {
		return cloudAuthFlags{}, false
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	opts := cloudAuthFlags{}
	fs.StringVar(&opts.server, "server", defaultServer, "sync server URL")
	fs.StringVar(&opts.email, "email", "", "account email")
	fs.StringVar(&opts.passwordFile, "password-file", "", "file containing account password")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if opts.email == "" {
		fmt.Fprintln(os.Stderr, "Error: --email required")
		os.Exit(1)
	}
	opts.server = strings.TrimRight(opts.server, "/")
	if opts.server == "" {
		fmt.Fprintln(os.Stderr, "Error: --server required")
		os.Exit(1)
	}
	return opts, true
}

func readSecretFile(path, label string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		printError(fmt.Errorf("%s file: %w", label, err))
		os.Exit(1)
	}
	secret := strings.TrimRight(string(data), "\r\n")
	if secret == "" {
		fmt.Fprintf(os.Stderr, "Error: %s file is empty\n", label)
		os.Exit(1)
	}
	return secret
}

func runLogout() {
	if err := cloud.DeleteCloud(); err != nil {
		fmt.Fprintln(os.Stderr, "Not logged in.")
		os.Exit(1)
	}
	fmt.Println("Logged out.")
}

func runPush() {
	if err := pushVault(); err != nil {
		writeCLIError("sync_push_failed", err.Error(), "local vault remains pending; fix sync and retry push", 1)
		os.Exit(1)
	}
	if machineJSON {
		writeMachineValue(struct {
			OK     bool   `json:"ok"`
			Action string `json:"action"`
		}{OK: true, Action: "pushed"})
		return
	}
	fmt.Println("Vault pushed to cloud.")
}

func pushVault() error {
	cfg, err := cloud.LoadCloud()
	if err != nil {
		return err
	}
	return cloud.Push(cfg)
}

func runRemoteHash() {
	cfg, err := cloud.LoadCloud()
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	etag, err := cloud.RemoteETag(cfg)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
	fmt.Println(etag)
}

func runPullIfChanged() {
	cfg, err := cloud.LoadCloud()
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	changed, err := cloud.PullIfChanged(cfg)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
	if changed {
		if machineJSON {
			writeMachineValue(struct {
				OK      bool   `json:"ok"`
				Action  string `json:"action"`
				Changed bool   `json:"changed"`
			}{OK: true, Action: "pulled", Changed: true})
			return
		}
		fmt.Println("Vault pulled from cloud.")
	} else {
		if machineJSON {
			writeMachineValue(struct {
				OK      bool   `json:"ok"`
				Action  string `json:"action"`
				Changed bool   `json:"changed"`
			}{OK: true, Action: "pulled", Changed: false})
			return
		}
		fmt.Println("Vault unchanged.")
	}
}

func pullIfChanged() {
	cfg, err := cloud.LoadCloud()
	if err != nil {
		return
	}
	if _, err := cloud.PullIfChanged(cfg); err != nil {
		config.Debug("pull-if-changed: %v", err)
	}
}

func runPull() {
	cfg, err := cloud.LoadCloud()
	if err != nil {
		writeCLIError("sync_config_error", err.Error(), "configure sync or use local inventory", 1)
		os.Exit(1)
	}

	if err := cloud.Pull(cfg); err != nil {
		writeCLIError("sync_pull_failed", err.Error(), "local inventory was not replaced", 1)
		os.Exit(1)
	}
	if machineJSON {
		writeMachineValue(struct {
			OK     bool   `json:"ok"`
			Action string `json:"action"`
		}{OK: true, Action: "pulled"})
		return
	}
	fmt.Println("Vault pulled from cloud.")
}
