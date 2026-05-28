package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"ssm/internal/cloud"
	"ssm/internal/config"
	"ssm/internal/tui"
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
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		cfg := &cloud.CloudConfig{Server: opts.server, Token: token, Email: opts.email}
		if err := cloud.SaveCloud(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Account registered.")
		return
	}

	fields := []tui.Field{
		{Label: "Server", Value: defaultServer},
		{Label: "Email", Required: true},
		{Label: "Password", Required: true, Password: true},
		{Label: "Confirm", Required: true, Password: true},
	}

	p := tea.NewProgram(tui.NewFormModel("Create account", fields), tea.WithAltScreen())
	result, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fm := result.(tui.FormModel)
	if fm.Canceled || !fm.Done {
		return
	}

	password := fm.GetValue("Password")
	if password != fm.GetValue("Confirm") {
		fmt.Fprintln(os.Stderr, "Passwords do not match.")
		os.Exit(1)
	}

	server := fm.GetValue("Server")
	email := fm.GetValue("Email")

	fmt.Println("Creating account...")
	token, err := cloud.Register(server, email, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	cfg := &cloud.CloudConfig{Server: server, Token: token, Email: email}
	_ = cloud.SaveCloud(cfg)

	check := func() bool {
		return cloud.CheckVerified(cfg)
	}

	vp := tea.NewProgram(tui.NewVerifyModel(email, check), tea.WithAltScreen())
	vResult, err := vp.Run()
	if err != nil {
		fmt.Println("Account created. Check your email to verify your account.")
		return
	}
	vm := vResult.(tui.VerifyModel)
	if vm.Verified() {
		fmt.Println("Account verified and ready.")
		if err := cloud.Pull(cfg); err == nil {
			fmt.Println("Vault synced from cloud.")
		}
	} else {
		fmt.Println("Account created. Verify your email to use cloud sync.")
	}
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
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		cfg := &cloud.CloudConfig{Server: opts.server, Token: token, Email: opts.email}
		if err := cloud.SaveCloud(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Logged in.")
		return
	}

	fields := []tui.Field{
		{Label: "Server", Value: defaultServer},
		{Label: "Email", Required: true},
		{Label: "Password", Required: true, Password: true},
	}

	p := tea.NewProgram(tui.NewFormModel("Login", fields), tea.WithAltScreen())
	result, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fm := result.(tui.FormModel)
	if fm.Canceled || !fm.Done {
		return
	}

	server := fm.GetValue("Server")
	email := fm.GetValue("Email")
	password := fm.GetValue("Password")

	fmt.Println("Logging in...")
	token, err := cloud.Login(server, email, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	cfg := &cloud.CloudConfig{Server: server, Token: token, Email: email}
	_ = cloud.SaveCloud(cfg)
	fmt.Println("Logged in.")

	if err := cloud.Pull(cfg); err == nil {
		fmt.Println("Vault synced from cloud.")
	}
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
		fmt.Fprintf(os.Stderr, "Error: %s file: %v\n", label, err)
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
	cfg, err := cloud.LoadCloud()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := cloud.Push(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Vault pushed to cloud.")
}

func runRemoteHash() {
	cfg, err := cloud.LoadCloud()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	etag, err := cloud.RemoteETag(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(etag)
}

func runPullIfChanged() {
	cfg, err := cloud.LoadCloud()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	changed, err := cloud.PullIfChanged(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if changed {
		fmt.Println("Vault pulled from cloud.")
	} else {
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
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := cloud.Pull(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Vault pulled from cloud.")
}
