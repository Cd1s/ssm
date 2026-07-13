package main

import (
	"errors"
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

type pushResult struct {
	OK        bool                  `json:"ok"`
	Action    string                `json:"action"`
	Scope     string                `json:"scope"`
	Only      string                `json:"transaction_id,omitempty"`
	Preflight []pendingMutationView `json:"preflight"`
	Remaining []pendingMutationView `json:"remaining_mutations"`
}

func runPush(args []string) {
	only := ""
	all := false
	seenOnly := false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--all":
			all = true
		case args[i] == "--only" && i+1 < len(args):
			i++
			only = args[i]
			seenOnly = true
		case strings.HasPrefix(args[i], "--only="):
			only = strings.TrimPrefix(args[i], "--only=")
			seenOnly = true
		default:
			writeCLIError("invalid_arguments", "push accepts --all or --only <transaction-id>", "inspect pending_mutations with sshctl --json status", 2)
			os.Exit(2)
		}
	}
	if seenOnly && strings.TrimSpace(only) == "" {
		writeCLIError("invalid_arguments", "--only requires a non-empty transaction id", "copy an exact id from sshctl --json status", 2)
		os.Exit(2)
	}
	if all && only != "" {
		writeCLIError("invalid_arguments", "--all and --only are mutually exclusive", "choose one explicit push scope", 2)
		os.Exit(2)
	}
	result, err := pushTransactionScope(only)
	if err != nil {
		writeCLIError("sync_push_failed", err.Error(), "local vault remains pending; fix sync and retry push", 1)
		os.Exit(1)
	}
	if machineJSON {
		writeMachineValue(result)
		return
	}
	fmt.Printf("push scope=%s\n", result.Scope)
	for _, mutation := range result.Preflight {
		fmt.Printf("publish transaction=%s alias=%s operation=%s\n", mutation.ID, mutation.Alias, mutation.Operation)
	}
	fmt.Println("Vault pushed to cloud.")
}

func pushTransactions(only string) (bool, error) {
	if only == "" {
		return false, fmt.Errorf("host mutation did not create a transaction to push")
	}
	result, err := pushTransactionScope(only)
	return len(result.Remaining) > 0, err
}

func pushTransactionScope(only string) (pushResult, error) {
	v, err := config.Load(masterPass)
	if err != nil {
		return pushResult{}, err
	}
	projected, selected, err := publishProjection(v, only)
	if err != nil {
		return pushResult{}, err
	}
	blob, err := config.EncryptVault(projected, masterPass)
	if err != nil {
		return pushResult{}, err
	}
	localAfter := cloneVault(v)
	markPublished(localAfter, selected, projected)
	if err := config.Save(localAfter, masterPass); err != nil {
		return pushResult{}, err
	}
	if only == "" {
		blob, err = os.ReadFile(config.Path())
		if err != nil {
			_ = config.Save(v, masterPass)
			return pushResult{}, err
		}
	}
	cfg, err := cloud.LoadCloud()
	if err == nil {
		err = cloud.PushBlob(cfg, blob)
	}
	if err != nil {
		_ = config.Save(v, masterPass)
		return pushResult{}, err
	}
	scope := "all"
	if only != "" {
		scope = "only"
	}
	return pushResult{OK: true, Action: "pushed", Scope: scope, Only: only, Preflight: mutationViews(selected), Remaining: pendingMutationViews(localAfter)}, nil
}

func mutationViews(mutations []config.PendingMutation) []pendingMutationView {
	views := make([]pendingMutationView, 0, len(mutations))
	for _, mutation := range mutations {
		views = append(views, pendingMutationView{ID: mutation.ID, Alias: mutation.Alias, Operation: mutation.Operation, CreatedAt: mutation.CreatedAt})
	}
	return views
}

func pushVault() error {
	_, err := pushTransactionScope("")
	return err
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
	if err := refreshVaultIfChanged(); err != nil {
		var conflict *cloud.SyncConflictError
		if errors.As(err, &conflict) {
			writeCLIErrorStage("sync_conflict", err.Error(), "local and remote blobs were preserved; inspect sshctl --offline --json doctor, then explicitly pull or push after review", "sync_compare", 1)
			os.Exit(1)
		}
		writeCLIErrorStage("sync_pull_failed", err.Error(), "fix sync connectivity or retry explicitly with --offline", "sync_pull", 1)
		os.Exit(1)
	}
}

func refreshVaultIfChanged() error {
	if offlineMode || !config.LoadSettings().AutoSync {
		return nil
	}
	cfg, err := cloud.LoadCloud()
	if err != nil {
		return nil
	}
	_, err = cloud.PullIfChanged(cfg)
	return err
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
