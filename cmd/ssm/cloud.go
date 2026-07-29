package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"ssm/internal/cloud"
	"ssm/internal/config"
	"ssm/internal/inventorytransaction"
	"ssm/internal/machinecontract"
	"ssm/internal/ssh"
	"ssm/internal/synctransaction"
)

const defaultServer = ""

func runRegister(args []string) {
	opts, ok := parseCloudAuthFlags("register", args)
	if ok {
		if opts.passwordFile == "" {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
				Message: "--password-file required for noninteractive register", Tool: "legacy_plain",
			}))
		}
		password := readSecretFile(opts.passwordFile, "password")
		fmt.Println("Creating account...")
		token, err := cloud.Register(opts.server, opts.email, password)
		if err != nil {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
		}
		cfg := &cloud.CloudConfig{Server: opts.server, Token: token, Email: opts.email}
		if err := cloud.SaveCloud(cfg); err != nil {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
		}
		fmt.Println("Account registered.")
		return
	}
	os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.RegisterArgumentsInvalid, machinecontract.Details{Message: "register requires explicit flags"}))
}

func runLogin(args []string) {
	opts, ok := parseCloudAuthFlags("login", args)
	if ok {
		if opts.passwordFile == "" {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
				Message: "--password-file required for noninteractive login", Tool: "legacy_plain",
			}))
		}
		password := readSecretFile(opts.passwordFile, "password")
		fmt.Println("Logging in...")
		token, err := cloud.Login(opts.server, opts.email, password)
		if err != nil {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
		}

		cfg := &cloud.CloudConfig{Server: opts.server, Token: token, Email: opts.email}
		if err := cloud.SaveCloud(cfg); err != nil {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
		}
		fmt.Println("Logged in.")
		return
	}
	os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.LoginArgumentsInvalid, machinecontract.Details{Message: "login requires explicit flags"}))
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
	var flagOutput bytes.Buffer
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	opts := cloudAuthFlags{}
	fs.StringVar(&opts.server, "server", defaultServer, "sync server URL")
	fs.StringVar(&opts.email, "email", "", "account email")
	fs.StringVar(&opts.passwordFile, "password-file", "", "file containing account password")
	if err := fs.Parse(args); err != nil {
		message := flagOutput.String()
		if message == "" {
			message = err.Error() + "\n"
		}
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(machinecontract.WriteFlagHelp(message))
		}
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.InvalidSSHCTLArguments, machinecontract.Details{
			Message: message, Cause: err, Tool: "raw_flag_error",
		}))
	}
	if opts.email == "" {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
			Message: "--email required", Tool: "legacy_plain",
		}))
	}
	opts.server = strings.TrimRight(opts.server, "/")
	if opts.server == "" {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
			Message: "--server required", Tool: "legacy_plain",
		}))
	}
	return opts, true
}

func readSecretFile(path, label string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
			Cause: fmt.Errorf("%s file: %w", label, err),
		}))
	}
	secret := strings.TrimRight(string(data), "\r\n")
	if secret == "" {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
			Message: fmt.Sprintf("%s file is empty", label),
		}))
	}
	return secret
}

func runLogout() {
	if err := cloud.DeleteCloud(); err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
			Cause: err, Tool: "legacy_message", Script: "logout",
		}))
	}
	fmt.Println("Logged out.")
}

type pendingMutationView = inventorytransaction.MutationView
type pushResult = inventorytransaction.PublicationReceipt

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
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.PushArgumentsInvalid, machinecontract.Details{
				Message: "push accepts --all or --only <transaction-id>",
			}))
		}
	}
	if seenOnly && strings.TrimSpace(only) == "" {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.PushOnlyRequired, machinecontract.Details{Message: "--only requires a non-empty transaction id"}))
	}
	if all && only != "" {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.PushScopeConflict, machinecontract.Details{Message: "--all and --only are mutually exclusive"}))
	}
	if !all && !seenOnly {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.PushArgumentsInvalid, machinecontract.Details{
			Message: "push requires --all or --only <transaction-id>",
		}))
	}
	session, err := inventorytransaction.BeginPublication()
	if err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPushFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	defer func() { _ = session.Close() }()
	unlock()
	result, err := pushTransactionScopeInSession(session, only)
	if err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPushFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
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
	session, err := inventorytransaction.BeginPublication()
	if err != nil {
		return pushResult{}, err
	}
	defer func() { _ = session.Close() }()
	return pushTransactionScopeInSession(session, only)
}

func pushTransactionScopeInSession(session *inventorytransaction.PublicationSession, only string) (pushResult, error) {
	v, err := loadVault()
	if err != nil {
		return pushResult{}, err
	}
	transaction := inventorytransaction.New(inventorytransaction.Options{
		MasterPass: masterPass,
		Sync:       syncTransaction(false),
	})
	return session.Publish(transaction, v, only)
}

func runRemoteHash() {
	etag, err := syncTransaction(false).RemoteIdentity()
	if err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.GenericFailure)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	fmt.Println(etag)
}

func runPullIfChanged() {
	facts, err := syncTransaction(false).Sync()
	if errors.Is(err, synctransaction.ErrUnconfigured) {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}
	if err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	if facts.Changed {
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
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
}

func refreshVaultIfChanged() error {
	_, err := refreshVaultIfChangedResult()
	return err
}

func refreshVaultIfChangedResult() (bool, error) {
	facts, err := syncTransaction(false).Refresh()
	return facts.Changed, err
}

func runPull() {
	_, err := syncTransaction(false).Pull()
	if errors.Is(err, synctransaction.ErrUnconfigured) {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.SyncUnconfigured, machinecontract.Details{
			Message: "not logged in (run: ssm login)",
		}))
	}
	if err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullReplaceFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
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

func syncTransaction(commandOffline bool) *synctransaction.Transaction {
	return synctransaction.New(synctransaction.Options{
		Offline:    offlineMode || commandOffline,
		Invalidate: invalidateInventory,
	})
}

func invalidateInventory() {
	ssh.ClosePool()
	invalidateVaultCache()
}

func autoPushOpaque() {
	blob, err := os.ReadFile(config.Path())
	if err != nil {
		return
	}
	_, _ = syncTransaction(false).AutoPushBlob(blob)
}
