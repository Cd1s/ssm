package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"ssm/internal/cloud"
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

type pushScope uint8

const (
	pushScopeUnset pushScope = iota
	pushScopeOnly
	pushScopeAll
)

type pushArgumentFailure struct {
	kind    machinecontract.Kind
	message string
}

const (
	pushScopeUsageMessage    = "push accepts --all or --only <transaction-id>"
	pushOnlyRequiredMessage  = "--only requires a non-empty transaction id"
	pushScopeConflictMessage = "--all and --only are mutually exclusive"
)

func pushScopeTransitionFailure(current, next pushScope) *pushArgumentFailure {
	switch current {
	case pushScopeUnset:
		return nil
	case next:
		return &pushArgumentFailure{kind: machinecontract.PushArgumentsInvalid, message: pushScopeUsageMessage}
	default:
		return &pushArgumentFailure{kind: machinecontract.PushScopeConflict, message: pushScopeConflictMessage}
	}
}

func parsePushScopeArguments(args []string) (string, *pushArgumentFailure) {
	scope := pushScopeUnset
	only := ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--all":
			if failure := pushScopeTransitionFailure(scope, pushScopeAll); failure != nil {
				return "", failure
			}
			scope = pushScopeAll
		case args[i] == "--only":
			if failure := pushScopeTransitionFailure(scope, pushScopeOnly); failure != nil {
				return "", failure
			}
			if i+1 >= len(args) {
				return "", &pushArgumentFailure{kind: machinecontract.PushOnlyRequired, message: pushOnlyRequiredMessage}
			}
			value := args[i+1]
			if value == "--all" {
				return "", &pushArgumentFailure{kind: machinecontract.PushScopeConflict, message: pushScopeConflictMessage}
			}
			if strings.TrimSpace(value) == "" || strings.HasPrefix(value, "-") {
				return "", &pushArgumentFailure{kind: machinecontract.PushOnlyRequired, message: pushOnlyRequiredMessage}
			}
			i++
			only = value
			scope = pushScopeOnly
		case strings.HasPrefix(args[i], "--only="):
			if failure := pushScopeTransitionFailure(scope, pushScopeOnly); failure != nil {
				return "", failure
			}
			value := strings.TrimPrefix(args[i], "--only=")
			if value == "--all" {
				return "", &pushArgumentFailure{kind: machinecontract.PushScopeConflict, message: pushScopeConflictMessage}
			}
			if strings.TrimSpace(value) == "" || strings.HasPrefix(value, "-") {
				return "", &pushArgumentFailure{kind: machinecontract.PushOnlyRequired, message: pushOnlyRequiredMessage}
			}
			only = value
			scope = pushScopeOnly
		default:
			return "", &pushArgumentFailure{kind: machinecontract.PushArgumentsInvalid, message: pushScopeUsageMessage}
		}
	}
	if scope == pushScopeUnset {
		return "", &pushArgumentFailure{
			kind: machinecontract.PushArgumentsInvalid, message: "push requires --all or --only <transaction-id>",
		}
	}
	return only, nil
}

func runPush(args []string) {
	only, argumentFailure := parsePushScopeArguments(args)
	if argumentFailure != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, argumentFailure.kind, machinecontract.Details{
			Message: argumentFailure.message,
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
	if result.Action == "noop" {
		fmt.Println("No pending transactions; local, cached, and remote encrypted vault identities are identical.")
		return
	}
	fmt.Printf("push scope=%s\n", result.Scope)
	for _, mutation := range result.Preflight {
		switch {
		case mutation.Alias != "":
			fmt.Printf("publish transaction=%s alias=%s operation=%s\n", mutation.ID, mutation.Alias, mutation.Operation)
		case len(mutation.Aliases) > 0 && mutation.Connections != nil && mutation.Keys != nil:
			fmt.Printf(
				"publish transaction=%s aliases=%s operation=%s connections=%d keys=%d\n",
				mutation.ID,
				strings.Join(mutation.Aliases, ","),
				mutation.Operation,
				*mutation.Connections,
				*mutation.Keys,
			)
		case mutation.KeyName != "" && mutation.Keys != nil:
			fmt.Printf(
				"publish transaction=%s key_name=%s operation=%s keys=%d\n",
				mutation.ID,
				mutation.KeyName,
				mutation.Operation,
				*mutation.Keys,
			)
		default:
			fmt.Printf("publish transaction=%s operation=%s\n", mutation.ID, mutation.Operation)
		}
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

func runPull(args []string) {
	adoptRemote := ""
	yes := false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--yes":
			yes = true
		case args[i] == "--adopt-remote" && i+1 < len(args):
			i++
			adoptRemote = args[i]
		case strings.HasPrefix(args[i], "--adopt-remote="):
			adoptRemote = strings.TrimPrefix(args[i], "--adopt-remote=")
		default:
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.InvalidSSHCTLArguments, machinecontract.Details{Message: "pull accepts only --adopt-remote <sha256> --yes"}))
		}
	}
	if adoptRemote != "" || yes {
		if adoptRemote == "" || !yes || len(adoptRemote) != 64 || strings.Trim(adoptRemote, "0123456789abcdef") != "" {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.InvalidSSHCTLArguments, machinecontract.Details{Message: "--adopt-remote requires a lowercase SHA-256 identity and --yes"}))
		}
		_, err := syncTransaction(false).AdoptRemote(synctransaction.BlobIdentity{Exists: true, Value: adoptRemote})
		if err != nil {
			failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullReplaceFailed)
			os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
		}
		if machineJSON {
			writeMachineValue(struct {
				OK     bool   `json:"ok"`
				Action string `json:"action"`
			}{OK: true, Action: "adopted_remote"})
			return
		}
		fmt.Println("Reviewed remote vault adopted.")
		return
	}
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
		Now:        syncTransactionClock(),
	})
}

func invalidateInventory() {
	ssh.ClosePool()
	invalidateVaultCache()
}
