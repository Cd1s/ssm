package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"ssm/internal/config"
	"ssm/internal/inventorytransaction"
	"ssm/internal/machinecontract"
	agentssh "ssm/internal/ssh"
	"ssm/internal/synctransaction"
)

type optionalString struct {
	value string
	set   bool
}

type optionalInt struct {
	value int
	set   bool
}

type hostCommandOptions struct {
	action       string
	alias        string
	filter       optionalString
	asJSON       bool
	host         optionalString
	port         optionalInt
	user         optionalString
	group        optionalString
	passwordFile optionalString
	keyName      optionalString
	keyFile      optionalString
	newKeyName   optionalString
	confirm      bool
	pruneKey     bool
	offline      bool
	verify       bool
	push         bool
}

type hostView = inventorytransaction.HostView
type hostMutationResult = inventorytransaction.MutationReceipt

type hostVerificationFailure struct {
	OK bool `json:"ok"`
	machinecontract.Metadata
	Action       string                `json:"action"`
	Changed      bool                  `json:"changed"`
	Applied      bool                  `json:"applied"`
	Host         hostView              `json:"host"`
	Verification *agentssh.CheckResult `json:"verification"`
	SyncPending  bool                  `json:"sync_pending"`
}

type hostPushFailure struct {
	OK bool `json:"ok"`
	machinecontract.Metadata
	Action       string                `json:"action"`
	Changed      bool                  `json:"changed"`
	Applied      bool                  `json:"applied"`
	Pushed       bool                  `json:"pushed"`
	Host         hostView              `json:"host"`
	Verification *agentssh.CheckResult `json:"verification,omitempty"`
	SyncPending  bool                  `json:"sync_pending"`
}

var errHostHelp = errors.New("host command help")

func newHostError(kind machinecontract.Kind, format string, args ...any) error {
	failure := machinecontract.Classify(kind, machinecontract.Details{Message: fmt.Sprintf(format, args...)})
	return machinecontract.NewClassifiedError(failure)
}

func parseHostCommandArgs(args []string) (hostCommandOptions, error) {
	opts := hostCommandOptions{asJSON: machineJSON}
	if len(args) == 0 {
		return opts, newHostError(machinecontract.HostInvalidArguments, "missing host action")
	}
	opts.action = args[0]
	if opts.action == "get" {
		opts.action = "show"
	}

	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--json":
			opts.asJSON = true
		case arg == "--yes":
			opts.confirm = true
		case arg == "--prune-key":
			opts.pruneKey = true
		case arg == "--offline":
			opts.offline = true
		case arg == "--verify":
			opts.verify = true
		case arg == "--push":
			opts.push = true
		case matchesValueFlag(arg, "--host"):
			value, err := readFlagValue(args, &i, "--host")
			if err != nil {
				return opts, err
			}
			opts.host = optionalString{value: value, set: true}
		case matchesValueFlag(arg, "--filter"):
			value, err := readFlagValue(args, &i, "--filter")
			if err != nil {
				return opts, err
			}
			opts.filter = optionalString{value: value, set: true}
		case matchesValueFlag(arg, "--port"):
			value, err := readFlagValue(args, &i, "--port")
			if err != nil {
				return opts, err
			}
			port, err := strconv.Atoi(value)
			if err != nil || port < 1 || port > 65535 {
				return opts, newHostError(machinecontract.HostInvalidArguments, "port must be an integer from 1 to 65535")
			}
			opts.port = optionalInt{value: port, set: true}
		case matchesValueFlag(arg, "--user"):
			value, err := readFlagValue(args, &i, "--user")
			if err != nil {
				return opts, err
			}
			opts.user = optionalString{value: value, set: true}
		case matchesValueFlag(arg, "--group"):
			value, err := readFlagValue(args, &i, "--group")
			if err != nil {
				return opts, err
			}
			opts.group = optionalString{value: value, set: true}
		case matchesValueFlag(arg, "--password-file"):
			value, err := readFlagValue(args, &i, "--password-file")
			if err != nil {
				return opts, err
			}
			opts.passwordFile = optionalString{value: value, set: true}
		case matchesValueFlag(arg, "--key"):
			value, err := readFlagValue(args, &i, "--key")
			if err != nil {
				return opts, err
			}
			opts.keyName = optionalString{value: value, set: true}
		case matchesValueFlag(arg, "--key-file"):
			value, err := readFlagValue(args, &i, "--key-file")
			if err != nil {
				return opts, err
			}
			opts.keyFile = optionalString{value: value, set: true}
		case matchesValueFlag(arg, "--key-name"):
			value, err := readFlagValue(args, &i, "--key-name")
			if err != nil {
				return opts, err
			}
			opts.newKeyName = optionalString{value: value, set: true}
		case arg == "-h" || arg == "--help":
			return opts, errHostHelp
		case strings.HasPrefix(arg, "-"):
			return opts, newHostError(machinecontract.HostInvalidArguments, "unknown host option %q", arg)
		default:
			if opts.alias != "" {
				return opts, newHostError(machinecontract.HostInvalidArguments, "unexpected positional argument; values must follow named options")
			}
			opts.alias = arg
		}
	}

	if err := validateHostCommandOptions(opts); err != nil {
		return opts, err
	}
	return opts, nil
}

func matchesValueFlag(arg, name string) bool {
	return arg == name || strings.HasPrefix(arg, name+"=")
}

func readFlagValue(args []string, i *int, name string) (string, error) {
	arg := args[*i]
	if strings.HasPrefix(arg, name+"=") {
		return strings.TrimPrefix(arg, name+"="), nil
	}
	if *i+1 >= len(args) {
		return "", newHostError(machinecontract.HostInvalidArguments, "%s requires a value", name)
	}
	(*i)++
	return args[*i], nil
}

func validateHostCommandOptions(opts hostCommandOptions) error {
	switch opts.action {
	case "list":
		if opts.alias != "" || opts.filter.set || opts.hasMutationOptions() || opts.confirm || opts.pruneKey || opts.verify || opts.push {
			return newHostError(machinecontract.HostInvalidArguments, "host list only accepts --json and --offline")
		}
		return nil
	case "search":
		if opts.alias == "" && !opts.filter.set {
			return newHostError(machinecontract.HostInvalidArguments, "host search requires a query or --filter")
		}
		if opts.alias != "" && opts.filter.set {
			return newHostError(machinecontract.HostInvalidArguments, "host search accepts either a query or --filter, not both")
		}
		if opts.hasMutationOptions() || opts.confirm || opts.pruneKey || opts.verify || opts.push {
			return newHostError(machinecontract.HostInvalidArguments, "host search accepts only a query, --json, and --offline")
		}
		return nil
	case "show":
		if opts.alias == "" {
			return newHostError(machinecontract.HostInvalidArguments, "host show requires an alias")
		}
		if opts.hasMutationOptions() || opts.confirm || opts.pruneKey || opts.verify || opts.push {
			return newHostError(machinecontract.HostInvalidArguments, "host show only accepts an alias, --json, and --offline")
		}
		return nil
	case "add", "update", "upsert":
		if opts.alias == "" {
			return newHostError(machinecontract.HostInvalidArguments, "host %s requires an alias", opts.action)
		}
		if opts.confirm || opts.pruneKey {
			return newHostError(machinecontract.HostInvalidArguments, "--yes and --prune-key are only valid for host remove")
		}
		if opts.push && !opts.verify {
			return newHostError(machinecontract.HostInvalidArguments, "--push requires --verify so an unverified host change cannot be published")
		}
		authFlags := 0
		for _, set := range []bool{opts.passwordFile.set, opts.keyName.set, opts.keyFile.set} {
			if set {
				authFlags++
			}
		}
		if authFlags > 1 {
			return newHostError(machinecontract.HostInvalidArguments, "use exactly one of --password-file, --key, or --key-file")
		}
		if opts.newKeyName.set && !opts.keyFile.set {
			return newHostError(machinecontract.HostInvalidArguments, "--key-name requires --key-file")
		}
		if opts.newKeyName.set && strings.TrimSpace(opts.newKeyName.value) == "" {
			return newHostError(machinecontract.HostInvalidArguments, "--key-name must not be empty")
		}
		if opts.action == "add" || opts.action == "upsert" {
			if !opts.host.set || !opts.user.set {
				return newHostError(machinecontract.HostInvalidArguments, "host %s requires --host and --user", opts.action)
			}
		}
		if opts.action == "add" && authFlags == 0 {
			return newHostError(machinecontract.HostAuthenticationRequired, "host add requires --password-file, --key, or --key-file")
		}
		if opts.action == "update" && !opts.hasMutationOptions() {
			return newHostError(machinecontract.HostInvalidArguments, "host update requires at least one field option")
		}
		return nil
	case "remove":
		if opts.alias == "" {
			return newHostError(machinecontract.HostInvalidArguments, "host remove requires an alias")
		}
		if opts.hasMutationOptions() || opts.verify || opts.push {
			return newHostError(machinecontract.HostInvalidArguments, "host remove only accepts --yes, --prune-key, and --json")
		}
		if !opts.confirm {
			return newHostError(machinecontract.HostConfirmationRequired, "host remove requires --yes")
		}
		return nil
	default:
		return newHostError(machinecontract.HostInvalidArguments, "unknown host action %q", opts.action)
	}
}

func (o hostCommandOptions) hasMutationOptions() bool {
	return o.host.set || o.port.set || o.user.set || o.group.set ||
		o.passwordFile.set || o.keyName.set || o.keyFile.set || o.newKeyName.set
}

func runHostCommand(args []string) {
	opts, err := parseHostCommandArgs(args)
	if err != nil {
		if errors.Is(err, errHostHelp) {
			hostCommandUsage()
			return
		}
		os.Exit(machinecontract.WriteMetadataError(opts.asJSON || hasJSONFlag(args), err, machinecontract.HostInternalFailure))
	}

	if err := refreshHostVault(opts.offline); err != nil {
		if errors.Is(err, synctransaction.ErrConfiguration) {
			failure := machinecontract.ClassifySyncFailure(err, machinecontract.HostSyncPullFailed)
			os.Exit(machinecontract.WriteFailure(opts.asJSON, failure, failure))
		}
		os.Exit(machinecontract.WriteMetadataError(opts.asJSON, newHostError(machinecontract.HostSyncPullFailed, "%s; retry only with --offline if stale local state is acceptable", redactError(err)), machinecontract.HostInternalFailure))
	}
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteMetadataError(opts.asJSON, newHostError(machinecontract.HostVaultFailed, "%s", redactError(err)), machinecontract.HostInternalFailure))
	}

	switch opts.action {
	case "list":
		views := make([]hostView, len(v.Connections))
		for i, c := range v.Connections {
			views[i] = inventorytransaction.View(c)
		}
		writeHostList(views, opts.asJSON)
		return
	case "search":
		query := opts.alias
		if opts.filter.set {
			query = opts.filter.value
		}
		views := searchHostViews(v, query)
		writeHostSearch(query, views, opts.asJSON)
		return
	case "show":
		idx := exactConnectionIndex(v, opts.alias)
		if idx < 0 {
			os.Exit(machinecontract.WriteMetadataError(opts.asJSON, newHostError(machinecontract.HostAliasNotFound, "host %q not found", opts.alias), machinecontract.HostInternalFailure))
		}
		writeHostView(inventorytransaction.View(v.Connections[idx]), opts.asJSON)
		return
	}

	result, err := inventorytransaction.New(inventorytransaction.Options{
		MasterPass: masterPass,
	}).ApplyHost(v, hostChangeFromOptions(opts))
	if err != nil {
		var verificationFailure *inventorytransaction.VerificationError
		if errors.As(err, &verificationFailure) {
			failure, document := hostVerificationFailureFor(verificationFailure.Receipt)
			os.Exit(machinecontract.WriteFailure(opts.asJSON, failure, document))
		}
		os.Exit(machinecontract.WriteMetadataError(opts.asJSON, err, machinecontract.HostInternalFailure))
	}
	if opts.push {
		remaining, err := pushTransactions(result.TransactionID)
		if err != nil {
			failure, document := hostPushFailureFor(result, err)
			os.Exit(machinecontract.WriteFailure(opts.asJSON, failure, document))
		}
		result.Pushed = true
		result.SyncPending = remaining
	}
	writeHostMutationResult(result, opts.asJSON)
}

func hostChangeFromOptions(opts hostCommandOptions) inventorytransaction.HostChange {
	change := inventorytransaction.HostChange{
		Action:   inventorytransaction.HostAction(opts.action),
		Alias:    opts.alias,
		PruneKey: opts.pruneKey,
		Verify:   opts.verify,
	}
	change.Host = optionalStringPointer(opts.host)
	change.Port = optionalIntPointer(opts.port)
	change.User = optionalStringPointer(opts.user)
	change.Group = optionalStringPointer(opts.group)
	change.PasswordFile = optionalStringPointer(opts.passwordFile)
	change.SavedKey = optionalStringPointer(opts.keyName)
	change.KeyFile = optionalStringPointer(opts.keyFile)
	change.KeyName = optionalStringPointer(opts.newKeyName)
	return change
}

func optionalStringPointer(value optionalString) *string {
	if !value.set {
		return nil
	}
	return &value.value
}

func optionalIntPointer(value optionalInt) *int {
	if !value.set {
		return nil
	}
	return &value.value
}

func refreshHostVault(offline bool) error {
	_, err := syncTransaction(offline).Refresh()
	return err
}

func exactConnectionIndex(v *config.Vault, alias string) int {
	for i := range v.Connections {
		if v.Connections[i].Name == alias {
			return i
		}
	}
	return -1
}

func searchHostViews(v *config.Vault, query string) []hostView {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" || v == nil {
		return []hostView{}
	}
	views := make([]hostView, 0)
	for _, connection := range v.Connections {
		fields := []string{connection.Name, connection.Host, connection.User, connection.Group}
		matched := false
		for _, field := range fields {
			if strings.Contains(strings.ToLower(field), query) {
				matched = true
				break
			}
		}
		if matched {
			views = append(views, inventorytransaction.View(connection))
		}
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Name < views[j].Name })
	return views
}

func writeHostSearch(query string, matches []hostView, asJSON bool) {
	if asJSON {
		writeMachineValue(struct {
			OK        bool       `json:"ok"`
			Query     string     `json:"query"`
			Count     int        `json:"count"`
			Ambiguous bool       `json:"ambiguous"`
			Matches   []hostView `json:"matches"`
		}{OK: true, Query: query, Count: len(matches), Ambiguous: len(matches) > 1, Matches: matches})
		return
	}
	for _, match := range matches {
		writeHostView(match, false)
	}
}

func writeHostList(hosts []hostView, asJSON bool) {
	if asJSON {
		writeMachineValue(hosts)
		return
	}
	for _, h := range hosts {
		writeHostView(h, false)
	}
}

func writeHostView(h hostView, asJSON bool) {
	if asJSON {
		writeMachineValue(h)
		return
	}
	fmt.Printf("%s\t%s@%s:%d\tauth=%s", h.Name, h.User, h.Host, h.Port, h.Auth)
	if h.KeyName != "" {
		fmt.Printf("\tkey=%s", h.KeyName)
	}
	if h.Group != "" {
		fmt.Printf("\tgroup=%s", h.Group)
	}
	fmt.Println()
}

func writeHostMutationResult(result hostMutationResult, asJSON bool) {
	if asJSON {
		writeMachineValue(result)
		return
	}
	fmt.Printf("host %s: %s (changed=%t, sync_pending=%t)\n", result.Host.Name, result.Action, result.Changed, result.SyncPending)
}

func hostVerificationFailureFor(result hostMutationResult) (machinecontract.Failure, hostVerificationFailure) {
	verificationError := ""
	if result.Verification != nil {
		verificationError = result.Verification.Error
	}
	failure := machinecontract.Classify(machinecontract.HostVerificationFailed, machinecontract.Details{
		Message:           "candidate host failed SSH verification; vault was not changed",
		Alias:             result.Host.Name,
		VerificationError: verificationError,
	})
	document := hostVerificationFailure{
		OK: false, Metadata: failure.Metadata(),
		Action: "not_applied", Changed: result.Changed, Applied: false, Host: result.Host,
		Verification: result.Verification, SyncPending: false,
	}
	return failure, document
}

func hostPushFailureFor(result hostMutationResult, err error) (machinecontract.Failure, hostPushFailure) {
	failure := machinecontract.Classify(machinecontract.HostPushFailed, machinecontract.Details{
		Cause: err,
		Alias: result.Host.Name,
	})
	document := hostPushFailure{
		OK: false, Metadata: failure.Metadata(), Action: result.Action,
		Changed: result.Changed, Applied: true, Pushed: false, Host: result.Host,
		Verification: result.Verification, SyncPending: true,
	}
	return failure, document
}

func hasJSONFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--json" {
			return true
		}
	}
	return false
}

func hostCommandUsage() {
	fmt.Print(`Usage:
  sshctl host list [--json] [--offline]
  sshctl host search <query> [--json] [--offline]
  sshctl host show <alias> [--json] [--offline]
	  sshctl host add <alias> --host <address> --user <user> [--port 22] [--group <name>] <auth> [--verify] [--push] [--json] [--offline]
	  sshctl host update <alias> [--host ...] [--user ...] [--port ...] [--group ...] [<auth>] [--verify] [--push] [--json] [--offline]
	  sshctl host upsert <alias> --host <address> --user <user> [--port 22] [--group <name>] [<auth>] [--verify] [--push] [--json] [--offline]
  sshctl host remove <alias> --yes [--prune-key] [--json] [--offline]

Auth (choose one when required):
  --key <saved-key-name>
  --key-file <path> [--key-name <saved-key-name>]
  --password-file <path>

Use upsert for retry-safe agent automation. Secrets are never accepted inline.
Mutations are saved locally; verify the host, then publish its returned transaction with sshctl --json push --only <transaction-id>.
With configured auto-sync, remote refresh errors stop the command; --offline is an explicit stale-state override.
`)
}
