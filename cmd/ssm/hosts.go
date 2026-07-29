package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
	agentssh "ssm/internal/ssh"
	"ssm/internal/synctransaction"
)

const maxHostCredentialBytes = 1 << 20

var safeHostAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

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

type hostView struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	Group   string `json:"group,omitempty"`
	Auth    string `json:"auth"`
	KeyName string `json:"key_name,omitempty"`
}

type hostMutationResult struct {
	OK            bool                  `json:"ok"`
	Action        string                `json:"action"`
	Changed       bool                  `json:"changed"`
	Host          hostView              `json:"host"`
	KeyAdded      string                `json:"key_added,omitempty"`
	KeyPruned     string                `json:"key_pruned,omitempty"`
	SyncPending   bool                  `json:"sync_pending"`
	Applied       bool                  `json:"applied"`
	Pushed        bool                  `json:"pushed"`
	TransactionID string                `json:"transaction_id,omitempty"`
	Verification  *agentssh.CheckResult `json:"verification,omitempty"`
}

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
			views[i] = newHostView(c)
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
		writeHostView(newHostView(v.Connections[idx]), opts.asJSON)
		return
	}

	updated, result, err := mutateHost(v, opts)
	if err != nil {
		os.Exit(machinecontract.WriteMetadataError(opts.asJSON, err, machinecontract.HostInternalFailure))
	}
	if opts.verify {
		idx := exactConnectionIndex(updated, opts.alias)
		if idx < 0 {
			os.Exit(machinecontract.WriteMetadataError(opts.asJSON, newHostError(machinecontract.HostInternalFailure, "candidate host disappeared before verification"), machinecontract.HostInternalFailure))
		}
		verification := agentssh.Check(updated.Connections[idx], updated)
		verification.Alias = opts.alias
		result.Verification = &verification
		if !verification.OK {
			failure, document := hostVerificationFailureFor(result)
			os.Exit(machinecontract.WriteFailure(opts.asJSON, failure, document))
		}
	}
	if result.Changed {
		if err := appendHostMutation(v, updated, &result); err != nil {
			os.Exit(machinecontract.WriteMetadataError(opts.asJSON, newHostError(machinecontract.HostTransactionFailed, "%s", redactError(err)), machinecontract.HostInternalFailure))
		}
		if err := config.Save(updated, masterPass); err != nil {
			os.Exit(machinecontract.WriteMetadataError(opts.asJSON, newHostError(machinecontract.HostVaultFailed, "%s", redactError(err)), machinecontract.HostInternalFailure))
		}
	}
	result.Applied = true
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

func refreshHostVault(offline bool) error {
	_, err := syncTransaction(offline).Refresh()
	return err
}

func mutateHost(v *config.Vault, opts hostCommandOptions) (*config.Vault, hostMutationResult, error) {
	updated := cloneVault(v)
	idx := exactConnectionIndex(updated, opts.alias)

	if opts.action == "remove" {
		if idx < 0 {
			return nil, hostMutationResult{}, newHostError(machinecontract.HostAliasNotFound, "host %q not found", opts.alias)
		}
		removed := updated.Connections[idx]
		updated.Connections = append(updated.Connections[:idx], updated.Connections[idx+1:]...)
		result := hostMutationResult{OK: true, Action: "removed", Changed: true, Host: newHostView(removed), SyncPending: true}
		if opts.pruneKey && removed.KeyName != "" && keyReferenceCount(updated, removed.KeyName) == 0 {
			if removeKeyByName(updated, removed.KeyName) {
				result.KeyPruned = removed.KeyName
			}
		}
		return updated, result, nil
	}

	exists := idx >= 0
	if opts.action == "add" && exists {
		return nil, hostMutationResult{}, newHostError(machinecontract.HostAlreadyExists, "host %q already exists; use host upsert or update", opts.alias)
	}
	if opts.action == "update" && !exists {
		return nil, hostMutationResult{}, newHostError(machinecontract.HostAliasNotFound, "host %q not found; use host upsert or add", opts.alias)
	}
	if !exists && !safeHostAliasPattern.MatchString(opts.alias) {
		return nil, hostMutationResult{}, newHostError(machinecontract.HostInvalidAlias, "new aliases must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
	}

	conn := config.Connection{Name: opts.alias, Port: 22}
	if exists {
		conn = updated.Connections[idx]
		if conn.Port == 0 {
			conn.Port = 22
		}
	}
	before := conn
	if opts.host.set {
		conn.Host = strings.TrimSpace(opts.host.value)
	}
	if opts.port.set {
		conn.Port = opts.port.value
	}
	if opts.user.set {
		conn.User = strings.TrimSpace(opts.user.value)
	}
	if opts.group.set {
		conn.Group = strings.TrimSpace(opts.group.value)
	}

	keyAdded := ""
	switch {
	case opts.passwordFile.set:
		password, err := loadPasswordFile(opts.passwordFile.value)
		if err != nil {
			return nil, hostMutationResult{}, err
		}
		conn.Password = password
		conn.KeyName = ""
	case opts.keyName.set:
		name := strings.TrimSpace(opts.keyName.value)
		if name == "" || updated.GetKey(name) == nil {
			return nil, hostMutationResult{}, newHostError(machinecontract.HostSavedKeyNotFound, "saved key %q not found", name)
		}
		conn.KeyName = name
		conn.Password = ""
	case opts.keyFile.set:
		name, added, err := installHostKey(updated, conn, opts)
		if err != nil {
			return nil, hostMutationResult{}, err
		}
		conn.KeyName = name
		conn.Password = ""
		if added {
			keyAdded = name
		}
	}

	if err := validateManagedConnection(conn, updated); err != nil {
		return nil, hostMutationResult{}, err
	}
	if exists {
		updated.Connections[idx] = conn
	} else {
		updated.Connections = append(updated.Connections, conn)
	}

	changed := !exists || before != conn || !equalSSHKeys(v.Keys, updated.Keys)
	action := "created"
	if exists && changed {
		action = "updated"
	} else if exists {
		action = "unchanged"
	}
	return updated, hostMutationResult{
		OK:          true,
		Action:      action,
		Changed:     changed,
		Host:        newHostView(conn),
		KeyAdded:    keyAdded,
		SyncPending: true,
	}, nil
}

func equalSSHKeys(a, b []config.SSHKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func cloneVault(v *config.Vault) *config.Vault {
	if v == nil {
		return &config.Vault{}
	}
	return &config.Vault{
		Connections:      append([]config.Connection(nil), v.Connections...),
		Keys:             append([]config.SSHKey(nil), v.Keys...),
		PendingBase:      v.PendingBase,
		PendingMutations: append([]config.PendingMutation(nil), v.PendingMutations...),
	}
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
			views = append(views, newHostView(connection))
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

func validateManagedConnection(c config.Connection, v *config.Vault) error {
	if strings.TrimSpace(c.Host) == "" {
		return newHostError(machinecontract.HostInvalidAddress, "host address must not be empty")
	}
	if c.Host != strings.TrimSpace(c.Host) || strings.ContainsAny(c.Host, " \t\r\n/@") || strings.Contains(c.Host, "://") {
		return newHostError(machinecontract.HostInvalidAddress, "host must be a hostname or unbracketed IP address without user, scheme, path, or whitespace")
	}
	if strings.HasPrefix(c.Host, "[") || strings.HasSuffix(c.Host, "]") {
		return newHostError(machinecontract.HostInvalidAddress, "IPv6 addresses must be unbracketed")
	}
	if strings.TrimSpace(c.User) == "" || strings.ContainsAny(c.User, " \t\r\n") || hasControlCharacter(c.User) {
		return newHostError(machinecontract.HostInvalidUser, "SSH user must not be empty or contain whitespace/control characters")
	}
	if c.Port < 1 || c.Port > 65535 {
		return newHostError(machinecontract.HostApplyInvalidArguments, "port must be from 1 to 65535")
	}
	if hasControlCharacter(c.Group) {
		return newHostError(machinecontract.HostInvalidGroup, "group must not contain control characters")
	}
	if c.Password == "" && c.KeyName == "" {
		return newHostError(machinecontract.HostApplyAuthenticationRequired, "host requires password or key authentication")
	}
	if c.KeyName != "" && v.GetKey(c.KeyName) == nil {
		return newHostError(machinecontract.HostSavedKeyNotFound, "saved key %q not found", c.KeyName)
	}
	return nil
}

func hasControlCharacter(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func loadPasswordFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", newHostError(machinecontract.HostApplyInvalidArguments, "--password-file requires a path")
	}
	data, err := readHostCredentialFile(path)
	if err != nil {
		return "", newHostError(machinecontract.HostPasswordFileFailed, "read password file: %s", redactError(err))
	}
	password := strings.TrimRight(string(data), "\r\n")
	if password == "" {
		return "", newHostError(machinecontract.HostPasswordFileFailed, "password file is empty")
	}
	if strings.IndexByte(password, 0) >= 0 {
		return "", newHostError(machinecontract.HostPasswordFileFailed, "password file contains a NUL byte")
	}
	return password, nil
}

func installHostKey(v *config.Vault, current config.Connection, opts hostCommandOptions) (string, bool, error) {
	path := strings.TrimSpace(opts.keyFile.value)
	if path == "" {
		return "", false, newHostError(machinecontract.HostApplyInvalidArguments, "--key-file requires a path")
	}
	data, err := readHostCredentialFile(path)
	if err != nil {
		return "", false, newHostError(machinecontract.HostKeyFileFailed, "read key file: %s", redactError(err))
	}
	material := strings.TrimSpace(string(data))
	if material == "" {
		return "", false, newHostError(machinecontract.HostInvalidKey, "key file is empty")
	}
	if _, err := gossh.ParsePrivateKey([]byte(material)); err != nil {
		return "", false, newHostError(machinecontract.HostInvalidKey, "key file is not an unencrypted SSH private key: %s", redactError(err))
	}

	name := strings.TrimSpace(opts.newKeyName.value)
	if name == "" {
		if current.KeyName != "" {
			name = current.KeyName
		} else {
			name = opts.alias
		}
	}
	if !safeHostAliasPattern.MatchString(name) {
		return "", false, newHostError(machinecontract.HostApplyInvalidArguments, "new key names must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
	}

	for i := range v.Keys {
		if v.Keys[i].Name != name {
			continue
		}
		if strings.TrimSpace(v.Keys[i].PrivateKey) == material {
			return name, false, nil
		}
		if current.KeyName != name {
			return "", false, newHostError(machinecontract.HostKeyConflict, "saved key %q already has different material; choose a new --key-name", name)
		}
		if keyReferenceCountExcept(v, name, current.Name) > 0 {
			return "", false, newHostError(machinecontract.HostKeyConflict, "saved key %q is shared and has different material; choose a new --key-name", name)
		}
		v.Keys[i].PrivateKey = material
		return name, false, nil
	}

	v.Keys = append(v.Keys, config.SSHKey{Name: name, PrivateKey: material})
	return name, true, nil
}

func readHostCredentialFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // credential files are explicit CLI inputs
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxHostCredentialBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxHostCredentialBytes {
		return nil, fmt.Errorf("credential file exceeds %d bytes", maxHostCredentialBytes)
	}
	return data, nil
}

func keyReferenceCount(v *config.Vault, name string) int {
	return keyReferenceCountExcept(v, name, "")
}

func keyReferenceCountExcept(v *config.Vault, name, exceptAlias string) int {
	count := 0
	for _, c := range v.Connections {
		if c.Name != exceptAlias && c.KeyName == name {
			count++
		}
	}
	return count
}

func removeKeyByName(v *config.Vault, name string) bool {
	for i := range v.Keys {
		if v.Keys[i].Name == name {
			v.Keys = append(v.Keys[:i], v.Keys[i+1:]...)
			return true
		}
	}
	return false
}

func newHostView(c config.Connection) hostView {
	port := c.Port
	if port == 0 {
		port = 22
	}
	auth := "none"
	switch {
	case c.KeyName != "" && c.Password != "":
		auth = "key+password"
	case c.KeyName != "":
		auth = "key"
	case c.Password != "":
		auth = "password"
	}
	return hostView{Name: c.Name, Host: c.Host, Port: port, User: c.User, Group: c.Group, Auth: auth, KeyName: c.KeyName}
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
Mutations are saved locally; verify the host, then run sshctl push explicitly.
With configured auto-sync, remote refresh errors stop the command; --offline is an explicit stale-state override.
`)
}
