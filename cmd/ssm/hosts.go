package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/cloud"
	"ssm/internal/config"
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
	OK          bool     `json:"ok"`
	Action      string   `json:"action"`
	Changed     bool     `json:"changed"`
	Host        hostView `json:"host"`
	KeyAdded    string   `json:"key_added,omitempty"`
	KeyPruned   string   `json:"key_pruned,omitempty"`
	SyncPending bool     `json:"sync_pending"`
}

type hostCLIError struct {
	Code    string `json:"error"`
	Message string `json:"message"`
}

func (e *hostCLIError) Error() string { return e.Message }

func newHostError(code, format string, args ...any) error {
	return &hostCLIError{Code: code, Message: fmt.Sprintf(format, args...)}
}

func parseHostCommandArgs(args []string) (hostCommandOptions, error) {
	var opts hostCommandOptions
	if len(args) == 0 {
		return opts, newHostError("invalid_args", "missing host action")
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
		case matchesValueFlag(arg, "--host"):
			value, err := readFlagValue(args, &i, "--host")
			if err != nil {
				return opts, err
			}
			opts.host = optionalString{value: value, set: true}
		case matchesValueFlag(arg, "--port"):
			value, err := readFlagValue(args, &i, "--port")
			if err != nil {
				return opts, err
			}
			port, err := strconv.Atoi(value)
			if err != nil || port < 1 || port > 65535 {
				return opts, newHostError("invalid_port", "port must be an integer from 1 to 65535")
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
			return opts, newHostError("help", "host command help")
		case strings.HasPrefix(arg, "-"):
			return opts, newHostError("invalid_args", "unknown host option %q", arg)
		default:
			if opts.alias != "" {
				return opts, newHostError("invalid_args", "unexpected positional argument; values must follow named options")
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
		return "", newHostError("invalid_args", "%s requires a value", name)
	}
	(*i)++
	return args[*i], nil
}

func validateHostCommandOptions(opts hostCommandOptions) error {
	switch opts.action {
	case "list":
		if opts.alias != "" || opts.hasMutationOptions() || opts.confirm || opts.pruneKey {
			return newHostError("invalid_args", "host list only accepts --json and --offline")
		}
		return nil
	case "show":
		if opts.alias == "" {
			return newHostError("invalid_args", "host show requires an alias")
		}
		if opts.hasMutationOptions() || opts.confirm || opts.pruneKey {
			return newHostError("invalid_args", "host show only accepts an alias, --json, and --offline")
		}
		return nil
	case "add", "update", "upsert":
		if opts.alias == "" {
			return newHostError("invalid_args", "host %s requires an alias", opts.action)
		}
		if opts.confirm || opts.pruneKey {
			return newHostError("invalid_args", "--yes and --prune-key are only valid for host remove")
		}
		authFlags := 0
		for _, set := range []bool{opts.passwordFile.set, opts.keyName.set, opts.keyFile.set} {
			if set {
				authFlags++
			}
		}
		if authFlags > 1 {
			return newHostError("invalid_auth", "use exactly one of --password-file, --key, or --key-file")
		}
		if opts.newKeyName.set && !opts.keyFile.set {
			return newHostError("invalid_args", "--key-name requires --key-file")
		}
		if opts.newKeyName.set && strings.TrimSpace(opts.newKeyName.value) == "" {
			return newHostError("invalid_key_name", "--key-name must not be empty")
		}
		if opts.action == "add" || opts.action == "upsert" {
			if !opts.host.set || !opts.user.set {
				return newHostError("invalid_args", "host %s requires --host and --user", opts.action)
			}
		}
		if opts.action == "add" && authFlags == 0 {
			return newHostError("auth_required", "host add requires --password-file, --key, or --key-file")
		}
		if opts.action == "update" && !opts.hasMutationOptions() {
			return newHostError("invalid_args", "host update requires at least one field option")
		}
		return nil
	case "remove":
		if opts.alias == "" {
			return newHostError("invalid_args", "host remove requires an alias")
		}
		if opts.hasMutationOptions() {
			return newHostError("invalid_args", "host remove only accepts --yes, --prune-key, and --json")
		}
		if !opts.confirm {
			return newHostError("confirmation_required", "host remove requires --yes")
		}
		return nil
	default:
		return newHostError("invalid_args", "unknown host action %q", opts.action)
	}
}

func (o hostCommandOptions) hasMutationOptions() bool {
	return o.host.set || o.port.set || o.user.set || o.group.set ||
		o.passwordFile.set || o.keyName.set || o.keyFile.set || o.newKeyName.set
}

func runHostCommand(args []string) {
	opts, err := parseHostCommandArgs(args)
	if err != nil {
		if ce, ok := err.(*hostCLIError); ok && ce.Code == "help" {
			hostCommandUsage()
			return
		}
		writeHostCommandError(opts.asJSON || hasJSONFlag(args), err)
		os.Exit(2)
	}

	if err := refreshHostVault(opts.offline); err != nil {
		writeHostCommandError(opts.asJSON, newHostError("sync_pull_failed", "%s; retry only with --offline if stale local state is acceptable", redactError(err)))
		os.Exit(1)
	}
	v, err := config.Load(masterPass)
	if err != nil {
		writeHostCommandError(opts.asJSON, newHostError("vault_error", "%s", redactError(err)))
		os.Exit(1)
	}

	switch opts.action {
	case "list":
		views := make([]hostView, len(v.Connections))
		for i, c := range v.Connections {
			views[i] = newHostView(c)
		}
		writeHostList(views, opts.asJSON)
		return
	case "show":
		idx := exactConnectionIndex(v, opts.alias)
		if idx < 0 {
			writeHostCommandError(opts.asJSON, newHostError("host_not_found", "host %q not found", opts.alias))
			os.Exit(1)
		}
		writeHostView(newHostView(v.Connections[idx]), opts.asJSON)
		return
	}

	updated, result, err := mutateHost(v, opts)
	if err != nil {
		writeHostCommandError(opts.asJSON, err)
		os.Exit(1)
	}
	if result.Changed {
		if err := config.Save(updated, masterPass); err != nil {
			writeHostCommandError(opts.asJSON, newHostError("vault_error", "%s", redactError(err)))
			os.Exit(1)
		}
	}
	writeHostMutationResult(result, opts.asJSON)
}

func refreshHostVault(offline bool) error {
	if offline || !config.LoadSettings().AutoSync {
		return nil
	}
	cloudPath := filepath.Join(config.Dir(), "cloud.json")
	if _, err := os.Stat(cloudPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	cfg, err := cloud.LoadCloud()
	if err != nil {
		return err
	}
	_, err = cloud.PullIfChanged(cfg)
	return err
}

func mutateHost(v *config.Vault, opts hostCommandOptions) (*config.Vault, hostMutationResult, error) {
	updated := cloneVault(v)
	idx := exactConnectionIndex(updated, opts.alias)

	if opts.action == "remove" {
		if idx < 0 {
			return nil, hostMutationResult{}, newHostError("host_not_found", "host %q not found", opts.alias)
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
		return nil, hostMutationResult{}, newHostError("host_exists", "host %q already exists; use host upsert or update", opts.alias)
	}
	if opts.action == "update" && !exists {
		return nil, hostMutationResult{}, newHostError("host_not_found", "host %q not found; use host upsert or add", opts.alias)
	}
	if !exists && !safeHostAliasPattern.MatchString(opts.alias) {
		return nil, hostMutationResult{}, newHostError("invalid_alias", "new aliases must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
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
			return nil, hostMutationResult{}, newHostError("key_not_found", "saved key %q not found", name)
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
		Connections: append([]config.Connection(nil), v.Connections...),
		Keys:        append([]config.SSHKey(nil), v.Keys...),
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

func validateManagedConnection(c config.Connection, v *config.Vault) error {
	if strings.TrimSpace(c.Host) == "" {
		return newHostError("invalid_host", "host address must not be empty")
	}
	if c.Host != strings.TrimSpace(c.Host) || strings.ContainsAny(c.Host, " \t\r\n/@") || strings.Contains(c.Host, "://") {
		return newHostError("invalid_host", "host must be a hostname or unbracketed IP address without user, scheme, path, or whitespace")
	}
	if strings.HasPrefix(c.Host, "[") || strings.HasSuffix(c.Host, "]") {
		return newHostError("invalid_host", "IPv6 addresses must be unbracketed")
	}
	if strings.TrimSpace(c.User) == "" || strings.ContainsAny(c.User, " \t\r\n") || hasControlCharacter(c.User) {
		return newHostError("invalid_user", "SSH user must not be empty or contain whitespace/control characters")
	}
	if c.Port < 1 || c.Port > 65535 {
		return newHostError("invalid_port", "port must be from 1 to 65535")
	}
	if hasControlCharacter(c.Group) {
		return newHostError("invalid_group", "group must not contain control characters")
	}
	if c.Password == "" && c.KeyName == "" {
		return newHostError("auth_required", "host requires password or key authentication")
	}
	if c.KeyName != "" && v.GetKey(c.KeyName) == nil {
		return newHostError("key_not_found", "saved key %q not found", c.KeyName)
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
		return "", newHostError("invalid_args", "--password-file requires a path")
	}
	data, err := readHostCredentialFile(path)
	if err != nil {
		return "", newHostError("password_file_error", "read password file: %s", redactError(err))
	}
	password := strings.TrimRight(string(data), "\r\n")
	if password == "" {
		return "", newHostError("password_file_error", "password file is empty")
	}
	if strings.IndexByte(password, 0) >= 0 {
		return "", newHostError("password_file_error", "password file contains a NUL byte")
	}
	return password, nil
}

func installHostKey(v *config.Vault, current config.Connection, opts hostCommandOptions) (string, bool, error) {
	path := strings.TrimSpace(opts.keyFile.value)
	if path == "" {
		return "", false, newHostError("invalid_args", "--key-file requires a path")
	}
	data, err := readHostCredentialFile(path)
	if err != nil {
		return "", false, newHostError("key_file_error", "read key file: %s", redactError(err))
	}
	material := strings.TrimSpace(string(data))
	if material == "" {
		return "", false, newHostError("invalid_key", "key file is empty")
	}
	if _, err := gossh.ParsePrivateKey([]byte(material)); err != nil {
		return "", false, newHostError("invalid_key", "key file is not an unencrypted SSH private key: %s", redactError(err))
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
		return "", false, newHostError("invalid_key_name", "new key names must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
	}

	for i := range v.Keys {
		if v.Keys[i].Name != name {
			continue
		}
		if strings.TrimSpace(v.Keys[i].PrivateKey) == material {
			return name, false, nil
		}
		if current.KeyName != name {
			return "", false, newHostError("key_conflict", "saved key %q already has different material; choose a new --key-name", name)
		}
		if keyReferenceCountExcept(v, name, current.Name) > 0 {
			return "", false, newHostError("key_conflict", "saved key %q is shared and has different material; choose a new --key-name", name)
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
		writeHostJSON(hosts)
		return
	}
	for _, h := range hosts {
		writeHostView(h, false)
	}
}

func writeHostView(h hostView, asJSON bool) {
	if asJSON {
		writeHostJSON(h)
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
		writeHostJSON(result)
		return
	}
	fmt.Printf("host %s: %s (changed=%t, sync_pending=%t)\n", result.Host.Name, result.Action, result.Changed, result.SyncPending)
}

func writeHostCommandError(asJSON bool, err error) {
	ce, ok := err.(*hostCLIError)
	if !ok {
		ce = &hostCLIError{Code: "internal", Message: redactError(err)}
	}
	if asJSON {
		writeHostJSON(struct {
			OK bool `json:"ok"`
			*hostCLIError
		}{OK: false, hostCLIError: ce})
		return
	}
	fmt.Fprintf(os.Stderr, "ssm: error=%s\nError: %s\n", ce.Code, ce.Message)
}

func writeHostJSON(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
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
  sshctl host show <alias> [--json] [--offline]
  sshctl host add <alias> --host <address> --user <user> [--port 22] [--group <name>] <auth> [--json] [--offline]
  sshctl host update <alias> [--host ...] [--user ...] [--port ...] [--group ...] [<auth>] [--json] [--offline]
  sshctl host upsert <alias> --host <address> --user <user> [--port 22] [--group <name>] [<auth>] [--json] [--offline]
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
