// Package inventorytransaction owns reviewed inventory mutation and exact-scope
// publication policy. Decrypted candidate state stays inside this module; sync
// receives only opaque encrypted vault bytes.
package inventorytransaction

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
	agentssh "ssm/internal/ssh"
	"ssm/internal/synctransaction"
)

const maxHostCredentialBytes = 1 << 20

var safeHostAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// publicationFaultInjection is enabled only in the compiled test binary
// through a linker value. Production builds ignore the test environment seam.
var publicationFaultInjection string

// HostAction identifies one modern reviewed host mutation.
type HostAction string

const (
	HostAdd    HostAction = "add"
	HostUpdate HostAction = "update"
	HostUpsert HostAction = "upsert"
	HostRemove HostAction = "remove"
)

// HostChange contains already-parsed command intent. Credential values remain
// file paths and are read only while constructing the private candidate.
type HostChange struct {
	Action       HostAction
	Alias        string
	Host         *string
	Port         *int
	User         *string
	Group        *string
	PasswordFile *string
	SavedKey     *string
	KeyFile      *string
	KeyName      *string
	PruneKey     bool
	Verify       bool
}

// HostView is the stable secret-free projection of one managed host.
type HostView struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	Group   string `json:"group,omitempty"`
	Auth    string `json:"auth"`
	KeyName string `json:"key_name,omitempty"`
}

// MutationReceipt is the stable secret-free result of a modern host mutation.
type MutationReceipt struct {
	OK            bool                  `json:"ok"`
	Action        string                `json:"action"`
	Changed       bool                  `json:"changed"`
	Host          HostView              `json:"host"`
	KeyAdded      string                `json:"key_added,omitempty"`
	KeyPruned     string                `json:"key_pruned,omitempty"`
	SyncPending   bool                  `json:"sync_pending"`
	Applied       bool                  `json:"applied"`
	Pushed        bool                  `json:"pushed"`
	TransactionID string                `json:"transaction_id,omitempty"`
	Verification  *agentssh.CheckResult `json:"verification,omitempty"`
}

// SavedKeyMutationReceipt is the stable secret-free result of one reviewed
// saved-key removal.
type SavedKeyMutationReceipt struct {
	OK            bool   `json:"ok"`
	Action        string `json:"action"`
	KeyName       string `json:"key_name"`
	Keys          int    `json:"keys"`
	SyncPending   bool   `json:"sync_pending"`
	Applied       bool   `json:"applied"`
	Pushed        bool   `json:"pushed"`
	TransactionID string `json:"transaction_id"`
}

// SavedKeyNotFoundError lets compatibility adapters preserve their established
// not-found rendering without reconstructing saved-key lookup policy.
type SavedKeyNotFoundError struct {
	Name string
}

func (e *SavedKeyNotFoundError) Error() string {
	return fmt.Sprintf("key %q not found", e.Name)
}

// ImportReceipt is the stable secret-free result of one reviewed bulk import.
type ImportReceipt struct {
	OK            bool                   `json:"ok"`
	Action        string                 `json:"action"`
	Connections   int                    `json:"connections"`
	Keys          int                    `json:"keys"`
	Aliases       []string               `json:"aliases"`
	Conflicts     []config.MergeConflict `json:"conflicts,omitempty"`
	SyncPending   bool                   `json:"sync_pending"`
	Applied       bool                   `json:"applied"`
	Pushed        bool                   `json:"pushed"`
	TransactionID string                 `json:"transaction_id"`
}

// MergeReportError identifies the compatible merge-report persistence stage.
type MergeReportError struct {
	Err error
}

func (e *MergeReportError) Error() string {
	return fmt.Sprintf("save merge report: %v", e.Err)
}

func (e *MergeReportError) Unwrap() error {
	return e.Err
}

// VerificationError keeps the safe candidate receipt available to the command
// renderer while guaranteeing the candidate was not persisted.
type VerificationError struct {
	Receipt MutationReceipt
}

func (e *VerificationError) Error() string {
	return "candidate host failed SSH verification; vault was not changed"
}

// Options supplies private persistence and controllable nondeterminism.
type Options struct {
	MasterPass string
	Now        func() time.Time
	Random     io.Reader
	Verifier   func(config.Connection, *config.Vault) agentssh.CheckResult
	Sync       *synctransaction.Transaction
}

// Transaction is the concrete owner of reviewed inventory policy.
type Transaction struct {
	masterPass string
	now        func() time.Time
	random     io.Reader
	verifier   func(config.Connection, *config.Vault) agentssh.CheckResult
	sync       *synctransaction.Transaction
}

// New constructs one inventory policy transaction.
func New(opts Options) *Transaction {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	random := opts.Random
	if random == nil {
		random = rand.Reader
	}
	verifier := opts.Verifier
	if verifier == nil {
		verifier = agentssh.Check
	}
	return &Transaction{
		masterPass: opts.MasterPass,
		now:        now,
		random:     random,
		verifier:   verifier,
		sync:       opts.Sync,
	}
}

// ApplyHost constructs, validates, optionally verifies, appends, and persists
// one modern host mutation. Failed verification and unchanged retries do not
// consume a transaction ID or alter the ledger.
func (t *Transaction) ApplyHost(before *config.Vault, change HostChange) (MutationReceipt, error) {
	if err := validateLedger(before); err != nil {
		return MutationReceipt{}, hostError(machinecontract.HostTransactionFailed, "%s", err)
	}
	after, receipt, err := buildHostCandidate(before, change)
	if err != nil {
		return MutationReceipt{}, err
	}
	if change.Verify {
		idx := exactConnectionIndex(after, change.Alias)
		if idx < 0 {
			return MutationReceipt{}, hostError(machinecontract.HostInternalFailure, "candidate host disappeared before verification")
		}
		verification := t.verifier(after.Connections[idx], after)
		verification.Alias = change.Alias
		receipt.Verification = &verification
		if !verification.OK {
			return receipt, &VerificationError{Receipt: receipt}
		}
	}
	if !receipt.Changed {
		receipt.Applied = true
		return receipt, nil
	}
	id, err := t.newID()
	if err != nil {
		return MutationReceipt{}, hostError(machinecontract.HostTransactionFailed, "%s", err)
	}
	if after.PendingBase == nil {
		if len(after.PendingMutations) != 0 {
			return MutationReceipt{}, hostError(machinecontract.HostTransactionFailed, "pending mutations require a pending base")
		}
		after.PendingBase = snapshotInventory(before)
	}
	mutation := config.PendingMutation{
		ID: id, Alias: receipt.Host.Name, Operation: receipt.Action,
		CreatedAt:  t.now().UTC().Format(time.RFC3339Nano),
		KeysBefore: append([]config.SSHKey(nil), before.Keys...),
		KeysAfter:  append([]config.SSHKey(nil), after.Keys...),
	}
	if idx := exactConnectionIndex(before, receipt.Host.Name); idx >= 0 {
		value := before.Connections[idx]
		mutation.Before = &value
	}
	if idx := exactConnectionIndex(after, receipt.Host.Name); idx >= 0 {
		value := after.Connections[idx]
		mutation.After = &value
	}
	after.PendingMutations = append(after.PendingMutations, mutation)
	receipt.TransactionID = id
	if err := config.Save(after, t.masterPass); err != nil {
		return MutationReceipt{}, hostError(machinecontract.HostVaultFailed, "%s", err)
	}
	receipt.Applied = true
	return receipt, nil
}

// RemoveSavedKey validates references, appends, and persists one reviewed
// saved-key removal. Referenced keys remain unchanged.
func (t *Transaction) RemoveSavedKey(before *config.Vault, name string) (SavedKeyMutationReceipt, error) {
	if err := validateLedger(before); err != nil {
		return SavedKeyMutationReceipt{}, fmt.Errorf("saved-key transaction: %w", err)
	}
	if before.GetKey(name) == nil {
		return SavedKeyMutationReceipt{}, &SavedKeyNotFoundError{Name: name}
	}
	references := make([]string, 0)
	for _, connection := range before.Connections {
		if connection.KeyName == name {
			references = append(references, connection.Name)
		}
	}
	sort.Strings(references)
	if len(references) > 0 {
		return SavedKeyMutationReceipt{}, fmt.Errorf(
			"saved key %q is still referenced by aliases %s",
			name,
			strings.Join(references, ", "),
		)
	}

	after := cloneVault(before)
	if !removeKeyByName(after, name) {
		return SavedKeyMutationReceipt{}, &SavedKeyNotFoundError{Name: name}
	}
	id, err := t.newID()
	if err != nil {
		return SavedKeyMutationReceipt{}, fmt.Errorf("saved-key transaction: %w", err)
	}
	if after.PendingBase == nil {
		if len(after.PendingMutations) != 0 {
			return SavedKeyMutationReceipt{}, fmt.Errorf("saved-key transaction: pending mutations require a pending base")
		}
		after.PendingBase = snapshotInventory(before)
	}
	after.PendingMutations = append(after.PendingMutations, config.PendingMutation{
		ID: id, KeyName: name, Operation: "saved_key_removed",
		CreatedAt:  t.now().UTC().Format(time.RFC3339Nano),
		KeysBefore: append([]config.SSHKey(nil), before.Keys...),
		KeysAfter:  append([]config.SSHKey(nil), after.Keys...),
		KeyCount:   1,
	})
	if err := config.Save(after, t.masterPass); err != nil {
		return SavedKeyMutationReceipt{}, fmt.Errorf("save saved-key transaction: %w", err)
	}
	return SavedKeyMutationReceipt{
		OK: true, Action: "saved_key_removed", KeyName: name, Keys: 1,
		SyncPending: true, Applied: true, TransactionID: id,
	}, nil
}

// ApplyImport validates the complete imported inventory and persists it as one
// atomic bulk transaction.
func (t *Transaction) ApplyImport(before, imported *config.Vault, replace bool) (ImportReceipt, error) {
	if err := validateLedger(before); err != nil {
		return ImportReceipt{}, fmt.Errorf("import transaction: %w", err)
	}
	if err := validateImportInventory(imported); err != nil {
		return ImportReceipt{}, err
	}

	after := cloneVault(before)
	report := config.MergeReport{Conflicts: []config.MergeConflict{}}
	if replace {
		after.Connections = append([]config.Connection(nil), imported.Connections...)
		after.Keys = append([]config.SSHKey(nil), imported.Keys...)
	} else {
		merged, mergeReport := config.MergeVaultsWithReport(
			inventoryOnly(before),
			inventoryOnly(imported),
		)
		after.Connections = merged.Connections
		after.Keys = merged.Keys
		report = mergeReport
	}

	id, err := t.newID()
	if err != nil {
		return ImportReceipt{}, fmt.Errorf("import transaction: %w", err)
	}
	if after.PendingBase == nil {
		if len(after.PendingMutations) != 0 {
			return ImportReceipt{}, fmt.Errorf("import transaction: pending mutations require a pending base")
		}
		after.PendingBase = snapshotInventory(before)
	}
	aliases := affectedConnectionAliases(before.Connections, after.Connections)
	affectedKeys := len(changedKeyNames(before.Keys, after.Keys))
	action := "merged"
	if replace {
		action = "replaced"
	}
	after.PendingMutations = append(after.PendingMutations, config.PendingMutation{
		ID: id, Aliases: aliases, Operation: "import_" + action,
		CreatedAt:       t.now().UTC().Format(time.RFC3339Nano),
		KeysBefore:      append([]config.SSHKey(nil), before.Keys...),
		KeysAfter:       append([]config.SSHKey(nil), after.Keys...),
		BulkBefore:      snapshotInventory(before),
		BulkAfter:       snapshotInventory(after),
		ConnectionCount: len(aliases),
		KeyCount:        affectedKeys,
	})
	if !replace {
		if err := config.SaveMergeReport(report); err != nil {
			return ImportReceipt{}, &MergeReportError{Err: err}
		}
	}
	if err := config.Save(after, t.masterPass); err != nil {
		return ImportReceipt{}, fmt.Errorf("save import transaction: %w", err)
	}
	return ImportReceipt{
		OK: true, Action: action, Connections: len(imported.Connections),
		Keys: len(imported.Keys), Aliases: aliases, Conflicts: report.Conflicts,
		SyncPending: true, Applied: true, TransactionID: id,
	}, nil
}

func affectedConnectionAliases(before, after []config.Connection) []string {
	beforeByAlias := make(map[string]config.Connection, len(before))
	afterByAlias := make(map[string]config.Connection, len(after))
	aliases := make(map[string]bool, len(before)+len(after))
	for _, connection := range before {
		beforeByAlias[connection.Name] = connection
		aliases[connection.Name] = true
	}
	for _, connection := range after {
		afterByAlias[connection.Name] = connection
		aliases[connection.Name] = true
	}
	affected := make([]string, 0, len(aliases))
	for alias := range aliases {
		previous, hadPrevious := beforeByAlias[alias]
		next, hasNext := afterByAlias[alias]
		if hadPrevious != hasNext || previous != next {
			affected = append(affected, alias)
		}
	}
	sort.Strings(affected)
	return affected
}

func validateImportInventory(imported *config.Vault) error {
	if imported == nil {
		return fmt.Errorf("import inventory is required")
	}
	keys := make(map[string]bool, len(imported.Keys))
	for _, key := range imported.Keys {
		if strings.TrimSpace(key.Name) == "" {
			return fmt.Errorf("imported saved key name must not be empty")
		}
		if keys[key.Name] {
			return fmt.Errorf("imported saved key %q is duplicated", key.Name)
		}
		keys[key.Name] = true
	}
	aliases := make(map[string]bool, len(imported.Connections))
	for _, connection := range imported.Connections {
		if strings.TrimSpace(connection.Name) == "" {
			return fmt.Errorf("imported alias must not be empty")
		}
		if aliases[connection.Name] {
			return fmt.Errorf("imported alias %q is duplicated", connection.Name)
		}
		aliases[connection.Name] = true
		if strings.TrimSpace(connection.Host) == "" || strings.TrimSpace(connection.User) == "" {
			return fmt.Errorf("imported alias %q requires host and user", connection.Name)
		}
		if connection.Port < 1 || connection.Port > 65535 {
			return fmt.Errorf("imported alias %q has invalid port", connection.Name)
		}
		if connection.Password == "" && connection.KeyName == "" {
			return fmt.Errorf("imported alias %q has no supported auth material", connection.Name)
		}
		if connection.KeyName != "" && !keys[connection.KeyName] {
			return fmt.Errorf(
				"imported alias %q references missing saved key %q",
				connection.Name,
				connection.KeyName,
			)
		}
	}
	return nil
}

func (t *Transaction) newID() (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(t.random, raw); err != nil {
		return "", fmt.Errorf("generate transaction id: %w", err)
	}
	return "tx_" + hex.EncodeToString(raw), nil
}

func buildHostCandidate(v *config.Vault, change HostChange) (*config.Vault, MutationReceipt, error) {
	updated := cloneVault(v)
	idx := exactConnectionIndex(updated, change.Alias)

	if change.Action == HostRemove {
		if idx < 0 {
			return nil, MutationReceipt{}, hostError(machinecontract.HostAliasNotFound, "host %q not found", change.Alias)
		}
		removed := updated.Connections[idx]
		updated.Connections = append(updated.Connections[:idx], updated.Connections[idx+1:]...)
		receipt := MutationReceipt{
			OK: true, Action: "removed", Changed: true, Host: View(removed), SyncPending: true,
		}
		if change.PruneKey && removed.KeyName != "" && keyReferenceCount(updated, removed.KeyName) == 0 {
			if removeKeyByName(updated, removed.KeyName) {
				receipt.KeyPruned = removed.KeyName
			}
		}
		return updated, receipt, nil
	}

	exists := idx >= 0
	if change.Action == HostAdd && exists {
		return nil, MutationReceipt{}, hostError(machinecontract.HostAlreadyExists, "host %q already exists; use host upsert or update", change.Alias)
	}
	if change.Action == HostUpdate && !exists {
		return nil, MutationReceipt{}, hostError(machinecontract.HostAliasNotFound, "host %q not found; use host upsert or add", change.Alias)
	}
	if change.Action != HostAdd && change.Action != HostUpdate && change.Action != HostUpsert {
		return nil, MutationReceipt{}, hostError(machinecontract.HostApplyInvalidArguments, "unsupported host mutation %q", change.Action)
	}
	if !exists && !safeHostAliasPattern.MatchString(change.Alias) {
		return nil, MutationReceipt{}, hostError(machinecontract.HostInvalidAlias, "new aliases must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
	}

	connection := config.Connection{Name: change.Alias, Port: 22}
	if exists {
		connection = updated.Connections[idx]
		if connection.Port == 0 {
			connection.Port = 22
		}
	}
	previous := connection
	if change.Host != nil {
		connection.Host = strings.TrimSpace(*change.Host)
	}
	if change.Port != nil {
		connection.Port = *change.Port
	}
	if change.User != nil {
		connection.User = strings.TrimSpace(*change.User)
	}
	if change.Group != nil {
		connection.Group = strings.TrimSpace(*change.Group)
	}

	keyAdded := ""
	switch {
	case change.PasswordFile != nil:
		password, err := loadPasswordFile(*change.PasswordFile)
		if err != nil {
			return nil, MutationReceipt{}, err
		}
		connection.Password = password
		connection.KeyName = ""
	case change.SavedKey != nil:
		name := strings.TrimSpace(*change.SavedKey)
		if name == "" || updated.GetKey(name) == nil {
			return nil, MutationReceipt{}, hostError(machinecontract.HostSavedKeyNotFound, "saved key %q not found", name)
		}
		connection.KeyName = name
		connection.Password = ""
	case change.KeyFile != nil:
		name, added, err := installHostKey(updated, connection, change)
		if err != nil {
			return nil, MutationReceipt{}, err
		}
		connection.KeyName = name
		connection.Password = ""
		if added {
			keyAdded = name
		}
	}

	if err := validateManagedConnection(connection, updated); err != nil {
		return nil, MutationReceipt{}, err
	}
	if exists {
		updated.Connections[idx] = connection
	} else {
		updated.Connections = append(updated.Connections, connection)
	}
	changed := !exists || previous != connection || !equalSSHKeys(v.Keys, updated.Keys)
	action := "created"
	if exists && changed {
		action = "updated"
	} else if exists {
		action = "unchanged"
	}
	return updated, MutationReceipt{
		OK: true, Action: action, Changed: changed, Host: View(connection),
		KeyAdded: keyAdded, SyncPending: true,
	}, nil
}

func hostError(kind machinecontract.Kind, format string, args ...any) error {
	failure := machinecontract.Classify(kind, machinecontract.Details{Message: fmt.Sprintf(format, args...)})
	return machinecontract.NewClassifiedError(failure)
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

func snapshotInventory(v *config.Vault) *config.InventorySnapshot {
	return &config.InventorySnapshot{
		Connections: append([]config.Connection(nil), v.Connections...),
		Keys:        append([]config.SSHKey(nil), v.Keys...),
	}
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

func validateManagedConnection(connection config.Connection, v *config.Vault) error {
	if strings.TrimSpace(connection.Host) == "" {
		return hostError(machinecontract.HostInvalidAddress, "host address must not be empty")
	}
	if connection.Host != strings.TrimSpace(connection.Host) ||
		strings.ContainsAny(connection.Host, " \t\r\n/@") ||
		strings.Contains(connection.Host, "://") {
		return hostError(machinecontract.HostInvalidAddress, "host must be a hostname or unbracketed IP address without user, scheme, path, or whitespace")
	}
	if strings.HasPrefix(connection.Host, "[") || strings.HasSuffix(connection.Host, "]") {
		return hostError(machinecontract.HostInvalidAddress, "IPv6 addresses must be unbracketed")
	}
	if strings.TrimSpace(connection.User) == "" ||
		strings.ContainsAny(connection.User, " \t\r\n") ||
		hasControlCharacter(connection.User) {
		return hostError(machinecontract.HostInvalidUser, "SSH user must not be empty or contain whitespace/control characters")
	}
	if connection.Port < 1 || connection.Port > 65535 {
		return hostError(machinecontract.HostApplyInvalidArguments, "port must be from 1 to 65535")
	}
	if hasControlCharacter(connection.Group) {
		return hostError(machinecontract.HostInvalidGroup, "group must not contain control characters")
	}
	if connection.Password == "" && connection.KeyName == "" {
		return hostError(machinecontract.HostApplyAuthenticationRequired, "host requires password or key authentication")
	}
	if connection.KeyName != "" && v.GetKey(connection.KeyName) == nil {
		return hostError(machinecontract.HostSavedKeyNotFound, "saved key %q not found", connection.KeyName)
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
		return "", hostError(machinecontract.HostApplyInvalidArguments, "--password-file requires a path")
	}
	data, err := readHostCredentialFile(path)
	if err != nil {
		return "", hostError(machinecontract.HostPasswordFileFailed, "read password file: %s", machinecontract.RedactError(err))
	}
	password := strings.TrimRight(string(data), "\r\n")
	if password == "" {
		return "", hostError(machinecontract.HostPasswordFileFailed, "password file is empty")
	}
	if strings.IndexByte(password, 0) >= 0 {
		return "", hostError(machinecontract.HostPasswordFileFailed, "password file contains a NUL byte")
	}
	return password, nil
}

func installHostKey(v *config.Vault, current config.Connection, change HostChange) (string, bool, error) {
	path := strings.TrimSpace(*change.KeyFile)
	if path == "" {
		return "", false, hostError(machinecontract.HostApplyInvalidArguments, "--key-file requires a path")
	}
	data, err := readHostCredentialFile(path)
	if err != nil {
		return "", false, hostError(machinecontract.HostKeyFileFailed, "read key file: %s", machinecontract.RedactError(err))
	}
	material := strings.TrimSpace(string(data))
	if material == "" {
		return "", false, hostError(machinecontract.HostInvalidKey, "key file is empty")
	}
	if _, err := gossh.ParsePrivateKey([]byte(material)); err != nil {
		return "", false, hostError(machinecontract.HostInvalidKey, "key file is not an unencrypted SSH private key: %s", machinecontract.RedactError(err))
	}

	name := ""
	if change.KeyName != nil {
		name = strings.TrimSpace(*change.KeyName)
	}
	if name == "" {
		if current.KeyName != "" {
			name = current.KeyName
		} else {
			name = change.Alias
		}
	}
	if !safeHostAliasPattern.MatchString(name) {
		return "", false, hostError(machinecontract.HostApplyInvalidArguments, "new key names must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
	}
	for i := range v.Keys {
		if v.Keys[i].Name != name {
			continue
		}
		if strings.TrimSpace(v.Keys[i].PrivateKey) == material {
			return name, false, nil
		}
		if current.KeyName != name {
			return "", false, hostError(machinecontract.HostKeyConflict, "saved key %q already has different material; choose a new --key-name", name)
		}
		if keyReferenceCountExcept(v, name, current.Name) > 0 {
			return "", false, hostError(machinecontract.HostKeyConflict, "saved key %q is shared and has different material; choose a new --key-name", name)
		}
		v.Keys[i].PrivateKey = material
		return name, false, nil
	}
	v.Keys = append(v.Keys, config.SSHKey{Name: name, PrivateKey: material})
	return name, true, nil
}

func readHostCredentialFile(path string) ([]byte, error) {
	file, err := os.Open(path) //nolint:gosec // credential files are explicit CLI inputs
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxHostCredentialBytes+1))
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
	for _, connection := range v.Connections {
		if connection.Name != exceptAlias && connection.KeyName == name {
			count++
		}
	}
	return count
}

// View returns the stable secret-free public host projection.
func View(connection config.Connection) HostView {
	port := connection.Port
	if port == 0 {
		port = 22
	}
	auth := "none"
	switch {
	case connection.KeyName != "" && connection.Password != "":
		auth = "key+password"
	case connection.KeyName != "":
		auth = "key"
	case connection.Password != "":
		auth = "password"
	}
	return HostView{
		Name: connection.Name, Host: connection.Host, Port: port, User: connection.User,
		Group: connection.Group, Auth: auth, KeyName: connection.KeyName,
	}
}

// MutationView is the stable, secret-free public view of a pending mutation.
type MutationView struct {
	ID          string   `json:"id"`
	Alias       string   `json:"alias,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	KeyName     string   `json:"key_name,omitempty"`
	Operation   string   `json:"operation"`
	CreatedAt   string   `json:"created_at"`
	Connections *int     `json:"connections,omitempty"`
	Keys        *int     `json:"keys,omitempty"`
}

// PublicationReceipt is the stable secret-free result of an explicit reviewed
// publication.
type PublicationReceipt struct {
	OK        bool           `json:"ok"`
	Action    string         `json:"action"`
	Scope     string         `json:"scope"`
	Only      string         `json:"transaction_id,omitempty"`
	Preflight []MutationView `json:"preflight"`
	Remaining []MutationView `json:"remaining_mutations"`
}

// PublicationRecovery is the additive, secret-free status projection of one
// outstanding durable publishing intent.
type PublicationRecovery struct {
	State                string   `json:"state"`
	Scope                string   `json:"scope"`
	TransactionIDs       []string `json:"transaction_ids"`
	PrerequisiteExists   bool     `json:"prerequisite_remote_exists"`
	PrerequisiteIdentity string   `json:"prerequisite_remote_identity,omitempty"`
	TargetIdentity       string   `json:"target_encrypted_blob_identity"`
	ObservedExists       bool     `json:"observed_remote_exists,omitempty"`
	ObservedIdentity     string   `json:"observed_remote_identity,omitempty"`
}

type publishingIntent struct {
	Version              int                           `json:"version"`
	State                string                        `json:"state"`
	Scope                string                        `json:"scope"`
	TransactionIDs       []string                      `json:"transaction_ids"`
	Transactions         []publishingIntentTransaction `json:"transactions"`
	PrerequisiteExists   bool                          `json:"prerequisite_remote_exists"`
	PrerequisiteIdentity string                        `json:"prerequisite_remote_identity,omitempty"`
	TargetIdentity       string                        `json:"target_encrypted_blob_identity"`
	ObservedExists       bool                          `json:"observed_remote_exists,omitempty"`
	ObservedIdentity     string                        `json:"observed_remote_identity,omitempty"`
}

// publishingIntentTransaction is the minimum receipt metadata that can outlive
// local finalization. TransactionIDs remain the reconciliation authority.
type publishingIntentTransaction struct {
	Operation string `json:"operation"`
	CreatedAt string `json:"created_at"`
}

// publishingIntentV1 exists only to strictly decode and sanitize sidecars
// written before the private projection was separated from MutationView.
type publishingIntentV1 struct {
	Version              int                                   `json:"version"`
	State                string                                `json:"state"`
	Scope                string                                `json:"scope"`
	TransactionIDs       []string                              `json:"transaction_ids"`
	Transactions         []publishingIntentTransactionV1Legacy `json:"transactions"`
	PrerequisiteExists   bool                                  `json:"prerequisite_remote_exists"`
	PrerequisiteIdentity string                                `json:"prerequisite_remote_identity,omitempty"`
	TargetIdentity       string                                `json:"target_encrypted_blob_identity"`
	ObservedExists       bool                                  `json:"observed_remote_exists,omitempty"`
	ObservedIdentity     string                                `json:"observed_remote_identity,omitempty"`
	CreatedAt            string                                `json:"created_at"`
}

// publishingIntentTransactionV1Legacy is the complete known v1 transaction
// schema. Deprecated fields are decoded only so they can be discarded.
type publishingIntentTransactionV1Legacy struct {
	ID          string   `json:"id"`
	Alias       string   `json:"alias,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	KeyName     string   `json:"key_name,omitempty"`
	Operation   string   `json:"operation"`
	CreatedAt   string   `json:"created_at"`
	Connections *int     `json:"connections,omitempty"`
	Keys        *int     `json:"keys,omitempty"`
}

const (
	publishingIntentVersion   = 2
	publishingIntentV1Version = 1
	// A canonical v2 intent at the 1,024-transaction ceiling is below 256
	// KiB and uses at most 7,192 JSON tokens. The larger byte/token budgets
	// retain migration headroom for v1's deprecated diagnostics. V1's deepest
	// known shape is four containers, so 16 levels also leaves 4x headroom.
	maxPublishingIntentDocumentBytes = 512 * 1024
	maxPublishingIntentJSONDepth     = 16
	maxPublishingIntentJSONTokens    = 32 * 1024
	maxPublishingIntentTransactions  = 1024
	intentPrepared                   = "prepared"
	intentReady                      = "ready"
	intentAmbiguous                  = "ambiguous"
	intentDivergent                  = "divergent"
	intentFinalizationFailed         = "finalization_failed"
)

var errInvalidPublishingIntentDocument = errors.New("publishing intent document is invalid")

// Pending returns stable secret-free pending views in ledger order.
func Pending(v *config.Vault) []MutationView {
	if v == nil {
		return []MutationView{}
	}
	return mutationViews(v.PendingMutations)
}

// Publish performs secret-free dependency preflight, exact projection, durable
// intent persistence, opaque publication, target confirmation, and exact local
// finalization under an active cross-process publication session. Pending IDs
// are never removed before target equality.
func (s *PublicationSession) Publish(t *Transaction, v *config.Vault, only string) (PublicationReceipt, error) {
	if !s.active() {
		return PublicationReceipt{}, fmt.Errorf("active publication session is required")
	}
	if t.sync == nil {
		return PublicationReceipt{}, fmt.Errorf("sync transaction is required for publication")
	}
	reconciled, recovery, err := t.reconcilePublishingIntent()
	if err != nil {
		return PublicationReceipt{}, err
	}
	if recovery != nil && recovery.State == "confirmed" {
		return reconciled, nil
	}

	publicationOnly := only
	var projection projection
	if recovery != nil && recovery.State == "pending" {
		projection, err = projectTransactionIDs(v, recovery.TransactionIDs)
		if recovery.Scope == "only" && len(recovery.TransactionIDs) == 1 {
			publicationOnly = recovery.TransactionIDs[0]
		} else {
			publicationOnly = ""
		}
	} else {
		projection, err = project(v, only)
	}
	if err != nil {
		return PublicationReceipt{}, err
	}
	if len(projection.Selected) == 0 {
		if err := t.sync.VerifyEmptyPublication(); err != nil {
			return PublicationReceipt{}, err
		}
		receipt := publicationReceipt(publicationOnly, projection.Selected, v)
		receipt.Action = "noop"
		return receipt, nil
	}
	blob, err := config.EncryptVault(projection.Vault, t.masterPass)
	if err != nil {
		return PublicationReceipt{}, err
	}

	scope := "all"
	if publicationOnly != "" {
		scope = "only"
	}
	intent := publishingIntent{
		Version:        publishingIntentVersion,
		State:          intentPrepared,
		Scope:          scope,
		TargetIdentity: synctransaction.PublicationTargetIdentity(blob),
	}
	for _, mutation := range projection.Selected {
		intent.TransactionIDs = append(intent.TransactionIDs, mutation.ID)
	}
	intent.Transactions = publishingIntentTransactions(projection.Selected)
	cached, err := t.sync.CachedPublicationPrerequisite()
	if err != nil {
		return PublicationReceipt{}, err
	}
	intent.PrerequisiteExists = cached.Exists
	intent.PrerequisiteIdentity = cached.Value

	if err := injectPublicationFault("before_intent_persist"); err != nil {
		return PublicationReceipt{}, err
	}
	if err := savePublishingIntent(intent); err != nil {
		return PublicationReceipt{}, err
	}
	if err := injectPublicationFault("after_intent_persist"); err != nil {
		return PublicationReceipt{}, err
	}

	prepared, err := t.sync.PreparePublication(blob)
	if err != nil {
		_ = clearPublishingIntent()
		return PublicationReceipt{}, err
	}
	intent.State = intentReady
	intent.PrerequisiteExists = prepared.Prerequisite.Exists
	intent.PrerequisiteIdentity = prepared.Prerequisite.Value
	if err := savePublishingIntent(intent); err != nil {
		return PublicationReceipt{}, err
	}
	if err := injectPublicationFault("after_prerequisite_persist"); err != nil {
		return PublicationReceipt{}, err
	}
	if err := injectPublicationFault("before_request_send"); err != nil {
		return PublicationReceipt{}, err
	}

	remote, err := t.sync.SendPublication(blob, prepared)
	if err != nil {
		switch {
		case errors.Is(err, synctransaction.ErrPushNotSent),
			errors.Is(err, synctransaction.ErrPushRejected):
			_ = clearPublishingIntent()
		case errors.Is(err, synctransaction.ErrPushAmbiguous):
			intent.State = intentAmbiguous
			_ = savePublishingIntent(intent)
		case errors.Is(err, synctransaction.ErrConflict):
			intent.State = intentDivergent
			intent.ObservedExists = remote.Exists
			intent.ObservedIdentity = remote.Value
			_ = savePublishingIntent(intent)
		}
		return PublicationReceipt{}, err
	}
	if remote.Value != intent.TargetIdentity {
		return PublicationReceipt{}, fmt.Errorf("%w: target identity was not confirmed", synctransaction.ErrConflict)
	}
	if err := injectPublicationFault("after_response_receipt"); err != nil {
		return PublicationReceipt{}, err
	}
	receipt, err := t.finalizePublishingIntent(intent)
	if err != nil {
		intent.State = intentFinalizationFailed
		_ = savePublishingIntent(intent)
		return PublicationReceipt{}, err
	}
	return receipt, nil
}

// ReconcilePublishingIntent resolves durable recovery state for status without
// retrying a PUT or absorbing any newly pending mutation.
func (t *Transaction) ReconcilePublishingIntent() (*PublicationRecovery, error) {
	session, err := BeginPublication()
	if err != nil {
		return nil, err
	}
	defer func() { _ = session.Close() }()
	_, recovery, err := t.reconcilePublishingIntent()
	return recovery, err
}

func (t *Transaction) reconcilePublishingIntent() (PublicationReceipt, *PublicationRecovery, error) {
	intent, err := loadPublishingIntent()
	if err != nil {
		if os.IsNotExist(err) {
			return PublicationReceipt{}, nil, nil
		}
		return PublicationReceipt{}, nil, err
	}
	if intent.State == intentPrepared {
		if err := clearPublishingIntent(); err != nil {
			return PublicationReceipt{}, recoveryView(intent, "pending"), err
		}
		return PublicationReceipt{}, recoveryView(intent, "pending"), nil
	}
	if intent.State == intentFinalizationFailed {
		receipt, err := t.finalizePublishingIntent(intent)
		if err != nil {
			_ = savePublishingIntent(intent)
			return PublicationReceipt{}, recoveryView(intent, intentFinalizationFailed), err
		}
		return receipt, recoveryView(intent, "confirmed"), nil
	}
	if t.sync.Offline() {
		return PublicationReceipt{}, recoveryView(intent, intent.State), nil
	}

	remote, err := t.sync.ObservePublicationIdentity()
	if err != nil {
		return PublicationReceipt{}, recoveryView(intent, intent.State), err
	}
	target := synctransaction.BlobIdentity{Exists: true, Value: intent.TargetIdentity}
	prerequisite := synctransaction.BlobIdentity{
		Exists: intent.PrerequisiteExists,
		Value:  intent.PrerequisiteIdentity,
	}
	switch {
	case equalBlobIdentity(remote, target):
		receipt, err := t.finalizePublishingIntent(intent)
		if err != nil {
			intent.State = intentFinalizationFailed
			_ = savePublishingIntent(intent)
			return PublicationReceipt{}, recoveryView(intent, "finalization_failed"), err
		}
		return receipt, recoveryView(intent, "confirmed"), nil
	case equalBlobIdentity(remote, prerequisite):
		if err := clearPublishingIntent(); err != nil {
			return PublicationReceipt{}, recoveryView(intent, "pending"), err
		}
		return PublicationReceipt{}, recoveryView(intent, "pending"), nil
	default:
		intent.State = intentDivergent
		intent.ObservedExists = remote.Exists
		intent.ObservedIdentity = remote.Value
		if err := savePublishingIntent(intent); err != nil {
			return PublicationReceipt{}, recoveryView(intent, intentDivergent), err
		}
		return PublicationReceipt{}, recoveryView(intent, intentDivergent),
			fmt.Errorf("%w: remote publication identity is neither prerequisite nor target", synctransaction.ErrConflict)
	}
}

func (t *Transaction) finalizePublishingIntent(intent publishingIntent) (PublicationReceipt, error) {
	current, err := config.Load(t.masterPass)
	if err != nil {
		return PublicationReceipt{}, fmt.Errorf("load pending publication for finalization: %w", err)
	}
	projection, err := projectTransactionIDs(current, intent.TransactionIDs)
	if err != nil {
		return PublicationReceipt{}, err
	}
	localAfter := cloneVault(current)
	if len(projection.Selected) > 0 {
		if err := injectPublicationFault("before_local_finalization"); err != nil {
			return PublicationReceipt{}, err
		}
		markPublished(localAfter, projection.Selected, projection.Vault)
		if err := config.Save(localAfter, t.masterPass); err != nil {
			return PublicationReceipt{}, fmt.Errorf("finalize confirmed publication: %w", err)
		}
		if err := injectPublicationFault("after_local_finalization"); err != nil {
			return PublicationReceipt{}, err
		}
	}
	t.sync.ConfirmPublication(intent.TargetIdentity)
	if err := clearPublishingIntent(); err != nil {
		return PublicationReceipt{}, fmt.Errorf("clear finalized publishing intent: %w", err)
	}
	only := ""
	if intent.Scope == "only" && len(intent.TransactionIDs) == 1 {
		only = intent.TransactionIDs[0]
	}
	receipt := publicationReceipt(only, projection.Selected, localAfter)
	if len(projection.Selected) == 0 {
		receipt.Preflight = publishingIntentMutationViews(intent.Transactions, intent.TransactionIDs)
	}
	return receipt, nil
}

func publicationReceipt(only string, selected []config.PendingMutation, localAfter *config.Vault) PublicationReceipt {
	scope := "all"
	if only != "" {
		scope = "only"
	}
	return PublicationReceipt{
		OK: true, Action: "pushed", Scope: scope, Only: only,
		Preflight: mutationViews(selected), Remaining: Pending(localAfter),
	}
}

func equalBlobIdentity(left, right synctransaction.BlobIdentity) bool {
	return left.Exists == right.Exists && (!left.Exists || left.Value == right.Value)
}

func publishingIntentPath() string {
	return filepath.Join(config.Dir(), "publishing-intent.json")
}

func savePublishingIntent(intent publishingIntent) error {
	if err := validatePublishingIntent(intent); err != nil {
		return err
	}
	data, err := json.MarshalIndent(intent, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxPublishingIntentDocumentBytes {
		return errInvalidPublishingIntentDocument
	}
	return config.WritePrivateFile(publishingIntentPath(), data)
}

func loadPublishingIntent() (publishingIntent, error) {
	file, err := os.Open(publishingIntentPath()) //nolint:gosec // fixed private recovery path under the SSM config directory
	if err != nil {
		return publishingIntent{}, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return publishingIntent{}, err
	}
	data, err := readPublishingIntentDocument(file, info.Size())
	if err != nil {
		return publishingIntent{}, err
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := decodePublishingIntent(data, &header, false); err != nil {
		return publishingIntent{}, err
	}
	switch header.Version {
	case publishingIntentVersion:
		var intent publishingIntent
		if err := decodePublishingIntent(data, &intent, true); err != nil {
			return publishingIntent{}, err
		}
		if err := validatePublishingIntent(intent); err != nil {
			return publishingIntent{}, err
		}
		return intent, nil
	case publishingIntentV1Version:
		var legacy publishingIntentV1
		if err := decodePublishingIntent(data, &legacy, true); err != nil {
			return publishingIntent{}, err
		}
		intent, err := sanitizePublishingIntentV1(legacy)
		if err != nil {
			return publishingIntent{}, err
		}
		if err := validatePublishingIntent(intent); err != nil {
			return publishingIntent{}, err
		}
		if err := savePublishingIntent(intent); err != nil {
			return publishingIntent{}, fmt.Errorf("sanitize version 1 publishing intent: %w", err)
		}
		return intent, nil
	default:
		return publishingIntent{}, errors.New("publishing intent version is unsupported")
	}
}

// readPublishingIntentDocument owns reader and closes it before returning.
func readPublishingIntentDocument(reader io.ReadCloser, size int64) ([]byte, error) {
	if size < 0 || size > maxPublishingIntentDocumentBytes {
		_ = reader.Close()
		return nil, errInvalidPublishingIntentDocument
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxPublishingIntentDocumentBytes+1))
	closeErr := reader.Close()
	if err != nil {
		return nil, err
	}
	if len(data) > maxPublishingIntentDocumentBytes {
		return nil, errInvalidPublishingIntentDocument
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return data, nil
}

func decodePublishingIntent(data []byte, target any, strict bool) error {
	if err := validateUniqueJSONMembers(data); err != nil {
		return errInvalidPublishingIntentDocument
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(target); err != nil {
		return errInvalidPublishingIntentDocument
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errInvalidPublishingIntentDocument
	}
	return nil
}

func validateUniqueJSONMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	budget := uniqueJSONBudget{}
	if err := consumeUniqueJSONValue(decoder, &budget, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("JSON document contains trailing data")
	}
	return nil
}

type uniqueJSONBudget struct {
	tokens int
}

func (budget *uniqueJSONBudget) nextToken(decoder *json.Decoder) (json.Token, error) {
	if budget.tokens >= maxPublishingIntentJSONTokens {
		return nil, errors.New("JSON document has too many tokens")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	budget.tokens++
	return token, nil
}

func consumeUniqueJSONValue(decoder *json.Decoder, budget *uniqueJSONBudget, depth int) error {
	token, err := budget.nextToken(decoder)
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxPublishingIntentJSONDepth {
		return errors.New("JSON document nesting is too deep")
	}
	switch delimiter {
	case '{':
		members := make(map[string]struct{})
		for decoder.More() {
			token, err := budget.nextToken(decoder)
			if err != nil {
				return err
			}
			member, ok := token.(string)
			if !ok {
				return errors.New("JSON object member name is invalid")
			}
			if _, duplicate := members[member]; duplicate {
				return errors.New("JSON object contains a duplicate member")
			}
			members[member] = struct{}{}
			if err := consumeUniqueJSONValue(decoder, budget, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder, budget, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("JSON value delimiter is invalid")
	}
	_, err = budget.nextToken(decoder)
	return err
}

func sanitizePublishingIntentV1(legacy publishingIntentV1) (publishingIntent, error) {
	if len(legacy.Transactions) != len(legacy.TransactionIDs) {
		return publishingIntent{}, errors.New("publishing intent transaction metadata is incomplete")
	}
	if _, err := time.Parse(time.RFC3339Nano, legacy.CreatedAt); err != nil {
		return publishingIntent{}, errors.New("publishing intent creation time is invalid")
	}
	for index, transaction := range legacy.Transactions {
		if transaction.ID != legacy.TransactionIDs[index] {
			return publishingIntent{}, errors.New("publishing intent transaction metadata order changed")
		}
	}
	intent := publishingIntent{
		Version:              publishingIntentVersion,
		State:                legacy.State,
		Scope:                legacy.Scope,
		TransactionIDs:       append([]string(nil), legacy.TransactionIDs...),
		PrerequisiteExists:   legacy.PrerequisiteExists,
		PrerequisiteIdentity: legacy.PrerequisiteIdentity,
		TargetIdentity:       legacy.TargetIdentity,
		ObservedExists:       legacy.ObservedExists,
		ObservedIdentity:     legacy.ObservedIdentity,
	}
	for _, transaction := range legacy.Transactions {
		intent.Transactions = append(intent.Transactions, publishingIntentTransaction{
			Operation: transaction.Operation, CreatedAt: transaction.CreatedAt,
		})
	}
	return intent, nil
}

func validatePublishingIntent(intent publishingIntent) error {
	if intent.Version != publishingIntentVersion {
		return errors.New("publishing intent version is unsupported")
	}
	switch intent.State {
	case intentPrepared, intentReady, intentAmbiguous, intentDivergent, intentFinalizationFailed:
	default:
		return errors.New("publishing intent state is invalid")
	}
	if intent.Scope != "all" && intent.Scope != "only" {
		return errors.New("publishing intent scope is invalid")
	}
	if len(intent.TransactionIDs) > maxPublishingIntentTransactions ||
		len(intent.Transactions) > maxPublishingIntentTransactions {
		return errInvalidPublishingIntentDocument
	}
	if len(intent.TransactionIDs) == 0 {
		return errors.New("publishing intent requires transaction IDs")
	}
	if intent.Scope == "only" && len(intent.TransactionIDs) != 1 {
		return errors.New("only publishing intent requires exactly one transaction ID")
	}
	if len(intent.Transactions) != len(intent.TransactionIDs) {
		return errors.New("publishing intent transaction metadata is incomplete")
	}
	seen := make(map[string]bool, len(intent.TransactionIDs))
	for index, id := range intent.TransactionIDs {
		if id == "" || seen[id] {
			return errors.New("publishing intent transaction IDs are invalid")
		}
		if !validPublishingIntentOperation(intent.Transactions[index].Operation) {
			return errors.New("publishing intent transaction operation is invalid")
		}
		if _, err := time.Parse(time.RFC3339Nano, intent.Transactions[index].CreatedAt); err != nil {
			return errors.New("publishing intent transaction creation time is invalid")
		}
		seen[id] = true
	}
	if !opaqueIdentityPattern.MatchString(intent.TargetIdentity) {
		return errors.New("publishing intent target identity is invalid")
	}
	if intent.PrerequisiteExists && !opaqueIdentityPattern.MatchString(intent.PrerequisiteIdentity) {
		return errors.New("publishing intent prerequisite identity is invalid")
	}
	if !intent.PrerequisiteExists && intent.PrerequisiteIdentity != "" {
		return errors.New("absent publishing intent prerequisite has an identity")
	}
	if intent.ObservedExists && !opaqueIdentityPattern.MatchString(intent.ObservedIdentity) {
		return errors.New("publishing intent observed identity is invalid")
	}
	if !intent.ObservedExists && intent.ObservedIdentity != "" {
		return errors.New("absent publishing intent observation has an identity")
	}
	return nil
}

func validPublishingIntentOperation(operation string) bool {
	switch operation {
	case "created", "updated", "removed", "saved_key_removed", "import_merged", "import_replaced":
		return true
	default:
		return false
	}
}

var opaqueIdentityPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func clearPublishingIntent() error {
	return config.RemovePrivateFile(publishingIntentPath())
}

func recoveryView(intent publishingIntent, state string) *PublicationRecovery {
	return &PublicationRecovery{
		State: state, Scope: intent.Scope,
		TransactionIDs:       append([]string(nil), intent.TransactionIDs...),
		PrerequisiteExists:   intent.PrerequisiteExists,
		PrerequisiteIdentity: intent.PrerequisiteIdentity,
		TargetIdentity:       intent.TargetIdentity,
		ObservedExists:       intent.ObservedExists,
		ObservedIdentity:     intent.ObservedIdentity,
	}
}

func injectPublicationFault(point string) error {
	if publicationFaultInjection != "enabled" {
		return nil
	}
	switch os.Getenv("SSM_TEST_PUBLICATION_FAULT") {
	case point:
		os.Exit(86)
	case point + "_error":
		return fmt.Errorf("test publication fault at %s", point)
	default:
		return nil
	}
	return nil
}

func mutationViews(mutations []config.PendingMutation) []MutationView {
	views := make([]MutationView, 0, len(mutations))
	for _, mutation := range mutations {
		view := MutationView{
			ID: mutation.ID, Alias: mutation.Alias, Aliases: mutation.Aliases,
			KeyName: mutation.KeyName, Operation: mutation.Operation,
			CreatedAt: mutation.CreatedAt,
		}
		if mutation.BulkAfter != nil {
			connections, keys := mutation.ConnectionCount, mutation.KeyCount
			view.Connections, view.Keys = &connections, &keys
		} else if mutation.KeyName != "" {
			keys := mutation.KeyCount
			view.Keys = &keys
		}
		views = append(views, view)
	}
	return views
}

func publishingIntentTransactions(mutations []config.PendingMutation) []publishingIntentTransaction {
	transactions := make([]publishingIntentTransaction, 0, len(mutations))
	for _, mutation := range mutations {
		transactions = append(transactions, publishingIntentTransaction{
			Operation: mutation.Operation, CreatedAt: mutation.CreatedAt,
		})
	}
	return transactions
}

func publishingIntentMutationViews(transactions []publishingIntentTransaction, transactionIDs []string) []MutationView {
	views := make([]MutationView, 0, len(transactions))
	for index, transaction := range transactions {
		views = append(views, MutationView{
			ID: transactionIDs[index], Operation: transaction.Operation, CreatedAt: transaction.CreatedAt,
		})
	}
	return views
}

// Dependency is a safe explanation of one pending prerequisite. It contains no
// connection credentials or saved-key material.
type Dependency struct {
	ID          string
	Alias       string
	Aliases     []string
	Operation   string
	CreatedAt   string
	KeyName     string
	Connections int
	Keys        int
	Bulk        bool
	Reason      string
}

// DependencyError reports the complete deterministic prerequisite set for one
// rejected exact publication scope.
type DependencyError struct {
	Selected string
	Required []Dependency
}

func (e *DependencyError) Error() string {
	if e == nil {
		return "inventory transaction dependencies are unsatisfied"
	}
	var message strings.Builder
	fmt.Fprintf(&message, "transaction %q requires pending transactions:", e.Selected)
	for _, dependency := range e.Required {
		fmt.Fprintf(
			&message,
			` id=%q`,
			dependency.ID,
		)
		if dependency.Alias != "" {
			fmt.Fprintf(&message, ` alias=%q`, dependency.Alias)
		}
		if len(dependency.Aliases) > 0 {
			fmt.Fprintf(&message, ` aliases=%q`, strings.Join(dependency.Aliases, ","))
		}
		fmt.Fprintf(
			&message,
			` operation=%q created_at=%q`,
			dependency.Operation,
			dependency.CreatedAt,
		)
		if dependency.KeyName != "" {
			fmt.Fprintf(&message, ` key_name=%q`, dependency.KeyName)
		}
		if dependency.Bulk || dependency.Connections > 0 {
			fmt.Fprintf(&message, ` connections=%d`, dependency.Connections)
		}
		if dependency.Bulk || dependency.Keys > 0 {
			fmt.Fprintf(&message, ` keys=%d`, dependency.Keys)
		}
		fmt.Fprintf(&message, ` reason=%q;`, dependency.Reason)
	}
	return strings.TrimSuffix(message.String(), ";")
}

type projection struct {
	Vault    *config.Vault
	Selected []config.PendingMutation
}

// Preflight reports safe unsatisfied prerequisites without constructing or
// exposing a decrypted publication projection.
func Preflight(v *config.Vault, only string) ([]Dependency, error) {
	if err := validateLedger(v); err != nil {
		return nil, err
	}
	if only == "" {
		return []Dependency{}, nil
	}
	selectedIndex := pendingIndex(v.PendingMutations, only)
	if selectedIndex < 0 {
		return nil, fmt.Errorf("pending transaction %q not found", only)
	}
	required := dependencies(v.PendingMutations, selectedIndex)
	if len(required) > 0 {
		return required, &DependencyError{Selected: only, Required: required}
	}
	return []Dependency{}, nil
}

func project(v *config.Vault, only string) (projection, error) {
	if _, err := Preflight(v, only); err != nil {
		return projection{}, err
	}
	if v.PendingBase == nil || len(v.PendingMutations) == 0 {
		return projection{Vault: inventoryOnly(v)}, nil
	}
	selected := make([]config.PendingMutation, 0)
	if only == "" {
		selected = append(selected, v.PendingMutations...)
	} else {
		selectedIndex := pendingIndex(v.PendingMutations, only)
		selected = append(selected, v.PendingMutations[selectedIndex])
	}

	projected := &config.Vault{
		Connections: append([]config.Connection(nil), v.PendingBase.Connections...),
		Keys:        append([]config.SSHKey(nil), v.PendingBase.Keys...),
	}
	for _, mutation := range selected {
		applyMutation(projected, mutation)
	}
	return projection{Vault: projected, Selected: selected}, nil
}

func projectTransactionIDs(v *config.Vault, ids []string) (projection, error) {
	if err := validateLedger(v); err != nil {
		return projection{}, err
	}
	selected := make([]config.PendingMutation, 0, len(ids))
	previousIndex := -1
	missing := 0
	for _, id := range ids {
		index := pendingIndex(v.PendingMutations, id)
		if index < 0 {
			missing++
			continue
		}
		if index <= previousIndex {
			return projection{}, fmt.Errorf("publishing intent transaction order changed")
		}
		previousIndex = index
		selected = append(selected, v.PendingMutations[index])
	}
	if missing == len(ids) {
		return projection{Vault: inventoryOnly(v)}, nil
	}
	if missing != 0 {
		return projection{}, fmt.Errorf("publishing intent transaction set was partially finalized")
	}
	if v.PendingBase == nil {
		return projection{}, fmt.Errorf("publishing intent transactions require a pending base")
	}
	projected := &config.Vault{
		Connections: append([]config.Connection(nil), v.PendingBase.Connections...),
		Keys:        append([]config.SSHKey(nil), v.PendingBase.Keys...),
	}
	for _, mutation := range selected {
		applyMutation(projected, mutation)
	}
	return projection{Vault: projected, Selected: selected}, nil
}

func validateLedger(v *config.Vault) error {
	if v == nil {
		return fmt.Errorf("inventory vault is required")
	}
	switch {
	case v.PendingBase == nil && len(v.PendingMutations) != 0:
		return fmt.Errorf("pending mutations require a pending base")
	case v.PendingBase != nil && len(v.PendingMutations) == 0:
		return fmt.Errorf("pending base requires at least one pending mutation")
	}
	seen := make(map[string]bool, len(v.PendingMutations))
	for _, mutation := range v.PendingMutations {
		if mutation.ID == "" {
			return fmt.Errorf("pending transaction ID must not be empty")
		}
		if seen[mutation.ID] {
			return fmt.Errorf("pending transaction ID %q is duplicated", mutation.ID)
		}
		seen[mutation.ID] = true
	}
	return nil
}

func pendingIndex(mutations []config.PendingMutation, id string) int {
	for i := range mutations {
		if mutations[i].ID == id {
			return i
		}
	}
	return -1
}

type dependencyEdge struct {
	index   int
	keyName string
	reason  string
}

func dependencies(mutations []config.PendingMutation, selectedIndex int) []Dependency {
	edges := make([][]dependencyEdge, selectedIndex+1)
	for target := 0; target <= selectedIndex; target++ {
		edges[target] = directDependencyEdges(mutations, target)
	}
	required := make(map[int]Dependency)
	var collect func(int)
	collect = func(target int) {
		for _, edge := range edges[target] {
			collect(edge.index)
			if _, exists := required[edge.index]; exists {
				continue
			}
			mutation := mutations[edge.index]
			required[edge.index] = Dependency{
				ID: mutation.ID, Alias: mutation.Alias, Aliases: mutation.Aliases,
				Operation: mutation.Operation, CreatedAt: mutation.CreatedAt,
				KeyName: edge.keyName, Connections: mutation.ConnectionCount,
				Keys: mutation.KeyCount, Bulk: mutation.BulkAfter != nil, Reason: edge.reason,
			}
		}
	}
	collect(selectedIndex)

	indexes := make([]int, 0, len(required))
	for index := range required {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	result := make([]Dependency, 0, len(indexes))
	for _, index := range indexes {
		result = append(result, required[index])
	}
	return result
}

func directDependencyEdges(mutations []config.PendingMutation, selectedIndex int) []dependencyEdge {
	selected := mutations[selectedIndex]
	required := make([]dependencyEdge, 0)
	for i := 0; i < selectedIndex; i++ {
		earlier := mutations[i]
		if selected.BulkAfter != nil || earlier.BulkAfter != nil {
			required = append(required, dependencyEdge{index: i, reason: "inventory_order"})
			continue
		}
		if earlier.Alias != "" && earlier.Alias == selected.Alias {
			required = append(required, dependencyEdge{index: i, reason: "alias_order"})
			continue
		}
		dependent := false
		for _, keyName := range changedKeyNames(selected.KeysBefore, selected.KeysAfter) {
			selectedChange := keyChange(selected.KeysBefore, selected.KeysAfter, keyName)
			if earlierChange := keyChange(earlier.KeysBefore, earlier.KeysAfter, keyName); earlierChange != "" {
				required = append(required, dependencyEdge{
					index: i, keyName: keyName, reason: keyLifecycleReason(earlier, keyName, earlierChange),
				})
				dependent = true
				break
			}
			if (selectedChange == "replace" || selectedChange == "delete") &&
				referenceRemoved(earlier, keyName) {
				required = append(required, dependencyEdge{
					index: i, keyName: keyName, reason: "saved_key_reference",
				})
				dependent = true
				break
			}
		}
		if dependent || selected.After == nil || selected.After.KeyName == "" {
			continue
		}
		keyName := selected.After.KeyName
		if earlierChange := keyChange(earlier.KeysBefore, earlier.KeysAfter, keyName); earlierChange != "" {
			switch earlierChange {
			case "create", "replace":
				required = append(required, dependencyEdge{
					index: i, keyName: keyName, reason: keyLifecycleReason(earlier, keyName, earlierChange),
				})
			}
		}
	}
	return required
}

func changedKeyNames(before, after []config.SSHKey) []string {
	names := make(map[string]bool, len(before)+len(after))
	for _, key := range before {
		names[key.Name] = true
	}
	for _, key := range after {
		names[key.Name] = true
	}
	changed := make([]string, 0, len(names))
	for name := range names {
		if keyChange(before, after, name) != "" {
			changed = append(changed, name)
		}
	}
	sort.Strings(changed)
	return changed
}

func keyLifecycleReason(mutation config.PendingMutation, keyName, change string) string {
	switch change {
	case "create":
		if mutation.Before != nil && mutation.After != nil &&
			mutation.Before.KeyName != "" && mutation.Before.KeyName != keyName &&
			mutation.After.KeyName == keyName {
			return "saved_key_rename"
		}
		return "saved_key_create"
	case "replace":
		return "saved_key_replace"
	case "delete":
		if mutation.Before != nil && mutation.Before.KeyName == keyName && mutation.After == nil {
			return "saved_key_prune"
		}
		return "saved_key_delete"
	default:
		return "saved_key_reference"
	}
}

func referenceRemoved(mutation config.PendingMutation, keyName string) bool {
	return mutation.Before != nil && mutation.Before.KeyName == keyName &&
		(mutation.After == nil || mutation.After.KeyName != keyName)
}

func keyChange(before, after []config.SSHKey, name string) string {
	previous, next := keyByName(before, name), keyByName(after, name)
	switch {
	case previous == nil && next != nil:
		return "create"
	case previous != nil && next == nil:
		return "delete"
	case previous != nil && next != nil && *previous != *next:
		return "replace"
	default:
		return ""
	}
}

func keyByName(keys []config.SSHKey, name string) *config.SSHKey {
	for i := range keys {
		if keys[i].Name == name {
			return &keys[i]
		}
	}
	return nil
}

func applyMutation(v *config.Vault, mutation config.PendingMutation) {
	if mutation.BulkAfter != nil {
		v.Connections = append([]config.Connection(nil), mutation.BulkAfter.Connections...)
		v.Keys = append([]config.SSHKey(nil), mutation.BulkAfter.Keys...)
		return
	}
	if mutation.KeyName == "" {
		idx := exactConnectionIndex(v, mutation.Alias)
		switch {
		case mutation.After == nil:
			if idx >= 0 {
				v.Connections = append(v.Connections[:idx], v.Connections[idx+1:]...)
			}
		case idx >= 0:
			v.Connections[idx] = *mutation.After
		default:
			v.Connections = append(v.Connections, *mutation.After)
		}
	}
	applyKeyDelta(v, mutation.KeysBefore, mutation.KeysAfter)
	sort.SliceStable(v.Connections, func(i, j int) bool {
		return v.Connections[i].Name < v.Connections[j].Name
	})
}

func applyKeyDelta(v *config.Vault, before, after []config.SSHKey) {
	beforeByName := make(map[string]config.SSHKey, len(before))
	afterByName := make(map[string]config.SSHKey, len(after))
	for _, key := range before {
		beforeByName[key.Name] = key
	}
	for _, key := range after {
		afterByName[key.Name] = key
	}
	for name, previous := range beforeByName {
		next, exists := afterByName[name]
		if exists && next == previous {
			continue
		}
		removeKeyByName(v, name)
		if exists {
			v.Keys = append(v.Keys, next)
		}
	}
	for name, next := range afterByName {
		if _, existed := beforeByName[name]; !existed {
			removeKeyByName(v, name)
			v.Keys = append(v.Keys, next)
		}
	}
	sort.SliceStable(v.Keys, func(i, j int) bool { return v.Keys[i].Name < v.Keys[j].Name })
}

func inventoryOnly(v *config.Vault) *config.Vault {
	return &config.Vault{
		Connections: append([]config.Connection(nil), v.Connections...),
		Keys:        append([]config.SSHKey(nil), v.Keys...),
	}
}

func markPublished(v *config.Vault, selected []config.PendingMutation, projected *config.Vault) {
	if len(selected) == 0 {
		return
	}
	published := make(map[string]bool, len(selected))
	for _, mutation := range selected {
		published[mutation.ID] = true
	}
	remaining := v.PendingMutations[:0]
	for _, mutation := range v.PendingMutations {
		if !published[mutation.ID] {
			remaining = append(remaining, mutation)
		}
	}
	v.PendingMutations = remaining
	if len(remaining) == 0 {
		v.PendingBase = nil
	} else {
		v.PendingBase = snapshotInventory(projected)
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

func removeKeyByName(v *config.Vault, name string) bool {
	for i := range v.Keys {
		if v.Keys[i].Name == name {
			v.Keys = append(v.Keys[:i], v.Keys[i+1:]...)
			return true
		}
	}
	return false
}
