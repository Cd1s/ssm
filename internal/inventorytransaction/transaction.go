// Package inventorytransaction owns reviewed inventory mutation and exact-scope
// publication policy. Decrypted candidate state stays inside this module; sync
// receives only opaque encrypted vault bytes.
package inventorytransaction

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
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
	ID        string `json:"id"`
	Alias     string `json:"alias"`
	Operation string `json:"operation"`
	CreatedAt string `json:"created_at"`
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

// Pending returns stable secret-free pending views in ledger order.
func Pending(v *config.Vault) []MutationView {
	if v == nil {
		return []MutationView{}
	}
	return mutationViews(v.PendingMutations)
}

// Publish performs secret-free dependency preflight, exact projection, local
// pre-persistence, opaque publication, and the bounded compatibility rollback
// retained until durable intent reconciliation is implemented.
func (t *Transaction) Publish(v *config.Vault, only string) (PublicationReceipt, error) {
	if t.sync == nil {
		return PublicationReceipt{}, fmt.Errorf("sync transaction is required for publication")
	}
	originalBlob, originalBlobErr := os.ReadFile(config.Path())
	originalBlobExists := originalBlobErr == nil
	if originalBlobErr != nil && !os.IsNotExist(originalBlobErr) {
		return PublicationReceipt{}, originalBlobErr
	}
	restoreOriginal := func() {
		if originalBlobExists {
			_ = config.WritePrivateFile(config.Path(), originalBlob)
		}
	}

	projection, err := project(v, only)
	if err != nil {
		return PublicationReceipt{}, err
	}
	blob, err := config.EncryptVault(projection.Vault, t.masterPass)
	if err != nil {
		return PublicationReceipt{}, err
	}
	localAfter := cloneVault(v)
	markPublished(localAfter, projection.Selected, projection.Vault)
	if len(projection.Selected) > 0 {
		if err := config.Save(localAfter, t.masterPass); err != nil {
			return PublicationReceipt{}, err
		}
	}
	if only == "" {
		blob, err = os.ReadFile(config.Path())
		if err != nil {
			restoreOriginal()
			return PublicationReceipt{}, err
		}
	}
	if _, err := t.sync.PushBlob(blob); err != nil {
		restoreOriginal()
		return PublicationReceipt{}, err
	}
	scope := "all"
	if only != "" {
		scope = "only"
	}
	return PublicationReceipt{
		OK: true, Action: "pushed", Scope: scope, Only: only,
		Preflight: mutationViews(projection.Selected), Remaining: Pending(localAfter),
	}, nil
}

func mutationViews(mutations []config.PendingMutation) []MutationView {
	views := make([]MutationView, 0, len(mutations))
	for _, mutation := range mutations {
		views = append(views, MutationView{
			ID: mutation.ID, Alias: mutation.Alias,
			Operation: mutation.Operation, CreatedAt: mutation.CreatedAt,
		})
	}
	return views
}

// Dependency is a safe explanation of one pending prerequisite. It contains no
// connection credentials or saved-key material.
type Dependency struct {
	ID        string
	Alias     string
	Operation string
	KeyName   string
	Reason    string
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
			` id=%q alias=%q operation=%q`,
			dependency.ID,
			dependency.Alias,
			dependency.Operation,
		)
		if dependency.KeyName != "" {
			fmt.Fprintf(&message, ` key_name=%q`, dependency.KeyName)
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
	if only == "" || len(v.PendingMutations) == 0 {
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
				ID: mutation.ID, Alias: mutation.Alias, Operation: mutation.Operation,
				KeyName: edge.keyName, Reason: edge.reason,
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
		if earlier.Alias == selected.Alias {
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
