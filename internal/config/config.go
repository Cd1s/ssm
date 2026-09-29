package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"ssm/internal/vault"
)

type SSHKey struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
}

type Connection struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password,omitempty"`
	KeyName  string `json:"key_name,omitempty"`
	Group    string `json:"group,omitempty"`
}

type Vault struct {
	Connections      []Connection       `json:"connections"`
	Keys             []SSHKey           `json:"keys"`
	PendingBase      *InventorySnapshot `json:"pending_base,omitempty"`
	PendingMutations []PendingMutation  `json:"pending_mutations,omitempty"`
}

type InventorySnapshot struct {
	Connections []Connection `json:"connections"`
	Keys        []SSHKey     `json:"keys"`
}

type PendingMutation struct {
	ID              string             `json:"id"`
	Alias           string             `json:"alias"`
	Aliases         []string           `json:"aliases,omitempty"`
	KeyName         string             `json:"key_name,omitempty"`
	Operation       string             `json:"operation"`
	CreatedAt       string             `json:"created_at"`
	Before          *Connection        `json:"before,omitempty"`
	After           *Connection        `json:"after,omitempty"`
	KeysBefore      []SSHKey           `json:"keys_before"`
	KeysAfter       []SSHKey           `json:"keys_after"`
	BulkBefore      *InventorySnapshot `json:"bulk_before,omitempty"`
	BulkAfter       *InventorySnapshot `json:"bulk_after,omitempty"`
	ConnectionCount int                `json:"connection_count,omitempty"`
	KeyCount        int                `json:"key_count,omitempty"`
}

type MergeConflict struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Winner string `json:"winner"`
}

type MergeReport struct {
	RecordedAt string          `json:"recorded_at,omitempty"`
	Conflicts  []MergeConflict `json:"conflicts"`
}

func (v *Vault) GetKey(name string) *SSHKey {
	for i, k := range v.Keys {
		if k.Name == name {
			return &v.Keys[i]
		}
	}
	return nil
}

func (v *Vault) KeyNames() []string {
	names := make([]string, len(v.Keys))
	for i, k := range v.Keys {
		names[i] = k.Name
	}
	return names
}

func (v *Vault) GroupNames() []string {
	seen := make(map[string]bool)
	var names []string
	for _, c := range v.Connections {
		if c.Group != "" && !seen[c.Group] {
			seen[c.Group] = true
			names = append(names, c.Group)
		}
	}
	return names
}

func (c Connection) SSHArgs() []string {
	var args []string
	if c.Port != 0 && c.Port != 22 {
		args = append(args, "-p", strconv.Itoa(c.Port))
	}
	args = append(args, fmt.Sprintf("%s@%s", c.User, c.Host))
	return args
}

func (c Connection) Display() string {
	port := ""
	if c.Port != 0 && c.Port != 22 {
		port = fmt.Sprintf(":%d", c.Port)
	}
	return fmt.Sprintf("%s@%s%s", c.User, c.Host, port)
}

func Dir() string {
	if configured := filepath.Clean(os.Getenv("SSM_CONFIG_DIR")); configured != "." && configured != "" {
		return configured
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "ssm")
}

func Path() string {
	return filepath.Join(Dir(), "connections.enc")
}

func Exists() bool {
	_, err := os.Stat(Path())
	return err == nil
}

// absentBlobIdentity stands for a vault file that does not exist.
const absentBlobIdentity = "absent"

var (
	loadedBlobMu       sync.Mutex
	loadedBlobIdentity string
	loadedBlobKnown    bool
)

func blobIdentity(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func recordLoadedBlob(identity string) {
	loadedBlobMu.Lock()
	loadedBlobIdentity, loadedBlobKnown = identity, true
	loadedBlobMu.Unlock()
}

// LoadedBlobIdentity returns the identity of the encrypted vault bytes this
// process most recently loaded or saved. Local mutation commands compare it to
// CurrentBlobIdentity under the vault write lock so a vault replaced in the
// meantime (for example by a background pull) is never overwritten.
func LoadedBlobIdentity() (string, bool) {
	loadedBlobMu.Lock()
	defer loadedBlobMu.Unlock()
	return loadedBlobIdentity, loadedBlobKnown
}

// CurrentBlobIdentity reads the identity of the vault file as it is now.
func CurrentBlobIdentity() (string, error) {
	data, err := os.ReadFile(Path())
	if err != nil {
		if os.IsNotExist(err) {
			return absentBlobIdentity, nil
		}
		return "", err
	}
	return blobIdentity(data), nil
}

func Load(masterPass string) (*Vault, error) {
	_ = EnsurePrivateDir(Dir())
	data, err := os.ReadFile(Path())
	if err != nil {
		if os.IsNotExist(err) {
			recordLoadedBlob(absentBlobIdentity)
			return &Vault{}, nil
		}
		return nil, err
	}
	recordLoadedBlob(blobIdentity(data))

	plaintext, err := vault.Decrypt(data, masterPass)
	if err != nil {
		return nil, err
	}

	// Try new Vault format first
	var v Vault
	if err := json.Unmarshal(plaintext, &v); err == nil {
		return &v, nil
	}

	// Migration: old format was just []Connection
	var conns []Connection
	if err := json.Unmarshal(plaintext, &conns); err != nil {
		return nil, err
	}
	return &Vault{Connections: conns}, nil
}

func Save(v *Vault, masterPass string) error {
	encrypted, err := EncryptVault(v, masterPass)
	if err != nil {
		return err
	}

	if err := WritePrivateFile(Path(), encrypted); err != nil {
		return err
	}
	recordLoadedBlob(blobIdentity(encrypted))
	return nil
}

func EncryptVault(v *Vault, masterPass string) ([]byte, error) {
	plaintext, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}

	encrypted, err := vault.Encrypt(plaintext, masterPass)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func MergeVaults(local, remote *Vault) *Vault {
	merged, _ := MergeVaultsWithReport(local, remote)
	return merged
}

func MergeVaultsWithReport(local, remote *Vault) (*Vault, MergeReport) {
	merged := &Vault{}
	report := MergeReport{RecordedAt: time.Now().UTC().Format(time.RFC3339), Conflicts: []MergeConflict{}}

	connMap := make(map[string]Connection)
	var connOrder []string
	for _, c := range local.Connections {
		if _, exists := connMap[c.Name]; !exists {
			connOrder = append(connOrder, c.Name)
		}
		connMap[c.Name] = c
	}
	for _, c := range remote.Connections {
		if previous, exists := connMap[c.Name]; !exists {
			connOrder = append(connOrder, c.Name)
		} else if previous != c {
			report.Conflicts = append(report.Conflicts, MergeConflict{Name: c.Name, Kind: "alias", Winner: "remote"})
		}
		connMap[c.Name] = c
	}
	for _, name := range connOrder {
		merged.Connections = append(merged.Connections, connMap[name])
	}

	keyMap := make(map[string]SSHKey)
	var keyOrder []string
	for _, k := range local.Keys {
		if _, exists := keyMap[k.Name]; !exists {
			keyOrder = append(keyOrder, k.Name)
		}
		keyMap[k.Name] = k
	}
	for _, k := range remote.Keys {
		if previous, exists := keyMap[k.Name]; !exists {
			keyOrder = append(keyOrder, k.Name)
		} else if previous != k {
			report.Conflicts = append(report.Conflicts, MergeConflict{Name: k.Name, Kind: "key_name", Winner: "remote"})
		}
		keyMap[k.Name] = k
	}
	for _, name := range keyOrder {
		merged.Keys = append(merged.Keys, keyMap[name])
	}

	return merged, report
}

func mergeReportPath() string { return filepath.Join(Dir(), "merge-conflicts.json") }

func SaveMergeReport(report MergeReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return WritePrivateFile(mergeReportPath(), append(data, '\n'))
}

func LoadMergeReport() MergeReport {
	data, err := os.ReadFile(mergeReportPath())
	if err != nil {
		return MergeReport{Conflicts: []MergeConflict{}}
	}
	var report MergeReport
	if err := json.Unmarshal(data, &report); err != nil {
		return MergeReport{Conflicts: []MergeConflict{}}
	}
	if report.Conflicts == nil {
		report.Conflicts = []MergeConflict{}
	}
	return report
}

// ValidVaultBlob reports whether data has the shape of an encrypted vault, so a
// malformed download never replaces the only local copy.
func ValidVaultBlob(data []byte) bool { return vault.ValidBlob(data) }

var vaultCreateLockWait = 5 * time.Second

// CreateVaultIfAbsent writes an initial vault only if none exists, under the
// vault write lock shared with every other vault writer, and reports whether it
// created one. An existing vault (for example one just pulled) is never
// replaced.
func CreateVaultIfAbsent(v *Vault, masterPass string) (bool, error) {
	lock, err := AcquireFileLock(VaultWriteLockName, vaultCreateLockWait)
	if err != nil {
		if errors.Is(err, ErrLockBusy) {
			return false, errors.New("vault write lock is busy; retry the command")
		}
		return false, err
	}
	defer func() { _ = lock.Close() }()
	if _, statErr := os.Stat(Path()); statErr == nil {
		return false, nil
	}
	if err := Save(v, masterPass); err != nil {
		return false, err
	}
	return true, nil
}
