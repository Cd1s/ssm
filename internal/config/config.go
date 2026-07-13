package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	ID         string      `json:"id"`
	Alias      string      `json:"alias"`
	Operation  string      `json:"operation"`
	CreatedAt  string      `json:"created_at"`
	Before     *Connection `json:"before,omitempty"`
	After      *Connection `json:"after,omitempty"`
	KeysBefore []SSHKey    `json:"keys_before"`
	KeysAfter  []SSHKey    `json:"keys_after"`
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

func Load(masterPass string) (*Vault, error) {
	_ = EnsurePrivateDir(Dir())
	data, err := os.ReadFile(Path())
	if err != nil {
		if os.IsNotExist(err) {
			return &Vault{}, nil
		}
		return nil, err
	}

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

	return WritePrivateFile(Path(), encrypted)
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
