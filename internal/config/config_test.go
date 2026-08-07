package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssm/internal/privatepath"
)

func setTestHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func TestSaveWritesVaultAtomicallyWithPrivatePermissions(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	v := &Vault{Connections: []Connection{{Name: "local", Host: "127.0.0.1", User: "root", Port: 22}}}
	if err := Save(v, "master-pass"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := privatepath.VerifyDirectory(Dir()); err != nil {
		t.Fatalf("config dir is not private: %v", err)
	}
	if err := privatepath.VerifyFile(Path()); err != nil {
		t.Fatalf("vault is not private: %v", err)
	}
	assertNoPrivateTempFiles(t, Dir())
}

func TestSettingsAndPasswordCacheUsePrivateFiles(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("TMPDIR", t.TempDir())

	if err := SaveSettings(DefaultSettings()); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	CachePassword("master-pass")
	if got := GetCachedPassword(); got != "master-pass" {
		t.Fatalf("cached password = %q", got)
	}

	for _, path := range []string{settingsPath(), cachePath()} {
		if err := privatepath.VerifyFile(path); err != nil {
			t.Fatalf("%s is not private: %v", path, err)
		}
	}
	if err := privatepath.VerifyDirectory(filepath.Dir(cachePath())); err != nil {
		t.Fatalf("cache directory is not private: %v", err)
	}
}

func TestLoadSettingsDefaultsMissingBooleansToEnabled(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	if err := WritePrivateFile(settingsPath(), []byte(`{"password_cache":"session"}`)); err != nil {
		t.Fatalf("write settings: %v", err)
	}

	s := LoadSettings()

	if s.PasswordCache != "session" {
		t.Fatalf("PasswordCache = %q, want session", s.PasswordCache)
	}
	if !s.VimKeys {
		t.Fatal("VimKeys defaulted to false")
	}
	if !s.AutoUpdate {
		t.Fatal("AutoUpdate defaulted to false")
	}
	if !s.AutoSync {
		t.Fatal("AutoSync defaulted to false")
	}
}

func TestLoadSettingsPreservesExplicitFalseBooleans(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	if err := WritePrivateFile(settingsPath(), []byte(`{"vim_keys":false,"auto_update":false,"auto_sync":false}`)); err != nil {
		t.Fatalf("write settings: %v", err)
	}

	s := LoadSettings()

	if s.VimKeys {
		t.Fatal("VimKeys explicit false was not preserved")
	}
	if s.AutoUpdate {
		t.Fatal("AutoUpdate explicit false was not preserved")
	}
	if s.AutoSync {
		t.Fatal("AutoSync explicit false was not preserved")
	}
}

func TestMergeVaultsKeepsStableOrderAndRemoteWinsConflicts(t *testing.T) {
	local := &Vault{
		Connections: []Connection{
			{Name: "alpha", Host: "local-alpha"},
			{Name: "shared", Host: "local-shared"},
		},
		Keys: []SSHKey{
			{Name: "key-a", PrivateKey: "local-a"},
			{Name: "shared-key", PrivateKey: "local-shared"},
		},
	}
	remote := &Vault{
		Connections: []Connection{
			{Name: "shared", Host: "remote-shared"},
			{Name: "beta", Host: "remote-beta"},
		},
		Keys: []SSHKey{
			{Name: "shared-key", PrivateKey: "remote-shared"},
			{Name: "key-b", PrivateKey: "remote-b"},
		},
	}

	merged := MergeVaults(local, remote)

	if got := connectionNames(merged.Connections); got != "alpha,shared,beta" {
		t.Fatalf("connection order = %q, want alpha,shared,beta", got)
	}
	if merged.Connections[1].Host != "remote-shared" {
		t.Fatalf("shared host = %q, want remote value", merged.Connections[1].Host)
	}
	if got := keyNames(merged.Keys); got != "key-a,shared-key,key-b" {
		t.Fatalf("key order = %q, want key-a,shared-key,key-b", got)
	}
	if merged.Keys[1].PrivateKey != "remote-shared" {
		t.Fatalf("shared key = %q, want remote value", merged.Keys[1].PrivateKey)
	}
}

func TestMergeVaultsReportsNonSecretAliasConflicts(t *testing.T) {
	local := &Vault{Connections: []Connection{{Name: "prod", Host: "old.example", User: "root", Password: "local-secret"}}}
	remote := &Vault{Connections: []Connection{{Name: "prod", Host: "new.example", User: "root", Password: "remote-secret"}}}
	merged, report := MergeVaultsWithReport(local, remote)
	if merged.Connections[0].Host != "new.example" || len(report.Conflicts) != 1 {
		t.Fatalf("merged=%+v report=%+v", merged, report)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret") || report.Conflicts[0].Name != "prod" || report.Conflicts[0].Winner != "remote" {
		t.Fatalf("unsafe or incorrect report: %s", encoded)
	}
}

func assertNoPrivateTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".tmp") {
			t.Fatalf("leftover temp file: %s", filepath.Join(dir, name))
		}
	}
}

func TestConfigDirOverrideIsUsedForAllState(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	override := filepath.Join(t.TempDir(), "ssm-state")
	t.Setenv("SSM_CONFIG_DIR", override)

	if got := Dir(); got != override {
		t.Fatalf("Dir() = %q, want %q", got, override)
	}
	if got := Path(); got != filepath.Join(override, "connections.enc") {
		t.Fatalf("Path() = %q, want override path", got)
	}
	if err := SaveSettings(DefaultSettings()); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	if _, err := os.Stat(filepath.Join(override, "settings.json")); err != nil {
		t.Fatalf("settings were not written below override: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "ssm")); !os.IsNotExist(err) {
		t.Fatalf("default config directory was touched: %v", err)
	}
}

func connectionNames(conns []Connection) string {
	out := ""
	for i, c := range conns {
		if i > 0 {
			out += ","
		}
		out += c.Name
	}
	return out
}

func keyNames(keys []SSHKey) string {
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += ","
		}
		out += k.Name
	}
	return out
}
