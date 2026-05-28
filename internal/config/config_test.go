package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveWritesVaultAtomicallyWithPrivatePermissions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	v := &Vault{Connections: []Connection{{Name: "local", Host: "127.0.0.1", User: "root", Port: 22}}}
	if err := Save(v, "master-pass"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	dirInfo, err := os.Stat(Dir())
	if err != nil {
		t.Fatalf("stat config dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("config dir mode = %o, want 700", dirInfo.Mode().Perm())
	}
	info, err := os.Stat(Path())
	if err != nil {
		t.Fatalf("stat vault: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("vault mode = %o, want 600", info.Mode().Perm())
	}
	assertNoPrivateTempFiles(t, Dir())
}

func TestSettingsAndPasswordCacheUsePrivateFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("TMPDIR", t.TempDir())

	if err := SaveSettings(DefaultSettings()); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	CachePassword("master-pass")
	if got := GetCachedPassword(); got != "master-pass" {
		t.Fatalf("cached password = %q", got)
	}

	for _, path := range []string{settingsPath(), cachePath()} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %o, want 600", path, info.Mode().Perm())
		}
	}
	cacheDirInfo, err := os.Stat(filepath.Dir(cachePath()))
	if err != nil {
		t.Fatalf("stat cache dir: %v", err)
	}
	if cacheDirInfo.Mode().Perm() != 0700 {
		t.Fatalf("cache dir mode = %o, want 700", cacheDirInfo.Mode().Perm())
	}
}

func TestLoadSettingsDefaultsMissingBooleansToEnabled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
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
	t.Setenv("HOME", home)
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
