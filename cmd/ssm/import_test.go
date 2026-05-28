package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadServerImportPreservesManifestAliases(t *testing.T) {
	dir := t.TempDir()
	serversPath := filepath.Join(dir, "servers.json")
	manifestPath := filepath.Join(dir, "manifest.json")
	keyPath := filepath.Join(dir, "id_test")

	if err := os.WriteFile(keyPath, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n-----END OPENSSH PRIVATE KEY-----\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(serversPath, []byte(`[
		{"name":"Password Host","host":"192.0.2.1","port":22,"user":"root","auth_type":"password","password":"secret"},
		{"name":"Key Host","host":"192.0.2.2","port":2222,"user":"admin","auth_type":"key","private_key_path":"`+keyPath+`"}
	]`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte(`[
		{"alias":"password-host","name":"Password Host","host":"192.0.2.1","port":22,"user":"root"},
		{"alias":"key-host","name":"Key Host","host":"192.0.2.2","port":2222,"user":"admin"}
	]`), 0600); err != nil {
		t.Fatal(err)
	}

	v, err := loadServerImport(serversPath, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Connections) != 2 {
		t.Fatalf("connections = %d, want 2", len(v.Connections))
	}
	if v.Connections[0].Name != "password-host" {
		t.Fatalf("password alias = %q", v.Connections[0].Name)
	}
	if v.Connections[1].Name != "key-host" {
		t.Fatalf("key alias = %q", v.Connections[1].Name)
	}
	if v.Connections[0].Password == "" {
		t.Fatal("password auth was not imported")
	}
	if v.Connections[1].KeyName == "" || len(v.Keys) != 1 {
		t.Fatal("key auth was not imported")
	}
}
