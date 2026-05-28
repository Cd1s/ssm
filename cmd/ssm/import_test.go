package main

import (
	"fmt"
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

func TestDecodeImportServersSortsMapShapes(t *testing.T) {
	servers, err := decodeImportServers([]byte(`{
		"z-host":{"host":"192.0.2.3","user":"root","password":"secret"},
		"a-host":{"host":"192.0.2.1","user":"root","password":"secret"},
		"m-host":{"host":"192.0.2.2","user":"root","password":"secret"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{servers[0].Alias, servers[1].Alias, servers[2].Alias}; got[0] != "a-host" || got[1] != "m-host" || got[2] != "z-host" {
		t.Fatalf("aliases = %v, want sorted map keys", got)
	}

	rootServers, err := decodeImportServers([]byte(`{"servers":{
		"z-host":{"host":"192.0.2.3","user":"root","password":"secret"},
		"a-host":{"host":"192.0.2.1","user":"root","password":"secret"}
	}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{rootServers[0].Alias, rootServers[1].Alias}; got[0] != "a-host" || got[1] != "z-host" {
		t.Fatalf("root aliases = %v, want sorted map keys", got)
	}
}

func TestConvertImportServerRejectsEmptyPasswordAuth(t *testing.T) {
	_, _, _, err := convertImportServer(importServer{
		Alias:    "empty-password",
		Host:     "192.0.2.1",
		User:     "root",
		AuthType: "password",
	}, map[string]string{}, map[string]bool{}, map[string]bool{})
	if err == nil {
		t.Fatal("expected empty password auth error")
	}
}

func TestParsePortRejectsFractionalAndOutOfRangeValues(t *testing.T) {
	for _, value := range []any{22.5, float64(0), float64(65536), "-1", "70000"} {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			if _, err := parsePort(value); err == nil {
				t.Fatalf("expected port %v to be rejected", value)
			}
		})
	}
}

func TestParseImportJSONArgsRejectsNegativeExpectCount(t *testing.T) {
	for _, args := range [][]string{
		{"hosts.json", "--expect-count", "-1"},
		{"hosts.json", "--expect-count=-1"},
	} {
		if _, err := parseImportJSONArgs(args); err == nil {
			t.Fatalf("parseImportJSONArgs(%v) accepted negative expect-count", args)
		}
	}
}
