package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

func TestParseHostUpsertArgs(t *testing.T) {
	opts, err := parseHostCommandArgs([]string{
		"upsert", "prod-api", "--host", "203.0.113.10", "--user=root",
		"--port", "2222", "--group=prod", "--key", "deploy", "--json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.action != "upsert" || opts.alias != "prod-api" || !opts.asJSON {
		t.Fatalf("unexpected options: %+v", opts)
	}
	if opts.host.value != "203.0.113.10" || opts.user.value != "root" || opts.port.value != 2222 {
		t.Fatalf("unexpected connection fields: %+v", opts)
	}
	if opts.keyName.value != "deploy" || opts.group.value != "prod" {
		t.Fatalf("unexpected optional fields: %+v", opts)
	}
}

func TestParseHostOfflineFlag(t *testing.T) {
	opts, err := parseHostCommandArgs([]string{"list", "--json", "--offline"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.offline || !opts.asJSON {
		t.Fatalf("options = %+v", opts)
	}
}

func TestHostErrorsUseCanonicalMachineContract(t *testing.T) {
	err := newHostError(machinecontract.HostAliasNotFound, "host %q not found", "missing")
	ce, ok := err.(*machinecontract.ClassifiedError)
	if !ok {
		t.Fatalf("error type = %T", err)
	}
	if ce.Code != "alias_not_found" || ce.Message == "" || ce.Hint == "" || ce.Exit != 255 || ce.Stage != "lookup" {
		t.Fatalf("contract = %+v", ce)
	}

	invalid := newHostError(machinecontract.HostInvalidArguments, "bad option").(*machinecontract.ClassifiedError)
	if invalid.Code != "invalid_arguments" || invalid.Exit != 2 || invalid.Stage != "validate" {
		t.Fatalf("invalid contract = %+v", invalid)
	}
}

func TestSearchHostViewsIsDeterministicAndCanBeAmbiguous(t *testing.T) {
	vault := &config.Vault{Connections: []config.Connection{
		{Name: "web-prod-b", Host: "b.example", User: "deploy", Group: "prod"},
		{Name: "db-stage", Host: "db.example", User: "postgres", Group: "stage"},
		{Name: "web-prod-a", Host: "a.example", User: "deploy", Group: "prod"},
	}}
	matches := searchHostViews(vault, "WEB-PROD")
	if len(matches) != 2 || matches[0].Name != "web-prod-a" || matches[1].Name != "web-prod-b" {
		t.Fatalf("matches = %+v", matches)
	}
	if got := searchHostViews(vault, "missing"); len(got) != 0 || got == nil {
		t.Fatalf("missing matches = %#v", got)
	}
}

func TestTypedHostSearchRequestUsesAliasAsQuery(t *testing.T) {
	args, err := requestHostArgs(agentRequest{Version: 1, Op: "host.search", Alias: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"search", "prod", "--json"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args=%v want=%v", args, want)
	}
}

func TestParseHostVerifyAndPushRequireSafeOrder(t *testing.T) {
	opts, err := parseHostCommandArgs([]string{
		"upsert", "prod", "--host", "203.0.113.10", "--user", "root", "--key", "deploy", "--verify", "--push",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.verify || !opts.push {
		t.Fatalf("opts = %+v", opts)
	}
	if _, err := parseHostCommandArgs([]string{
		"upsert", "prod", "--host", "203.0.113.10", "--user", "root", "--key", "deploy", "--push",
	}); err == nil {
		t.Fatal("accepted --push without --verify")
	}
}

func TestParseHostArgsRejectsInlineAndAmbiguousAuth(t *testing.T) {
	for _, args := range [][]string{
		{"add", "host", "--host", "example.com", "--user", "root", "--password", "secret"},
		{"add", "host", "--host", "example.com", "--user", "root", "--key", "saved", "--password-file", "pass"},
		{"update", "host", "--json"},
		{"remove", "host"},
	} {
		if _, err := parseHostCommandArgs(args); err == nil {
			t.Fatalf("parseHostCommandArgs(%v) unexpectedly succeeded", args)
		}
	}
}

func TestMutateHostUpsertIsIdempotent(t *testing.T) {
	v := &config.Vault{Keys: []config.SSHKey{{Name: "deploy", PrivateKey: "material"}}}
	opts, err := parseHostCommandArgs([]string{
		"upsert", "prod-api", "--host", "203.0.113.10", "--user", "root",
		"--port", "2222", "--group", "prod", "--key", "deploy",
	})
	if err != nil {
		t.Fatal(err)
	}

	first, result, err := mutateHost(v, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Action != "created" || len(first.Connections) != 1 {
		t.Fatalf("first upsert: result=%+v vault=%+v", result, first)
	}

	second, result, err := mutateHost(first, opts)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Action != "unchanged" {
		t.Fatalf("second upsert result=%+v", result)
	}
	if len(second.Connections) != 1 || len(second.Keys) != 1 {
		t.Fatalf("second upsert duplicated data: %+v", second)
	}
}

func TestMutateHostUpdatePreservesUnspecifiedFields(t *testing.T) {
	v := &config.Vault{
		Connections: []config.Connection{{
			Name: "prod-api", Host: "old.example", Port: 22, User: "root", Group: "prod", KeyName: "deploy",
		}},
		Keys: []config.SSHKey{{Name: "deploy", PrivateKey: "material"}},
	}
	opts, err := parseHostCommandArgs([]string{"update", "prod-api", "--host", "new.example", "--port", "2202"})
	if err != nil {
		t.Fatal(err)
	}
	updated, result, err := mutateHost(v, opts)
	if err != nil {
		t.Fatal(err)
	}
	got := updated.Connections[0]
	if !result.Changed || got.Host != "new.example" || got.Port != 2202 {
		t.Fatalf("update failed: result=%+v connection=%+v", result, got)
	}
	if got.User != "root" || got.Group != "prod" || got.KeyName != "deploy" {
		t.Fatalf("unspecified field changed: %+v", got)
	}
}

func TestMutateHostPasswordNeverAppearsInResult(t *testing.T) {
	dir := t.TempDir()
	passwordPath := filepath.Join(dir, "password")
	if err := os.WriteFile(passwordPath, []byte("do-not-print\n"), 0600); err != nil {
		t.Fatal(err)
	}
	opts, err := parseHostCommandArgs([]string{
		"add", "password-host", "--host", "192.0.2.10", "--user", "root", "--password-file", passwordPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, result, err := mutateHost(&config.Vault{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Connections[0].Password != "do-not-print" {
		t.Fatal("password was not loaded")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "do-not-print") || strings.Contains(string(encoded), passwordPath) {
		t.Fatalf("result leaked password data: %s", encoded)
	}
}

func TestLoadPasswordFileRejectsOversizedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, make([]byte, maxHostCredentialBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPasswordFile(path); err == nil {
		t.Fatal("accepted oversized password file")
	}
}

func TestMutateHostKeyFileRefusesToOverwriteSharedKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, testPrivateKey(t), 0600); err != nil {
		t.Fatal(err)
	}
	v := &config.Vault{
		Connections: []config.Connection{
			{Name: "one", Host: "one.example", Port: 22, User: "root", KeyName: "shared"},
			{Name: "two", Host: "two.example", Port: 22, User: "root", KeyName: "shared"},
		},
		Keys: []config.SSHKey{{Name: "shared", PrivateKey: "different-material"}},
	}
	opts, err := parseHostCommandArgs([]string{"update", "one", "--key-file", keyPath})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = mutateHost(v, opts)
	if err == nil || !strings.Contains(err.Error(), "shared") {
		t.Fatalf("expected shared key conflict, got %v", err)
	}
	if v.Keys[0].PrivateKey != "different-material" {
		t.Fatal("input vault was mutated after conflict")
	}
}

func TestMutateHostKeyFileRefusesToOverwriteUnrelatedKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, testPrivateKey(t), 0600); err != nil {
		t.Fatal(err)
	}
	v := &config.Vault{Keys: []config.SSHKey{{Name: "new-host", PrivateKey: "unrelated-material"}}}
	opts, err := parseHostCommandArgs([]string{
		"add", "new-host", "--host", "new.example", "--user", "root", "--key-file", keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := mutateHost(v, opts); err == nil || !strings.Contains(err.Error(), "--key-name") {
		t.Fatalf("expected unrelated key conflict, got %v", err)
	}
	if v.Keys[0].PrivateKey != "unrelated-material" {
		t.Fatal("input key was overwritten")
	}
}

func TestMutateHostNormalizesLegacyZeroPort(t *testing.T) {
	v := &config.Vault{
		Connections: []config.Connection{{Name: "legacy", Host: "old.example", User: "root", KeyName: "deploy"}},
		Keys:        []config.SSHKey{{Name: "deploy", PrivateKey: "material"}},
	}
	opts, err := parseHostCommandArgs([]string{"update", "legacy", "--host", "new.example"})
	if err != nil {
		t.Fatal(err)
	}
	updated, _, err := mutateHost(v, opts)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Connections[0].Port != 22 {
		t.Fatalf("port = %d", updated.Connections[0].Port)
	}
}

func TestMutateHostRemoveOnlyPrunesUnreferencedKey(t *testing.T) {
	v := &config.Vault{
		Connections: []config.Connection{
			{Name: "one", Host: "one.example", Port: 22, User: "root", KeyName: "shared"},
			{Name: "two", Host: "two.example", Port: 22, User: "root", KeyName: "shared"},
		},
		Keys: []config.SSHKey{{Name: "shared", PrivateKey: "material"}},
	}
	removeOne, err := parseHostCommandArgs([]string{"remove", "one", "--yes", "--prune-key"})
	if err != nil {
		t.Fatal(err)
	}
	afterOne, result, err := mutateHost(v, removeOne)
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyPruned != "" || len(afterOne.Keys) != 1 {
		t.Fatalf("shared key was pruned: result=%+v vault=%+v", result, afterOne)
	}

	removeTwo, err := parseHostCommandArgs([]string{"remove", "two", "--yes", "--prune-key"})
	if err != nil {
		t.Fatal(err)
	}
	afterTwo, result, err := mutateHost(afterOne, removeTwo)
	if err != nil {
		t.Fatal(err)
	}
	if result.KeyPruned != "shared" || len(afterTwo.Keys) != 0 {
		t.Fatalf("unreferenced key was not pruned: result=%+v vault=%+v", result, afterTwo)
	}
}

func TestMutateHostRejectsUnsafeNewAliasAndHost(t *testing.T) {
	v := &config.Vault{Keys: []config.SSHKey{{Name: "deploy", PrivateKey: "material"}}}
	for _, args := range [][]string{
		{"add", "bad alias", "--host", "example.com", "--user", "root", "--key", "deploy"},
		{"add", "good-alias", "--host", "root@example.com", "--user", "root", "--key", "deploy"},
		{"add", "good-alias", "--host", "https://example.com", "--user", "root", "--key", "deploy"},
	} {
		opts, err := parseHostCommandArgs(args)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := mutateHost(v, opts); err == nil {
			t.Fatalf("mutateHost(%v) unexpectedly succeeded", args)
		}
	}
}

func TestRefreshHostVaultRejectsBrokenCloudUnlessOffline(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	dir := filepath.Join(home, ".config", "ssm")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cloud.json"), []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := refreshHostVault(false); err == nil {
		t.Fatal("expected malformed cloud config to stop refresh")
	}
	if err := refreshHostVault(true); err != nil {
		t.Fatalf("offline refresh = %v", err)
	}
}

func testPrivateKey(t *testing.T) []byte {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKey(privateKey, "ssm-test")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}
