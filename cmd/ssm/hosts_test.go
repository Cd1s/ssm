package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
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
