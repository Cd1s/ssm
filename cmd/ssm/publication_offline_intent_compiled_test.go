package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"ssm/internal/config"
)

func assertOfflineIntentFailure(t *testing.T, result compiledCLIResult) {
	t.Helper()
	if result.ProcessExit != 1 || result.Stderr != "" {
		t.Fatalf("offline push process contract changed: %s", compiledOutputIdentity(result))
	}
	want := map[string]any{"ok": false, "error": "sync_push_failed", "exit": float64(1), "hint": scopeGuardHint, "message": "not logged in (run: ssm login)"}
	if value := decodeExactlyOneJSONObject(t, result.Stdout); !reflect.DeepEqual(value, want) {
		t.Fatalf("offline push JSON = %v, want %v", value, want)
	}
}

func TestPublicationScopeGuardKeepsOfflineIntent(t *testing.T) {
	cli, sync, _ := newTwoPublicationScenario(t, "offline")
	crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_TEST_PUBLICATION_FAULT": "after_prerequisite_persist"}, "--json", "push", "--all")
	if crashed.ProcessExit != 86 || sync.putCount() != 0 {
		t.Fatalf("failed to create offline recovery: %s", compiledOutputIdentity(crashed))
	}
	before, ok := scopeIntentBytes(t, cli)
	if !ok {
		t.Fatal("ready intent missing before offline push")
	}
	headsBefore := sync.headCount()
	putsBefore := sync.putCount()
	vaultBefore := cli.VaultBlob(t)
	result := cli.Run(t, "sshctl", nil, "--offline", "--json", "push", "--only", "tx_scope_alpha_0000000000000000000000000001")
	if result.ProcessExit == 0 {
		t.Fatalf("offline push unexpectedly succeeded: %s", compiledOutputIdentity(result))
	}
	value := decodeExactlyOneJSONObject(t, result.Stdout)
	assertOfflineIntentFailure(t, result)
	if value["error"] != "sync_push_failed" || value["exit"] != float64(1) {
		t.Fatalf("offline push failure contract: %v", value)
	}
	after, ok := scopeIntentBytes(t, cli)
	if !ok || !bytes.Equal(before, after) || !bytes.Equal(vaultBefore, cli.VaultBlob(t)) || sync.putCount() != putsBefore || sync.headCount() != headsBefore {
		t.Fatal("offline push changed recovery evidence or contacted remote")
	}
	if _, err := os.Stat(filepath.Join(cli.home, ".config", "ssm", "publishing-intent.json")); err != nil {
		t.Fatalf("offline publishing intent disappeared: %v", err)
	}
}

func TestPublicationScopeGuardKeepsOfflineDivergentIntent(t *testing.T) {
	cli, sync, original := newTwoPublicationScenario(t, "offline-divergent")
	crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_TEST_PUBLICATION_FAULT": "after_prerequisite_persist"}, "--json", "push", "--all")
	if crashed.ProcessExit != 86 {
		t.Fatalf("failed to create divergent recovery: %s", compiledOutputIdentity(crashed))
	}
	third := &config.Vault{Connections: []config.Connection{{Name: "third", Host: "third.example", Port: 22, User: "root", Password: "SCOPE_GUARD_THIRD"}}} //nolint:gosec // fake credential in an isolated test vault
	sync.setRemote(encryptCompiledVault(t, cli, third))
	conflict := cli.Run(t, "sshctl", nil, "--json", "push", "--only", original.PendingMutations[0].ID)
	if conflict.ProcessExit == 0 {
		t.Fatalf("divergent recovery unexpectedly succeeded: %s", compiledOutputIdentity(conflict))
	}
	before, ok := scopeIntentBytes(t, cli)
	if !ok {
		t.Fatal("divergent intent missing after conflict")
	}
	headsBefore := sync.headCount()
	putsBefore := sync.putCount()
	vaultBefore := cli.VaultBlob(t)
	offline := cli.Run(t, "sshctl", nil, "--offline", "--json", "push", "--only", original.PendingMutations[0].ID)
	assertOfflineIntentFailure(t, offline)
	if offline.ProcessExit == 0 {
		t.Fatalf("offline divergent push unexpectedly succeeded: %s", compiledOutputIdentity(offline))
	}
	after, ok := scopeIntentBytes(t, cli)
	if !ok || !bytes.Equal(before, after) || !bytes.Equal(vaultBefore, cli.VaultBlob(t)) || sync.putCount() != putsBefore || sync.headCount() != headsBefore {
		t.Fatal("offline divergent push changed recovery evidence or contacted remote")
	}
}
