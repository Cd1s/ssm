package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"ssm/internal/config"
)

func TestCompiledIdempotentHostUpsertPushIsSuccessfulNoOp(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	password := "COMPILED_NOOP_PASSWORD_CANARY"
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password:           password,
		RunCommandContains: "hostname; uname -sr",
		RunStdoutFragments: []string{"compiled-fixture\n", "Linux compiled-fixture\n"},
	})
	defer server.Close(t)
	cli.TrustSSHHost(t, server)
	alias := "noop-host"
	connection := server.Connection(alias, password)
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{connection}})
	passwordPath := filepath.Join(cli.temp, "noop.password")
	if err := os.WriteFile(passwordPath, []byte(password+"\n"), 0o600); err != nil {
		t.Fatalf("write no-op password fixture: %v", err)
	}

	result := cli.Run(t, "sshctl", nil, "--json", "host", "upsert", alias,
		"--host", connection.Host, "--port", strconv.Itoa(connection.Port),
		"--user", connection.User, "--password-file", passwordPath,
		"--verify", "--push")
	if result.ProcessExit != 0 {
		t.Fatalf("idempotent upsert --push failed: %s", result.Stdout)
	}
	value := assertCompiledJSONSuccess(t, result)
	if value["changed"] != false || value["pushed"] != false || value["sync_pending"] != false {
		t.Fatalf("idempotent upsert --push receipt = %#v", value)
	}
	if _, exists := value["transaction_id"]; exists {
		t.Fatalf("idempotent upsert --push created a transaction: %#v", value)
	}
}
