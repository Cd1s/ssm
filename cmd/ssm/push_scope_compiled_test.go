package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"ssm/internal/config"
)

const emptyLedgerRecoveryHint = "review sshctl --offline --json doctor and preserve the local vault and sync-conflict.json; run sshctl --json pull to adopt remote, then use guarded ssm --offline --json import-json <reviewed-file> --merge and publish its reviewed transaction with sshctl --json push --only <transaction-id>"

func TestPushScopeArgumentsFailBeforePublicationSideEffects(t *testing.T) {
	const (
		scopeConflictFailure = "{\n" +
			"  \"ok\": false,\n" +
			"  \"error\": \"invalid_arguments\",\n" +
			"  \"message\": \"--all and --only are mutually exclusive\",\n" +
			"  \"hint\": \"choose one explicit push scope\",\n" +
			"  \"exit\": 2\n" +
			"}\n"
		onlyRequiredFailure = "{\n" +
			"  \"ok\": false,\n" +
			"  \"error\": \"invalid_arguments\",\n" +
			"  \"message\": \"--only requires a non-empty transaction id\",\n" +
			"  \"hint\": \"copy an exact id from sshctl --json status\",\n" +
			"  \"exit\": 2\n" +
			"}\n"
		invalidScopeFailure = "{\n" +
			"  \"ok\": false,\n" +
			"  \"error\": \"invalid_arguments\",\n" +
			"  \"message\": \"push accepts --all or --only \\u003ctransaction-id\\u003e\",\n" +
			"  \"hint\": \"inspect pending_mutations with sshctl --json status\",\n" +
			"  \"exit\": 2\n" +
			"}\n"
	)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "only then all", args: []string{"--only", "--all"}, want: scopeConflictFailure},
		{name: "all then only", args: []string{"--all", "--only", "tx_reviewed"}, want: scopeConflictFailure},
		{name: "repeated only", args: []string{"--only", "tx_first", "--only=tx_second"}, want: invalidScopeFailure},
		{name: "repeated all", args: []string{"--all", "--all"}, want: invalidScopeFailure},
		{name: "missing only value", args: []string{"--only"}, want: onlyRequiredFailure},
		{name: "empty only value", args: []string{"--only", ""}, want: onlyRequiredFailure},
		{name: "whitespace only value", args: []string{"--only", " \t "}, want: onlyRequiredFailure},
		{name: "empty only equals value", args: []string{"--only="}, want: onlyRequiredFailure},
		{name: "only equals all", args: []string{"--only=--all"}, want: scopeConflictFailure},
		{name: "only equals unknown option token", args: []string{"--only=--unknown"}, want: onlyRequiredFailure},
		{name: "only equals short option token", args: []string{"--only=-x"}, want: onlyRequiredFailure},
		{name: "only equals only option token", args: []string{"--only=--only"}, want: onlyRequiredFailure},
		{name: "only equals known long option token", args: []string{"--only=--json"}, want: onlyRequiredFailure},
		{name: "only equals known short option token", args: []string{"--only=-v"}, want: onlyRequiredFailure},
		{name: "unknown flag", args: []string{"--unknown"}, want: invalidScopeFailure},
		{name: "only rejects long option token", args: []string{"--only", "--unknown"}, want: onlyRequiredFailure},
		{name: "only rejects short option token", args: []string{"--only", "-x"}, want: onlyRequiredFailure},
	}

	for _, executable := range []string{"ssm", "sshctl"} {
		for _, test := range tests {
			t.Run(executable+"/"+test.name, func(t *testing.T) {
				cli := newCompiledCLIHarness(t)
				sync := newCompiledSyncFixture(t)
				cli.SaveCloud(t, sync.URL(), "ISSUE25_PUSH_ARGUMENT_TOKEN_CANARY")
				unlockCanary := filepath.Join(cli.temp, "ISSUE25_UNLOCK_MUST_NOT_BE_TOUCHED_CANARY")
				configDir := filepath.Join(cli.home, ".config", "ssm")
				untouchedPaths := []string{
					unlockCanary,
					filepath.Join(configDir, "connections.enc"),
					filepath.Join(configDir, "publication.lock"),
					filepath.Join(configDir, "publishing-intent.json"),
					filepath.Join(configDir, "sync-conflict.json"),
				}
				for _, path := range untouchedPaths {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatalf("precondition: push argument canary path %s exists: %v", filepath.Base(path), err)
					}
				}

				args := append([]string{"--json", "push"}, test.args...)
				result := cli.RunWithEnv(t, executable, nil, map[string]string{
					"SSM_MASTER_PASS_FILE": unlockCanary,
				}, args...)
				if result.ProcessExit != 2 || result.Stdout != test.want || result.Stderr != "" {
					t.Fatalf("push argument rejection changed; output=%s", compiledOutputIdentity(result))
				}
				decodeExactlyOneJSONObject(t, result.Stdout)
				assertPushRequestCounts(t, sync, 0, 0)
				for _, path := range untouchedPaths {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatalf("invalid push arguments touched %s: %v", filepath.Base(path), err)
					}
				}
			})
		}
	}
}

func TestPushOnlyEqualsPreservesExactScope(t *testing.T) {
	const transactionID = "tx_25252525252525252525252525252529"
	for _, executable := range []string{"ssm", "sshctl"} {
		t.Run(executable, func(t *testing.T) {
			cli, sync, _ := newSinglePublicationScenario(t, transactionID, executable+" only equals")
			result := cli.Run(
				t,
				executable,
				nil,
				"--master-pass-file="+cli.passPath,
				"--json",
				"push",
				"--only="+transactionID,
			)
			value := assertCompiledJSONSuccess(t, result)
			assertCompiledStringField(t, value, "scope", "only", result)
			assertCompiledStringField(t, value, "transaction_id", transactionID, result)
			assertCompiledSinglePreflightID(t, value, transactionID)
			if remaining, ok := value["remaining_mutations"].([]any); !ok || len(remaining) != 0 {
				t.Fatalf("only equals remaining_mutations = %v, want []", value["remaining_mutations"])
			}
			if got := sync.headCount(); got != 2 {
				t.Fatalf("only equals HEAD count = %d, want 2", got)
			}
			if got := sync.putCount(); got != 1 {
				t.Fatalf("only equals PUT count = %d, want 1", got)
			}
		})
	}
}

func TestEmptyLedgerPushNeverPuts(t *testing.T) {
	t.Run("identical local cached and remote identities are an explicit no-op", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		vault := &config.Vault{Connections: []config.Connection{{ //nolint:gosec // test-only fake credential canary
			Name: "identical-empty-ledger", Host: "192.0.2.125", Port: 22, User: "runner",
			Password: "ISSUE25_IDENTICAL_EMPTY_LEDGER_PASSWORD_CANARY",
		}}}
		cli.SaveVault(t, vault)
		localBlob := cli.VaultBlob(t)
		localIdentity := compiledOpaqueIdentity(localBlob)
		sync.SetRemote(t, localBlob, localIdentity)
		cli.SaveRemoteETag(t, localIdentity)
		cli.SaveCloud(t, sync.URL(), "ISSUE25_IDENTICAL_EMPTY_LEDGER_TOKEN_CANARY")

		result := cli.Run(t, "sshctl", nil, "--json", "push", "--all")
		value := assertCompiledJSONSuccess(t, result)
		assertCompiledStringField(t, value, "action", "noop", result)
		assertCompiledStringField(t, value, "scope", "all", result)
		if preflight, ok := value["preflight"].([]any); !ok || len(preflight) != 0 {
			t.Fatalf("identical empty-ledger preflight = %v, want []", value["preflight"])
		}
		if remaining, ok := value["remaining_mutations"].([]any); !ok || len(remaining) != 0 {
			t.Fatalf("identical empty-ledger remaining_mutations = %v, want []", value["remaining_mutations"])
		}
		assertNoCompiledCanaryLeak(t, result, map[string]string{ //nolint:gosec // test-only fake credential canaries
			"vault": "ISSUE25_IDENTICAL_EMPTY_LEDGER_PASSWORD_CANARY",
			"token": "ISSUE25_IDENTICAL_EMPTY_LEDGER_TOKEN_CANARY",
		})
		assertPushRequestCounts(t, sync, 1, 0)
		if after := cli.VaultBlob(t); !bytes.Equal(after, localBlob) {
			t.Fatal("identical empty-ledger no-op changed the local encrypted vault")
		}
		for _, name := range []string{"publishing-intent.json", "sync-conflict.json"} {
			if _, err := os.Stat(filepath.Join(cli.home, ".config", "ssm", name)); !os.IsNotExist(err) {
				t.Fatalf("identical empty-ledger no-op created %s: %v", name, err)
			}
		}
	})

	t.Run("divergence preserves both blobs cached identity and recovery evidence", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		vault := &config.Vault{Connections: []config.Connection{{ //nolint:gosec // test-only fake credential canary
			Name: "local-empty-ledger", Host: "192.0.2.126", Port: 22, User: "runner",
			Password: "ISSUE25_DIVERGENT_EMPTY_LEDGER_PASSWORD_CANARY",
		}}}
		cli.SaveVault(t, vault)
		localBlob := cli.VaultBlob(t)
		localIdentity := compiledOpaqueIdentity(localBlob)
		remoteBlob := []byte("ISSUE25_OPAQUE_DIVERGENT_REMOTE_BLOB")
		remoteIdentity := compiledOpaqueIdentity(remoteBlob)
		sync.SetRemote(t, remoteBlob, remoteIdentity)
		cli.SaveRemoteETag(t, localIdentity)
		cli.SaveCloud(t, sync.URL(), "ISSUE25_DIVERGENT_EMPTY_LEDGER_TOKEN_CANARY")

		result := cli.Run(t, "ssm", nil, "--json", "push", "--all")
		assertCompiledMachineContract(t, result, compiledMachineContract{
			OK: false, Error: "sync_conflict", Stage: "sync_compare",
			Hint: emptyLedgerRecoveryHint, JSONExit: 1, ProcessExit: 1,
		})
		assertNoCompiledCanaryLeak(t, result, map[string]string{ //nolint:gosec // test-only fake credential canaries
			"vault":  "ISSUE25_DIVERGENT_EMPTY_LEDGER_PASSWORD_CANARY",
			"token":  "ISSUE25_DIVERGENT_EMPTY_LEDGER_TOKEN_CANARY",
			"remote": string(remoteBlob),
		})
		assertPushRequestCounts(t, sync, 1, 0)
		if after := cli.VaultBlob(t); !bytes.Equal(after, localBlob) {
			t.Fatal("empty-ledger divergence changed the local encrypted vault")
		}
		if _, err := os.Stat(filepath.Join(cli.home, ".config", "ssm", "publishing-intent.json")); !os.IsNotExist(err) {
			t.Fatalf("empty-ledger divergence created publishing intent: %v", err)
		}
		cached, err := os.ReadFile(filepath.Join(cli.home, ".config", "ssm", "remote.etag"))
		if err != nil || string(cached) != localIdentity+"\n" {
			t.Fatalf("empty-ledger divergence changed cached identity: value=%q err=%v", cached, err)
		}
		evidenceData, err := os.ReadFile(filepath.Join(cli.home, ".config", "ssm", "sync-conflict.json"))
		if err != nil {
			t.Fatalf("read empty-ledger recovery evidence: %v", err)
		}
		var evidence struct {
			Local  string `json:"local_etag"`
			Remote string `json:"remote_etag"`
			Cached string `json:"cached_etag"`
		}
		if err := json.Unmarshal(evidenceData, &evidence); err != nil {
			t.Fatalf("decode empty-ledger recovery evidence: %v", err)
		}
		if evidence.Local != localIdentity || evidence.Remote != remoteIdentity || evidence.Cached != localIdentity {
			t.Fatalf("empty-ledger recovery identities = %+v", evidence)
		}
	})

	t.Run("unknown only scope fails before transport", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		cli.SaveVault(t, &config.Vault{})
		cli.SaveCloud(t, sync.URL(), "ISSUE25_UNKNOWN_ONLY_TOKEN_CANARY")

		result := cli.Run(t, "sshctl", nil, "--json", "push", "--only", "tx_unknown")
		assertCompiledMachineContract(t, result, compiledMachineContract{
			OK: false, Error: "sync_push_failed",
			Hint:     "local vault remains pending; fix sync, then retry with sshctl --json push --only <transaction-id> or, after reviewing all pending transactions, sshctl --json push --all",
			JSONExit: 1, ProcessExit: 1,
		})
		assertNoCompiledCanaryLeak(t, result, map[string]string{ //nolint:gosec // test-only fake credential canary
			"token": "ISSUE25_UNKNOWN_ONLY_TOKEN_CANARY",
		})
		assertPushRequestCounts(t, sync, 0, 0)
	})
}

func TestPushAllUsesInvocationStartSnapshot(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	sync := newPublicationSyncFixture(t)
	base := config.Connection{ //nolint:gosec // test-only fake credential canary
		Name: "snapshot-base", Host: "192.0.2.130", Port: 22, User: "runner",
		Password: "ISSUE25_SNAPSHOT_BASE_PASSWORD_CANARY",
	}
	alpha := config.Connection{ //nolint:gosec // test-only fake credential canary
		Name: "snapshot-alpha", Host: "192.0.2.131", Port: 22, User: "runner",
		Password: "ISSUE25_SNAPSHOT_ALPHA_PASSWORD_CANARY",
	}
	beta := config.Connection{ //nolint:gosec // test-only fake credential canary
		Name: "snapshot-beta", Host: "192.0.2.132", Port: 22, User: "runner",
		Password: "ISSUE25_SNAPSHOT_BETA_PASSWORD_CANARY",
	}
	const (
		alphaID = "tx_25252525252525252525252525252525"
		betaID  = "tx_25252525252525252525252525252526"
	)
	starting := &config.Vault{
		Connections: []config.Connection{base, alpha, beta},
		PendingBase: &config.InventorySnapshot{
			Connections: []config.Connection{base},
		},
		PendingMutations: []config.PendingMutation{
			{
				ID: alphaID, Alias: alpha.Name, Operation: "created",
				CreatedAt: "2026-07-29T00:00:25Z", After: &alpha,
			},
			{
				ID: betaID, Alias: beta.Name, Operation: "created",
				CreatedAt: "2026-07-29T00:00:26Z", After: &beta,
			},
		},
	}
	cli.SaveVault(t, starting)
	prerequisite := encryptCompiledVault(t, cli, &config.Vault{
		Connections: []config.Connection{base},
	})
	prerequisiteIdentity := compiledOpaqueIdentity(prerequisite)
	sync.setRemote(prerequisite)
	cli.SaveRemoteETag(t, prerequisiteIdentity)
	cli.SaveCloud(t, sync.server.URL, "ISSUE25_SNAPSHOT_TOKEN_CANARY")

	release := sync.holdFirstBeforeCommit()
	defer closeChannelOnce(release)
	running := startCompiledPush(t, cli, "--json", "push", "--all")
	waitPublicationEvent(t, sync.requestRead, "request-body barrier")

	intentPath := filepath.Join(cli.home, ".config", "ssm", "publishing-intent.json")
	intentBeforeMutation := readCompiledPublishingIntentEvidence(t, intentPath)
	assertInvocationStartIntent(t, intentBeforeMutation, prerequisiteIdentity, alphaID, betaID)

	gammaPassword := "ISSUE25_SNAPSHOT_GAMMA_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
	gammaPasswordPath := filepath.Join(cli.temp, "snapshot-gamma.password")
	if err := os.WriteFile(gammaPasswordPath, []byte(gammaPassword+"\n"), 0o600); err != nil {
		t.Fatalf("write concurrent mutation password fixture: %v", err)
	}
	mutation := cli.Run(
		t,
		"sshctl",
		nil,
		"--offline", "--json", "host", "add", "snapshot-gamma",
		"--host", "192.0.2.133", "--user", "runner",
		"--password-file", gammaPasswordPath,
	)
	mutationValue := assertCompiledJSONSuccess(t, mutation)
	gammaID := compiledTransactionID(t, mutationValue, mutation)
	if gammaID == alphaID || gammaID == betaID {
		t.Fatal("concurrent mutation reused an invocation-start transaction ID")
	}
	intentAfterMutation := readCompiledPublishingIntentEvidence(t, intentPath)
	assertInvocationStartIntent(t, intentAfterMutation, prerequisiteIdentity, alphaID, betaID)

	closeChannelOnce(release)
	result := waitCompiledPublication(t, running)
	value := assertCompiledJSONSuccess(t, result)
	preflight, ok := value["preflight"].([]any)
	if !ok || len(preflight) != 2 {
		t.Fatalf("invocation-start preflight = %v", value["preflight"])
	}
	for index, wantID := range []string{alphaID, betaID} {
		mutation, ok := preflight[index].(map[string]any)
		if !ok || mutation["id"] != wantID {
			t.Fatalf("invocation-start preflight[%d] = %v, want id %s", index, preflight[index], wantID)
		}
	}
	assertNoCompiledCanaryLeak(t, result, map[string]string{ //nolint:gosec // test-only fake credential canaries
		"base":  base.Password,
		"alpha": alpha.Password,
		"beta":  beta.Password,
		"gamma": gammaPassword,
		"token": "ISSUE25_SNAPSHOT_TOKEN_CANARY",
	})
	if sync.headCount() != 2 || sync.putCount() != 1 {
		t.Fatalf("invocation-start publication requests HEAD=%d PUT=%d, want HEAD=2 PUT=1", sync.headCount(), sync.putCount())
	}
	remote := sync.remote()
	if compiledOpaqueIdentity(remote) != intentBeforeMutation.TargetIdentity {
		t.Fatal("captured remote blob identity differs from the invocation-start intent target")
	}
	assertCompiledEncryptedPublication(t, remote, cli.passphrase, map[string]string{ //nolint:gosec // test-only fake credential canaries
		"base":  base.Password,
		"alpha": alpha.Password,
		"beta":  beta.Password,
		"gamma": gammaPassword,
	}, &config.Vault{Connections: []config.Connection{alpha, base, beta}})

	local := cli.LoadVaultIdentity(t)
	if len(local.PendingMutations) != 1 || local.PendingMutations[0].ID != gammaID {
		t.Fatal("concurrent mutation was absorbed or lost instead of remaining pending")
	}
	if local.PendingBase == nil || len(local.PendingBase.Connections) != 3 {
		t.Fatal("concurrent mutation was not rebased onto the exact confirmed invocation-start projection")
	}
	if len(local.Connections) != 4 {
		t.Fatal("local inventory lost an invocation-start or concurrent mutation")
	}
}

func TestEveryPushPathUsesInventoryTransactions(t *testing.T) {
	for _, executable := range []string{"ssm", "sshctl"} {
		for _, scope := range []string{"only", "all"} {
			t.Run(executable+" push --"+scope, func(t *testing.T) {
				testOwnedExplicitPushScope(t, executable, scope)
			})
		}
	}

	routes := []ownedMutationPublicationRoute{
		{name: "ssm host add", executable: "ssm", noun: "host", action: "add"},
		{name: "ssm hosts update compatibility alias", executable: "ssm", noun: "hosts", action: "update"},
		{name: "ssm host upsert", executable: "ssm", noun: "host", action: "upsert"},
		{name: "sshctl host add", executable: "sshctl", noun: "host", action: "add"},
		{name: "sshctl hosts update compatibility alias", executable: "sshctl", noun: "hosts", action: "update"},
		{name: "sshctl host upsert", executable: "sshctl", noun: "host", action: "upsert"},
		{name: "request v1 host.add", executable: "sshctl", action: "add", request: true},
		{name: "request v1 host.update", executable: "sshctl", action: "update", request: true},
		{name: "request v1 host.upsert", executable: "sshctl", action: "upsert", request: true},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			testOwnedMutationPublicationRoute(t, route)
		})
	}
}

func testOwnedExplicitPushScope(t *testing.T, executable, scope string) {
	t.Helper()
	cli := newCompiledCLIHarness(t)
	sync := newCompiledSyncFixture(t)
	base := config.Connection{ //nolint:gosec // test-only fake credential canary
		Name: "00-owned-base", Host: "192.0.2.140", Port: 22, User: "runner",
		Password: "ISSUE25_OWNED_BASE_PASSWORD_CANARY",
	}
	alpha := config.Connection{ //nolint:gosec // test-only fake credential canary
		Name: "10-owned-alpha", Host: "192.0.2.141", Port: 22, User: "runner",
		Password: "ISSUE25_OWNED_ALPHA_PASSWORD_CANARY",
	}
	beta := config.Connection{ //nolint:gosec // test-only fake credential canary
		Name: "20-owned-beta", Host: "192.0.2.142", Port: 22, User: "runner",
		Password: "ISSUE25_OWNED_BETA_PASSWORD_CANARY",
	}
	const (
		alphaID = "tx_25252525252525252525252525252527"
		betaID  = "tx_25252525252525252525252525252528"
	)
	cli.SaveVault(t, &config.Vault{
		Connections: []config.Connection{base, alpha, beta},
		PendingBase: &config.InventorySnapshot{Connections: []config.Connection{base}},
		PendingMutations: []config.PendingMutation{
			{
				ID: alphaID, Alias: alpha.Name, Operation: "created",
				CreatedAt: "2026-07-29T00:00:27Z", After: &alpha,
			},
			{
				ID: betaID, Alias: beta.Name, Operation: "created",
				CreatedAt: "2026-07-29T00:00:28Z", After: &beta,
			},
		},
	})
	prerequisite := encryptCompiledVault(t, cli, &config.Vault{Connections: []config.Connection{base}})
	prerequisiteIdentity := compiledOpaqueIdentity(prerequisite)
	sync.SetRemote(t, prerequisite, prerequisiteIdentity)
	cli.SaveRemoteETag(t, prerequisiteIdentity)
	cli.SaveCloud(t, sync.URL(), "ISSUE25_OWNED_PUSH_TOKEN_CANARY")

	args := []string{"--json", "push", "--" + scope}
	wantRemote := &config.Vault{Connections: []config.Connection{base, alpha, beta}}
	wantRemaining := 0
	if scope == "only" {
		args = append(args, betaID)
		wantRemote = &config.Vault{Connections: []config.Connection{base, beta}}
		wantRemaining = 1
	}
	result := cli.Run(t, executable, nil, args...)
	value := assertCompiledJSONSuccess(t, result)
	assertCompiledStringField(t, value, "scope", scope, result)
	if scope == "only" {
		assertCompiledStringField(t, value, "transaction_id", betaID, result)
	}
	remaining, ok := value["remaining_mutations"].([]any)
	if !ok || len(remaining) != wantRemaining {
		t.Fatalf("owned %s push remaining_mutations = %v", scope, value["remaining_mutations"])
	}
	assertNoCompiledCanaryLeak(t, result, map[string]string{ //nolint:gosec // test-only fake credential canaries
		"base":  base.Password,
		"alpha": alpha.Password,
		"beta":  beta.Password,
		"token": "ISSUE25_OWNED_PUSH_TOKEN_CANARY",
	})
	assertPushRequestCounts(t, sync, 2, 1)
	assertCompiledEncryptedPublication(t, sync.UploadedBlob(), cli.passphrase, map[string]string{ //nolint:gosec // test-only fake credential canaries
		"base":  base.Password,
		"alpha": alpha.Password,
		"beta":  beta.Password,
	}, wantRemote)
}

type ownedMutationPublicationRoute struct {
	name       string
	executable string
	noun       string
	action     string
	request    bool
}

func testOwnedMutationPublicationRoute(t *testing.T, route ownedMutationPublicationRoute) {
	t.Helper()
	cli := newCompiledCLIHarness(t)
	sync := newCompiledSyncFixture(t)
	password := "ISSUE25_OWNED_MUTATION_ROUTE_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password:           password,
		RunCommandContains: "hostname; uname -sr",
		RunStdoutFragments: []string{"owned-fixture\n", "Linux owned-fixture\n"},
	})
	alias := "20-owned-route"
	published := server.Connection(alias, password)
	cli.TrustSSHHost(t, server)

	unrelated := config.Connection{ //nolint:gosec // test-only fake credential canary
		Name: "10-owned-unrelated", Host: "192.0.2.150", Port: 22, User: "runner",
		Password: "ISSUE25_OWNED_UNRELATED_PASSWORD_CANARY",
	}
	base := &config.Vault{}
	if route.action == "update" {
		base.Connections = []config.Connection{{ //nolint:gosec // test-only fake credential canary
			Name: alias, Host: "192.0.2.151", Port: 22, User: "runner",
			Password: "ISSUE25_OWNED_REPLACED_PASSWORD_CANARY",
		}}
	}
	startingConnections := append([]config.Connection(nil), base.Connections...)
	startingConnections = append(startingConnections, unrelated)
	const unrelatedID = "tx_25252525252525252525252525252529"
	cli.SaveVault(t, &config.Vault{
		Connections: startingConnections,
		PendingBase: &config.InventorySnapshot{
			Connections: append([]config.Connection(nil), base.Connections...),
		},
		PendingMutations: []config.PendingMutation{{
			ID: unrelatedID, Alias: unrelated.Name, Operation: "created",
			CreatedAt: "2026-07-29T00:00:29Z", After: &unrelated,
		}},
	})
	prerequisite := encryptCompiledVault(t, cli, base)
	prerequisiteIdentity := compiledOpaqueIdentity(prerequisite)
	sync.SetRemote(t, prerequisite, prerequisiteIdentity)
	cli.SaveRemoteETag(t, prerequisiteIdentity)
	cli.SaveCloud(t, sync.URL(), "ISSUE25_OWNED_MUTATION_ROUTE_TOKEN_CANARY")
	passwordPath := filepath.Join(cli.temp, "owned-mutation-route.password")
	if err := os.WriteFile(passwordPath, []byte(password+"\n"), 0o600); err != nil {
		t.Fatalf("write owned mutation route password fixture: %v", err)
	}

	var input []byte
	var args []string
	if route.request {
		request := map[string]any{
			"version": 1,
			"op":      "host." + route.action,
			"alias":   alias,
			"host": map[string]any{
				"address":       published.Host,
				"port":          published.Port,
				"user":          published.User,
				"password_file": passwordPath,
				"verify":        true,
				"push":          true,
			},
		}
		var err error
		input, err = json.Marshal(request)
		if err != nil {
			t.Fatalf("marshal owned request route: %v", err)
		}
		args = []string{"request", "-"}
	} else {
		args = []string{
			"--json", route.noun, route.action, alias,
			"--host", published.Host,
			"--port", strconv.Itoa(published.Port),
			"--user", published.User,
			"--password-file", passwordPath,
			"--verify", "--push",
		}
	}
	result := cli.Run(t, route.executable, input, args...)
	if result.ProcessExit != 0 {
		failure := decodeExactlyOneJSONObject(t, result.Stdout)
		t.Fatalf(
			"owned mutation publication failed: error=%v stage=%v message=%v hint=%v",
			failure["error"], failure["stage"], failure["message"], failure["hint"],
		)
	}
	value := assertCompiledJSONSuccess(t, result)
	transactionID := compiledTransactionID(t, value, result)
	if value["pushed"] != true || value["sync_pending"] != true || transactionID == unrelatedID {
		t.Fatalf("owned mutation publication receipt = %#v", value)
	}
	assertNoCompiledCanaryLeak(t, result, map[string]string{ //nolint:gosec // test-only fake credential canaries
		"published": published.Password,
		"unrelated": unrelated.Password,
		"replaced":  "ISSUE25_OWNED_REPLACED_PASSWORD_CANARY",
		"token":     "ISSUE25_OWNED_MUTATION_ROUTE_TOKEN_CANARY",
	})
	assertPushRequestCounts(t, sync, 3, 1)
	assertCompiledEncryptedPublication(t, sync.UploadedBlob(), cli.passphrase, map[string]string{ //nolint:gosec // test-only fake credential canaries
		"published": published.Password,
		"unrelated": unrelated.Password,
		"replaced":  "ISSUE25_OWNED_REPLACED_PASSWORD_CANARY",
	}, &config.Vault{Connections: []config.Connection{published}})
	local := cli.LoadVaultIdentity(t)
	if len(local.PendingMutations) != 1 || local.PendingMutations[0].ID != unrelatedID {
		t.Fatal("explicit mutation publication included or lost prior pending work")
	}
}

type compiledPublishingIntentEvidence struct {
	State                string   `json:"state"`
	Scope                string   `json:"scope"`
	TransactionIDs       []string `json:"transaction_ids"`
	PrerequisiteIdentity string   `json:"prerequisite_remote_identity"`
	TargetIdentity       string   `json:"target_encrypted_blob_identity"`
}

func startCompiledPush(t *testing.T, cli *compiledCLIHarness, args ...string) *runningCompiledPublication {
	t.Helper()
	running := &runningCompiledPublication{
		command: exec.Command(cli.paths["sshctl"], args...), //nolint:gosec // fixed test-built CLI under the compiled harness
	}
	running.command.Env = isolatedCompiledCLIEnvironmentWith(cli.home, cli.temp, map[string]string{
		"SSM_MASTER_PASS_FILE": cli.passPath,
	})
	running.command.Stdout = &running.stdout
	running.command.Stderr = &running.stderr
	if err := running.command.Start(); err != nil {
		t.Fatalf("start compiled push: %v", err)
	}
	return running
}

func readCompiledPublishingIntentEvidence(t *testing.T, path string) compiledPublishingIntentEvidence {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // fixed private path beneath the harness-owned home
	if err != nil {
		t.Fatalf("read invocation-start publishing intent: %v", err)
	}
	var evidence compiledPublishingIntentEvidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		t.Fatalf("decode invocation-start publishing intent: %v", err)
	}
	return evidence
}

func assertInvocationStartIntent(
	t *testing.T,
	evidence compiledPublishingIntentEvidence,
	prerequisiteIdentity string,
	wantIDs ...string,
) {
	t.Helper()
	if evidence.State != "ready" || evidence.Scope != "all" ||
		evidence.PrerequisiteIdentity != prerequisiteIdentity ||
		len(evidence.TransactionIDs) != len(wantIDs) {
		t.Fatalf("invocation-start intent evidence = %+v", evidence)
	}
	for i, want := range wantIDs {
		if evidence.TransactionIDs[i] != want {
			t.Fatalf("invocation-start intent transaction_ids[%d] = %q, want %q", i, evidence.TransactionIDs[i], want)
		}
	}
}

func closeChannelOnce(channel chan struct{}) {
	select {
	case <-channel:
	default:
		close(channel)
	}
}

func assertPushRequestCounts(t *testing.T, sync *compiledSyncFixture, heads, puts int) {
	t.Helper()
	for method, want := range map[string]int{
		http.MethodHead: heads,
		http.MethodGet:  0,
		http.MethodPut:  puts,
	} {
		if got := sync.MethodCount(method); got != want {
			t.Fatalf("push %s count = %d, want %d", method, got, want)
		}
	}
}
