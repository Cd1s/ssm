package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"ssm/internal/config"
)

const (
	compiledBC3NewStartupFailure = "{\"ok\":false,\"error\":\"sync_pull_failed\",\"message\":\"sync refresh failed: remote refresh did not commit\",\"hint\":\"fix sync connectivity or restart explicitly with --offline\",\"stage\":\"sync_pull\",\"exit\":1}\n"
	compiledBC6NewZeroOnline     = "{\"ok\":false,\"error\":\"invalid_arguments\",\"message\":\"--refresh=0 requires explicit global --offline\",\"hint\":\"use sshctl run \\u003calias\\u003e --stream [--refresh 30s]\",\"exit\":2}\n"
	compiledStreamMigrationPath  = "testdata/compiled_contracts/v2_stream_migration.json"
)

type compiledStreamMigrationFixture struct {
	SchemaVersion int                         `json:"schema_version"`
	BC3           compiledStreamMigrationCase `json:"bc_3"`
	BC6           compiledStreamMigrationCase `json:"bc_6"`
}

type compiledStreamMigrationCase struct {
	Command string                       `json:"command"`
	Input   string                       `json:"input"`
	Before  compiledStreamMigrationState `json:"before"`
	After   compiledStreamMigrationState `json:"after"`
}

type compiledStreamMigrationState struct {
	Accepted              bool   `json:"accepted"`
	Framing               string `json:"framing"`
	Stdout                string `json:"stdout"`
	StdoutLines           int    `json:"stdout_lines"`
	ProcessExit           int    `json:"process_exit"`
	ConsumedNonEmptyLines int    `json:"consumed_non_empty_lines"`
	HeadRequests          int    `json:"head_requests"`
	GetRequests           int    `json:"get_requests"`
	PutRequests           int    `json:"put_requests"`
	TCPConnections        int    `json:"tcp_connections"`
	SSHSessions           int    `json:"ssh_sessions"`
}

func TestStreamMigrationFixture(t *testing.T) {
	data, err := os.ReadFile(compiledStreamMigrationPath)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var fixture compiledStreamMigrationFixture
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatal("stream migration fixture contains trailing data")
	}

	const oldBC3 = "{\n  \"ok\": false,\n  \"error\": \"sync_pull_failed\",\n  \"message\": \"sync refresh failed: remote refresh did not commit\",\n  \"hint\": \"fix sync connectivity or retry explicitly with --offline\",\n  \"stage\": \"sync_pull\",\n  \"exit\": 1\n}\n"
	if fixture.SchemaVersion != 1 ||
		fixture.BC3.Before.Stdout != oldBC3 ||
		fixture.BC3.After.Stdout != compiledBC3NewStartupFailure ||
		fixture.BC6.After.Stdout != compiledBC6NewZeroOnline {
		t.Fatalf("stream migration exact-byte fixture drifted")
	}
	if !reflect.DeepEqual(
		[]int{
			fixture.BC3.Before.StdoutLines,
			fixture.BC3.After.StdoutLines,
			fixture.BC6.Before.ConsumedNonEmptyLines,
			fixture.BC6.After.ConsumedNonEmptyLines,
			fixture.BC6.Before.HeadRequests,
			fixture.BC6.After.HeadRequests,
			fixture.BC6.Before.SSHSessions,
			fixture.BC6.After.SSHSessions,
		},
		[]int{8, 1, 2, 0, 1, 0, 2, 0},
	) {
		t.Fatalf("stream migration count fixture drifted")
	}
}

func TestCompiledStreamContract(t *testing.T) {
	t.Run("online zero refresh is one compact initialization failure", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		password := "ISSUE21_ZERO_ONLINE_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
		cli.TrustSSHHost(t, server)
		cli.SaveVault(t, &config.Vault{
			Connections: []config.Connection{server.Connection("zero-online", password)},
		})

		result := cli.Run(
			t,
			"sshctl",
			[]byte("[\"true\"]\n"),
			"--json", "run", "zero-online", "--stream", "--refresh=0",
		)
		assertNoCompiledCanaryLeak(t, result, map[string]string{"password": password})
		if result.ProcessExit != 2 || result.Stdout != compiledBC6NewZeroOnline || result.Stderr != "" {
			t.Fatalf("zero online stream contract failed; output=%s", compiledOutputIdentity(result))
		}
		if server.ConnectionCount() != 0 || server.SessionCount() != 0 {
			t.Fatalf(
				"zero online stream reached SSH: connections=%d sessions=%d",
				server.ConnectionCount(),
				server.SessionCount(),
			)
		}
	})

	t.Run("startup refresh failure is one compact terminal line", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		sync.SetStatus(t, http.MethodHead, http.StatusInternalServerError)
		cli.SaveVault(t, &config.Vault{})
		cli.SaveCloud(t, sync.URL(), "ISSUE21_STARTUP_SYNC_TOKEN_CANARY")

		result := cli.RunWithHeldOpenStdin(
			t,
			"sshctl",
			"--json", "run", "unused", "--stream", "--refresh=30s",
		)
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"token":      "ISSUE21_STARTUP_SYNC_TOKEN_CANARY",
			"passphrase": cli.passphrase,
		})
		if result.ProcessExit != 1 || result.Stdout != compiledBC3NewStartupFailure || result.Stderr != "" {
			t.Fatalf("startup refresh stream contract failed; output=%s", compiledOutputIdentity(result))
		}
		if got := sync.MethodCount(http.MethodHead); got != 1 {
			t.Fatalf("startup refresh HEAD count = %d, want 1", got)
		}
	})

	t.Run("startup vault failure is one compact terminal line", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		if err := os.WriteFile(cli.passPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}

		result := cli.RunWithHeldOpenStdin(
			t,
			"sshctl",
			"--offline", "run", "unused", "--stream", "--refresh=0",
		)
		const want = "{\"ok\":false,\"error\":\"master_pass_file_error\",\"message\":\"master pass file is empty\",\"hint\":\"write the vault passphrase to the configured file\",\"exit\":1}\n"
		if result.ProcessExit != 1 || result.Stdout != want || result.Stderr != "" {
			t.Fatalf("startup vault stream contract failed; output=%s", compiledOutputIdentity(result))
		}
	})

	t.Run("refresh failure is the triggering line only and stops", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		cli.SaveVault(t, &config.Vault{})
		blob := cli.VaultBlob(t)
		identity := fmt.Sprintf("%x", sha256.Sum256(blob))
		cli.SaveCloud(t, sync.URL(), "ISSUE21_REFRESH_FAILURE_TOKEN_CANARY")
		cli.SaveRemoteETag(t, identity)
		sync.SetRemote(t, blob, identity)
		sync.SetStatusAfter(t, http.MethodHead, 1, http.StatusInternalServerError)

		input, writer := io.Pipe()
		go func() {
			if err := waitForCompiledStreamState(func() bool {
				return sync.MethodCount(http.MethodHead) == 1
			}); err != nil {
				_ = writer.CloseWithError(err)
				return
			}
			time.Sleep(120 * time.Millisecond)
			_, _ = io.WriteString(writer, "[\"true\"]\n[\"true\"]\n")
			_ = writer.Close()
		}()
		result := cli.runWithStdin(
			t,
			"sshctl",
			input,
			map[string]string{"SSM_MASTER_PASS_FILE": cli.passPath},
			"--json", "run", "unused", "--stream", "--refresh=100ms",
		)
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"token": "ISSUE21_REFRESH_FAILURE_TOKEN_CANARY",
		})
		if result.ProcessExit != 1 || result.Stdout != compiledBC3NewStartupFailure || result.Stderr != "" {
			t.Fatalf("refresh failure stream contract failed; output=%s", compiledOutputIdentity(result))
		}
		if got := sync.MethodCount(http.MethodHead); got != 2 {
			t.Fatalf("refresh failure HEAD count = %d, want startup plus triggering-line refresh", got)
		}
		if sync.MethodCount(http.MethodGet) != 0 || sync.MethodCount(http.MethodPut) != 0 {
			t.Fatalf(
				"refresh failure requests GET=%d PUT=%d, want 0 and 0",
				sync.MethodCount(http.MethodGet),
				sync.MethodCount(http.MethodPut),
			)
		}
	})

	t.Run("each non-empty line has one ordered compact result", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		password := "ISSUE21_CARDINALITY_PASSWORD_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
		cli.TrustSSHHost(t, server)
		cli.SaveVault(t, &config.Vault{
			Connections: []config.Connection{server.Connection("cardinality", password)},
		})
		input := strings.Join([]string{
			"",
			"{bad}",
			"[\"true\"]",
			"[\"sh\",\"-c\",\"exit 255\"]",
			"[\"true\"]",
			"",
		}, "\n")

		result := cli.Run(
			t,
			"sshctl",
			[]byte(input),
			"--offline", "--json", "run", "cardinality", "--stream", "--refresh=0",
		)
		assertNoCompiledCanaryLeak(t, result, map[string]string{"password": password})
		if result.ProcessExit != 255 || result.Stderr != "" {
			t.Fatalf("mixed stream process contract failed; output=%s", compiledOutputIdentity(result))
		}
		lines := nonEmptyCompiledLines(result.Stdout)
		if len(lines) != 4 {
			t.Fatalf("mixed stream line count = %d, want 4; output=%s", len(lines), compiledOutputIdentity(result))
		}
		want := []struct {
			ok    bool
			code  string
			stage string
			exit  int
		}{
			{ok: false, code: "invalid_request", stage: "decode", exit: 2},
			{ok: true, exit: 0},
			{ok: false, code: "remote_failed", stage: "remote_execution", exit: 255},
			{ok: true, exit: 0},
		}
		for index, line := range lines {
			if strings.TrimSpace(line) != line {
				t.Fatalf("stream line %d is not compact framing", index)
			}
			var value map[string]any
			if err := json.Unmarshal([]byte(line), &value); err != nil {
				t.Fatalf("decode stream line %d: %v", index, err)
			}
			if value["ok"] != want[index].ok ||
				value["error"] != emptyStringAsNil(want[index].code) ||
				value["stage"] != emptyStringAsNil(want[index].stage) ||
				!compiledJSONExitEquals(value["exit"], want[index].exit) {
				t.Fatalf("stream line %d fields = %#v", index, value)
			}
		}
		if server.ConnectionCount() != 1 || server.SessionCount() != 3 {
			t.Fatalf(
				"mixed stream SSH counts connections=%d sessions=%d, want 1 and 3",
				server.ConnectionCount(),
				server.SessionCount(),
			)
		}
	})
}

func TestStreamRefreshClosesPool(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	sync := newCompiledSyncFixture(t)
	password := "ISSUE21_REFRESH_PASSWORD_CANARY"
	unrelatedPassword := "ISSUE21_UNRELATED_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
	refreshToken := "ISSUE21_REFRESH_TOKEN_CANARY"           //nolint:gosec // test-only fake credential canary
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
	cli.TrustSSHHost(t, server)

	active := server.Connection("active", password)
	initial := &config.Vault{Connections: []config.Connection{active}}
	cli.SaveVault(t, initial)
	initialBlob := cli.VaultBlob(t)
	initialIdentity := fmt.Sprintf("%x", sha256.Sum256(initialBlob))
	cli.SaveCloud(t, sync.URL(), refreshToken)
	cli.SaveRemoteETag(t, initialIdentity)
	sync.SetRemote(t, initialBlob, initialIdentity)

	changed := &config.Vault{Connections: []config.Connection{
		active,
		{
			Name: "unrelated-added", Host: "192.0.2.121", Port: 22, User: "unused",
			Password: unrelatedPassword,
		},
	}}
	changedBlob, err := config.EncryptVault(changed, cli.passphrase)
	if err != nil {
		t.Fatal(err)
	}
	changedIdentity := fmt.Sprintf("%x", sha256.Sum256(changedBlob))

	input, writer := io.Pipe()
	writeDone := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(writer, "[\"true\"]\n"); err != nil {
			writeDone <- err
			return
		}
		if err := waitForCompiledStreamState(func() bool { return server.SessionCount() == 1 }); err != nil {
			writeDone <- err
			_ = writer.CloseWithError(err)
			return
		}
		sync.setRemote(changedBlob, changedIdentity)
		time.Sleep(120 * time.Millisecond)
		_, err := io.WriteString(writer, "[\"true\"]\n")
		if closeErr := writer.Close(); err == nil {
			err = closeErr
		}
		writeDone <- err
	}()

	result := cli.runWithStdin(
		t,
		"sshctl",
		input,
		map[string]string{"SSM_MASTER_PASS_FILE": cli.passPath},
		"--json", "run", "active", "--stream", "--refresh=100ms",
	)
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	assertNoCompiledCanaryLeak(t, result, map[string]string{
		"password":           password,
		"unrelated_password": unrelatedPassword,
		"token":              refreshToken,
	})
	assertTwoCompiledNDJSONSuccesses(t, result)
	if got := sync.MethodCount(http.MethodHead); got != 2 {
		t.Fatalf("stream refresh HEAD count = %d, want startup plus one due refresh", got)
	}
	if got := sync.MethodCount(http.MethodGet); got != 1 {
		t.Fatalf("stream refresh GET count = %d, want 1 changed snapshot load", got)
	}
	if got := sync.MethodCount(http.MethodPut); got != 0 {
		t.Fatalf("stream refresh PUT count = %d, want 0", got)
	}
	if server.ConnectionCount() != 2 || server.SessionCount() != 2 {
		t.Fatalf(
			"changed inventory SSH counts connections=%d sessions=%d, want 2 and 2",
			server.ConnectionCount(),
			server.SessionCount(),
		)
	}

	t.Run("unchanged inventory retains one connection and two command sessions", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		password := "ISSUE21_UNCHANGED_PASSWORD_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
		cli.TrustSSHHost(t, server)
		cli.SaveVault(t, &config.Vault{
			Connections: []config.Connection{server.Connection("active", password)},
		})
		blob := cli.VaultBlob(t)
		identity := fmt.Sprintf("%x", sha256.Sum256(blob))
		cli.SaveCloud(t, sync.URL(), "ISSUE21_UNCHANGED_TOKEN_CANARY")
		cli.SaveRemoteETag(t, identity)
		sync.SetRemote(t, blob, identity)

		input, writer := io.Pipe()
		writeDone := make(chan error, 1)
		go func() {
			if _, err := io.WriteString(writer, "[\"true\"]\n"); err != nil {
				writeDone <- err
				return
			}
			if err := waitForCompiledStreamState(func() bool { return server.SessionCount() == 1 }); err != nil {
				writeDone <- err
				_ = writer.CloseWithError(err)
				return
			}
			time.Sleep(120 * time.Millisecond)
			_, err := io.WriteString(writer, "[\"true\"]\n")
			if closeErr := writer.Close(); err == nil {
				err = closeErr
			}
			writeDone <- err
		}()
		result := cli.runWithStdin(
			t,
			"sshctl",
			input,
			map[string]string{"SSM_MASTER_PASS_FILE": cli.passPath},
			"--json", "run", "active", "--stream", "--refresh=100ms",
		)
		if err := <-writeDone; err != nil {
			t.Fatal(err)
		}
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"password": password,
			"token":    "ISSUE21_UNCHANGED_TOKEN_CANARY",
		})
		assertTwoCompiledNDJSONSuccesses(t, result)
		if sync.MethodCount(http.MethodHead) != 2 ||
			sync.MethodCount(http.MethodGet) != 0 ||
			sync.MethodCount(http.MethodPut) != 0 {
			t.Fatalf(
				"unchanged stream requests HEAD=%d GET=%d PUT=%d, want 2, 0, 0",
				sync.MethodCount(http.MethodHead),
				sync.MethodCount(http.MethodGet),
				sync.MethodCount(http.MethodPut),
			)
		}
		if server.ConnectionCount() != 1 || server.SessionCount() != 2 {
			t.Fatalf(
				"unchanged stream SSH counts connections=%d sessions=%d, want 1 and 2",
				server.ConnectionCount(),
				server.SessionCount(),
			)
		}
	})

	t.Run("order key material and authentication reference changes close an unrelated active client", func(t *testing.T) {
		cases := []struct {
			name   string
			vaults func(config.Connection) (*config.Vault, *config.Vault)
		}{
			{
				name: "alias order",
				vaults: func(active config.Connection) (*config.Vault, *config.Vault) {
					spare := active
					spare.Name = "spare"
					return &config.Vault{Connections: []config.Connection{active, spare}},
						&config.Vault{Connections: []config.Connection{spare, active}}
				},
			},
			{
				name: "saved key material",
				vaults: func(active config.Connection) (*config.Vault, *config.Vault) {
					return &config.Vault{
							Connections: []config.Connection{active},
							Keys:        []config.SSHKey{{Name: "unused-key", PrivateKey: "ISSUE21_OLD_KEY_CANARY"}},
						}, &config.Vault{
							Connections: []config.Connection{active},
							Keys:        []config.SSHKey{{Name: "unused-key", PrivateKey: "ISSUE21_NEW_KEY_CANARY"}},
						}
				},
			},
			{
				name: "authentication reference",
				vaults: func(active config.Connection) (*config.Vault, *config.Vault) {
					unused := active
					unused.Name = "unused-key-host"
					unused.Password = ""
					unused.KeyName = "old-key"
					changedUnused := unused
					changedUnused.KeyName = "new-key"
					keys := []config.SSHKey{
						{Name: "old-key", PrivateKey: "ISSUE21_OLD_REFERENCE_KEY_CANARY"},
						{Name: "new-key", PrivateKey: "ISSUE21_NEW_REFERENCE_KEY_CANARY"},
					}
					return &config.Vault{Connections: []config.Connection{active, unused}, Keys: keys},
						&config.Vault{Connections: []config.Connection{active, changedUnused}, Keys: keys}
				},
			},
		}

		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				cli := newCompiledCLIHarness(t)
				password := "ISSUE21_IDENTITY_PASSWORD_CANARY"
				server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
				cli.TrustSSHHost(t, server)
				initial, changed := test.vaults(server.Connection("active", password))
				result, sync := runCompiledChangedStream(
					t, cli, initial, changed,
					func() bool { return server.SessionCount() == 1 },
					nil,
				)
				assertNoCompiledCanaryLeak(t, result, map[string]string{
					"password": password,
					"old_key":  "ISSUE21_OLD_KEY_CANARY",
					"new_key":  "ISSUE21_NEW_KEY_CANARY",
				})
				assertTwoCompiledNDJSONSuccesses(t, result)
				assertCompiledChangedStreamRequests(t, sync)
				if server.ConnectionCount() != 2 || server.SessionCount() != 2 {
					t.Fatalf(
						"%s SSH counts connections=%d sessions=%d, want 2 and 2",
						test.name,
						server.ConnectionCount(),
						server.SessionCount(),
					)
				}
			})
		}
	})

	t.Run("address user and port changes use only the replacement endpoint", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		firstPassword := "ISSUE21_FIRST_ENDPOINT_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
		secondPassword := "ISSUE21_SECOND_ENDPOINT_PASSWORD_CANARY"
		first := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: firstPassword})
		second := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: secondPassword})
		cli.TrustSSHHost(t, first)
		cli.TrustSSHHost(t, second)
		initialConnection := first.Connection("active", firstPassword)
		changedConnection := second.Connection("active", secondPassword)
		changedConnection.User = "replacement-user"

		result, sync := runCompiledChangedStream(
			t,
			cli,
			&config.Vault{Connections: []config.Connection{initialConnection}},
			&config.Vault{Connections: []config.Connection{changedConnection}},
			func() bool { return first.SessionCount() == 1 },
			nil,
		)
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"first_password":  firstPassword,
			"second_password": secondPassword,
		})
		assertTwoCompiledNDJSONSuccesses(t, result)
		assertCompiledChangedStreamRequests(t, sync)
		if first.ConnectionCount() != 1 || first.SessionCount() != 1 ||
			second.ConnectionCount() != 1 || second.SessionCount() != 1 {
			t.Fatalf(
				"endpoint swap counts first=%d/%d second=%d/%d, want 1/1 and 1/1",
				first.ConnectionCount(),
				first.SessionCount(),
				second.ConnectionCount(),
				second.SessionCount(),
			)
		}
	})

	t.Run("credential change cannot reuse the authenticated client", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		password := "ISSUE21_ACCEPTED_PASSWORD_CANARY"
		rejected := "ISSUE21_REJECTED_PASSWORD_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
		cli.TrustSSHHost(t, server)
		initialConnection := server.Connection("active", password)
		changedConnection := initialConnection
		changedConnection.Password = rejected

		result, sync := runCompiledChangedStream(
			t,
			cli,
			&config.Vault{Connections: []config.Connection{initialConnection}},
			&config.Vault{Connections: []config.Connection{changedConnection}},
			func() bool { return server.SessionCount() == 1 },
			nil,
		)
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"accepted_password": password,
			"rejected_password": rejected,
		})
		values := decodeCompiledStreamResults(t, result, 2)
		if values[0]["ok"] != true ||
			values[1]["ok"] != false ||
			values[1]["error"] != "auth_failed" ||
			values[1]["stage"] != "dial" {
			t.Fatalf("credential swap results = %#v", values)
		}
		assertCompiledChangedStreamRequests(t, sync)
		if server.ConnectionCount() != 1 || server.SessionCount() != 1 {
			t.Fatalf(
				"credential swap reused an authenticated client: connections=%d sessions=%d",
				server.ConnectionCount(),
				server.SessionCount(),
			)
		}
	})

	t.Run("trust state is rechecked after inventory replacement", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		password := "ISSUE21_TRUST_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
		cli.TrustSSHHost(t, server)
		initialConnection := server.Connection("active", password)
		changedConnection := initialConnection
		changedConnection.Group = "inventory-changed"
		removeTrust := func() error {
			return os.Remove(filepath.Join(cli.home, ".ssh", "known_hosts"))
		}

		result, sync := runCompiledChangedStream(
			t,
			cli,
			&config.Vault{Connections: []config.Connection{initialConnection}},
			&config.Vault{Connections: []config.Connection{changedConnection}},
			func() bool { return server.SessionCount() == 1 },
			removeTrust,
		)
		assertNoCompiledCanaryLeak(t, result, map[string]string{"password": password})
		values := decodeCompiledStreamResults(t, result, 2)
		if values[0]["ok"] != true ||
			values[1]["ok"] != false ||
			values[1]["error"] != "host_key_unknown" ||
			values[1]["stage"] != "dial" {
			t.Fatalf("trust replacement results = %#v", values)
		}
		assertCompiledChangedStreamRequests(t, sync)
		if server.ConnectionCount() != 1 || server.SessionCount() != 1 {
			t.Fatalf(
				"trust change reused the old client: connections=%d sessions=%d",
				server.ConnectionCount(),
				server.SessionCount(),
			)
		}
	})

	t.Run("removed alias fails without selecting its suggestion", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		password := "ISSUE21_REMOVED_ALIAS_PASSWORD_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
		cli.TrustSSHHost(t, server)
		active := server.Connection("active", password)
		candidate := active
		candidate.Name = "active-old"

		result, sync := runCompiledChangedStream(
			t,
			cli,
			&config.Vault{Connections: []config.Connection{active, candidate}},
			&config.Vault{Connections: []config.Connection{candidate}},
			func() bool { return server.SessionCount() == 1 },
			nil,
		)
		assertNoCompiledCanaryLeak(t, result, map[string]string{"password": password})
		values := decodeCompiledStreamResults(t, result, 2)
		if values[0]["ok"] != true ||
			values[1]["ok"] != false ||
			values[1]["error"] != "alias_not_found" ||
			values[1]["stage"] != "lookup" ||
			values[1]["alias"] != "active" {
			t.Fatalf("removed alias results = %#v", values)
		}
		assertCompiledChangedStreamRequests(t, sync)
		if server.ConnectionCount() != 1 || server.SessionCount() != 1 {
			t.Fatalf(
				"removed alias selected a candidate: connections=%d sessions=%d",
				server.ConnectionCount(),
				server.SessionCount(),
			)
		}
	})
}

func TestStreamOfflineUsesFixedSnapshot(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	sync := newCompiledSyncFixture(t)
	initialPassword := "ISSUE21_OFFLINE_INITIAL_PASSWORD_CANARY"
	replacementPassword := "ISSUE21_OFFLINE_REPLACEMENT_PASSWORD_CANARY"
	initialServer := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: initialPassword})
	replacementServer := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: replacementPassword})
	cli.TrustSSHHost(t, initialServer)
	cli.TrustSSHHost(t, replacementServer)
	cli.SaveVault(t, &config.Vault{
		Connections: []config.Connection{initialServer.Connection("fixed", initialPassword)},
	})
	replacementBlob, err := config.EncryptVault(&config.Vault{
		Connections: []config.Connection{replacementServer.Connection("fixed", replacementPassword)},
	}, cli.passphrase)
	if err != nil {
		t.Fatal(err)
	}
	cli.writeConfigFile(
		t,
		"cloud.json",
		[]byte(`{"server":"`+sync.URL()+`","token":"ISSUE21_OFFLINE_CLOUD_TOKEN_CANARY"`),
	)

	input, writer := io.Pipe()
	writeDone := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(writer, "[\"true\"]\n"); err != nil {
			writeDone <- err
			return
		}
		if err := waitForCompiledStreamState(func() bool { return initialServer.SessionCount() == 1 }); err != nil {
			writeDone <- err
			_ = writer.CloseWithError(err)
			return
		}
		path := filepath.Join(cli.home, ".config", "ssm", "connections.enc")
		if err := os.WriteFile(path, replacementBlob, 0o600); err != nil {
			writeDone <- err
			_ = writer.CloseWithError(err)
			return
		}
		_, err := io.WriteString(writer, "[\"true\"]\n")
		if closeErr := writer.Close(); err == nil {
			err = closeErr
		}
		writeDone <- err
	}()

	result := cli.runWithStdin(
		t,
		"sshctl",
		input,
		map[string]string{"SSM_MASTER_PASS_FILE": cli.passPath},
		"--offline", "--json", "run", "fixed", "--stream", "--refresh=0",
	)
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	assertNoCompiledCanaryLeak(t, result, map[string]string{
		"initial_password":     initialPassword,
		"replacement_password": replacementPassword,
		"cloud_token":          "ISSUE21_OFFLINE_CLOUD_TOKEN_CANARY",
	})
	assertTwoCompiledNDJSONSuccesses(t, result)
	if initialServer.ConnectionCount() != 1 || initialServer.SessionCount() != 2 {
		t.Fatalf(
			"offline fixed snapshot counts connections=%d sessions=%d, want 1 and 2",
			initialServer.ConnectionCount(),
			initialServer.SessionCount(),
		)
	}
	if replacementServer.ConnectionCount() != 0 || replacementServer.SessionCount() != 0 {
		t.Fatalf(
			"offline stream loaded replacement snapshot: connections=%d sessions=%d",
			replacementServer.ConnectionCount(),
			replacementServer.SessionCount(),
		)
	}
	for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
		if got := sync.MethodCount(method); got != 0 {
			t.Fatalf("offline stream %s request count = %d, want 0", method, got)
		}
	}
}

func emptyStringAsNil(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func waitForCompiledStreamState(ready func() bool) error {
	deadline := time.Now().Add(5 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			return fmt.Errorf("compiled stream did not reach the expected intermediate state")
		}
		time.Sleep(time.Millisecond)
	}
	return nil
}

func runCompiledChangedStream(
	t *testing.T,
	cli *compiledCLIHarness,
	initial, changed *config.Vault,
	firstLineComplete func() bool,
	beforeSecondLine func() error,
) (compiledCLIResult, *compiledSyncFixture) {
	t.Helper()
	sync := newCompiledSyncFixture(t)
	cli.SaveVault(t, initial)
	initialBlob := cli.VaultBlob(t)
	initialIdentity := fmt.Sprintf("%x", sha256.Sum256(initialBlob))
	changedBlob, err := config.EncryptVault(changed, cli.passphrase)
	if err != nil {
		t.Fatal(err)
	}
	changedIdentity := fmt.Sprintf("%x", sha256.Sum256(changedBlob))
	cli.SaveCloud(t, sync.URL(), "ISSUE21_CHANGED_STREAM_TOKEN_CANARY")
	cli.SaveRemoteETag(t, initialIdentity)
	sync.SetRemote(t, initialBlob, initialIdentity)

	input, writer := io.Pipe()
	writeDone := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(writer, "[\"true\"]\n"); err != nil {
			writeDone <- err
			return
		}
		if err := waitForCompiledStreamState(firstLineComplete); err != nil {
			writeDone <- err
			_ = writer.CloseWithError(err)
			return
		}
		if beforeSecondLine != nil {
			if err := beforeSecondLine(); err != nil {
				writeDone <- err
				_ = writer.CloseWithError(err)
				return
			}
		}
		sync.setRemote(changedBlob, changedIdentity)
		time.Sleep(120 * time.Millisecond)
		_, err := io.WriteString(writer, "[\"true\"]\n")
		if closeErr := writer.Close(); err == nil {
			err = closeErr
		}
		writeDone <- err
	}()

	result := cli.runWithStdin(
		t,
		"sshctl",
		input,
		map[string]string{"SSM_MASTER_PASS_FILE": cli.passPath},
		"--json", "run", "active", "--stream", "--refresh=100ms",
	)
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	return result, sync
}

func assertCompiledChangedStreamRequests(t *testing.T, sync *compiledSyncFixture) {
	t.Helper()
	if sync.MethodCount(http.MethodHead) != 2 ||
		sync.MethodCount(http.MethodGet) != 1 ||
		sync.MethodCount(http.MethodPut) != 0 {
		t.Fatalf(
			"changed stream requests HEAD=%d GET=%d PUT=%d, want 2, 1, 0",
			sync.MethodCount(http.MethodHead),
			sync.MethodCount(http.MethodGet),
			sync.MethodCount(http.MethodPut),
		)
	}
}

func decodeCompiledStreamResults(t *testing.T, result compiledCLIResult, wantLines int) []map[string]any {
	t.Helper()
	if result.Stderr != "" {
		t.Fatalf("stream stderr is not empty; output=%s", compiledOutputIdentity(result))
	}
	lines := nonEmptyCompiledLines(result.Stdout)
	if len(lines) != wantLines {
		t.Fatalf("stream result line count = %d, want %d; output=%s", len(lines), wantLines, compiledOutputIdentity(result))
	}
	values := make([]map[string]any, len(lines))
	for index, line := range lines {
		if err := json.Unmarshal([]byte(line), &values[index]); err != nil {
			t.Fatalf("decode stream result %d: %v; output=%s", index, err, compiledOutputIdentity(result))
		}
	}
	return values
}
