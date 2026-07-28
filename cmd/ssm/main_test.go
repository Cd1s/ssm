package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
	"ssm/internal/update"
)

func TestMigrationJSONStreamsReviewBeforeTruthfulResult(t *testing.T) {
	review := update.MigrationReview{
		Current: "v1.4.3", Target: "v2.0.0", ReleaseNotes: "notes",
		Authorized: true, AuthorizationState: "authorized",
		RollbackGuidance: "rollback", Remediation: "remediate",
	}
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{name: "success", ok: true},
		{name: "failure", ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := os.CreateTemp(t.TempDir(), "migration-json-*")
			if err != nil {
				t.Fatal(err)
			}
			oldStdout := os.Stdout
			os.Stdout = output
			t.Cleanup(func() {
				os.Stdout = oldStdout
				_ = output.Close()
			})

			finish, err := beginMigrationJSON(review)
			if err != nil {
				t.Fatal(err)
			}
			if err := output.Sync(); err != nil {
				t.Fatal(err)
			}
			prefix, err := os.ReadFile(output.Name()) //nolint:gosec // test-owned temporary output
			if err != nil {
				t.Fatal(err)
			}
			if json.Valid(prefix) || !bytes.Contains(prefix, []byte(`"authorization_state":"authorized"`)) || bytes.Contains(prefix, []byte(`"installed"`)) {
				t.Fatalf("pre-replacement prefix=%q", prefix)
			}

			failure := machinecontract.Failure{}
			if !tc.ok {
				failure = machinecontract.Failure{Error: "update_failed", Message: "rename failed", Stage: "publish", Hint: "preserve old executable", Exit: 1}
			}
			if err := finish(tc.ok, failure); err != nil {
				t.Fatal(err)
			}
			if err := output.Sync(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(output.Name()) //nolint:gosec // test-owned temporary output
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatalf("final migration JSON: %v; output=%q", err, data)
			}
			if bytes.Count(data, []byte(`"ok"`)) != 1 || bytes.Count(data, []byte(`"installed"`)) != 1 {
				t.Fatalf("final result cardinality: output=%q", data)
			}
			if document["ok"] != tc.ok || document["installed"] != tc.ok {
				t.Fatalf("result=%v", document)
			}
			if !tc.ok && document["error"] != failure.Error {
				t.Fatalf("failure result=%v", document)
			}
		})
	}
}

func setTestHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func TestMachineSuccessRendererPropagatesWriterFailure(t *testing.T) {
	err := renderMachineValue(machineRejectWriter{}, []string{"host"})
	if err == nil || !strings.Contains(err.Error(), "fixture machine output rejected") {
		t.Fatalf("machine success render error = %v", err)
	}
}

type machineRejectWriter struct{}

func (machineRejectWriter) Write([]byte) (int, error) {
	return 0, errors.New("fixture machine output rejected")
}

func TestSSHCTLInvocationNameIsPortable(t *testing.T) {
	for _, test := range []struct {
		path string
		want bool
	}{
		{path: "sshctl", want: true},
		{path: "/usr/local/bin/SSHCTL", want: true},
		{path: `C:	ools\sshctl.exe`, want: true},
		{path: `C:	ools\SSHCTL.EXE`, want: true},
		{path: "ssm", want: false},
		{path: "sshctl.test", want: false},
	} {
		if got := isSSHCTLInvocation(test.path); got != test.want {
			t.Errorf("isSSHCTLInvocation(%q) = %t, want %t", test.path, got, test.want)
		}
	}
}

func TestMachineErrorContractHasStableFields(t *testing.T) {
	value := machinecontract.Failure{OK: false, Error: "alias_not_found", Message: "missing", Hint: "list aliases", Exit: 255, Stage: "lookup"}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"ok", "error", "message", "hint", "exit", "stage"} {
		if _, ok := got[field]; !ok {
			t.Fatalf("missing %q in %s", field, encoded)
		}
	}
}

func TestParseGlobalArgsExtractsMasterPassFile(t *testing.T) {
	old := masterPassFile
	t.Cleanup(func() { masterPassFile = old })
	masterPassFile = ""

	got, err := parseGlobalArgs([]string{"--master-pass-file", "/tmp/pass", "list", "--json"})
	if err != nil {
		t.Fatalf("parseGlobalArgs: %v", err)
	}
	if masterPassFile != "/tmp/pass" {
		t.Fatalf("masterPassFile = %q", masterPassFile)
	}
	if !reflect.DeepEqual(got, []string{"list", "--json"}) {
		t.Fatalf("args = %#v", got)
	}
}

func TestInformationalInvocationSkipsUpdateCheck(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"push", "--help"}, {"help", "put"}, {"--version"}, {"update"}, {"--json", "update", "--major"}} {
		if !isInformationalInvocation(args) {
			t.Fatalf("isInformationalInvocation(%q) = false", args)
		}
	}
	if isInformationalInvocation([]string{"run", "host", "--", "--help"}) {
		t.Fatal("remote --help after delimiter must not affect update policy")
	}
	if isInformationalInvocation([]string{"host", "update", "prod", "--host", "example.com"}) {
		t.Fatal("host update must not be mistaken for the top-level update command")
	}
}

func TestParseGlobalArgsExtractsLeadingJSONOnly(t *testing.T) {
	oldJSON := machineJSON
	t.Cleanup(func() { machineJSON = oldJSON })
	machineJSON = false

	got, err := parseGlobalArgs([]string{"--json", "run", "prod", "--argv", "printf", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if !machineJSON {
		t.Fatal("leading --json did not enable machine output")
	}
	want := []string{"run", "prod", "--argv", "printf", "--json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestParseGlobalArgsExtractsLeadingOffline(t *testing.T) {
	oldOffline := offlineMode
	t.Cleanup(func() { offlineMode = oldOffline })
	offlineMode = false

	got, err := parseGlobalArgs([]string{"--offline", "status"})
	if err != nil {
		t.Fatal(err)
	}
	if !offlineMode || !reflect.DeepEqual(got, []string{"status"}) {
		t.Fatalf("offline=%t args=%v", offlineMode, got)
	}
}

func TestSplitRunAliasHandlesCommandLocalJSON(t *testing.T) {
	alias, args, err := splitRunAlias([]string{"--json", "prod", "--argv", "hostname"})
	if err != nil {
		t.Fatal(err)
	}
	if alias != "prod" || !reflect.DeepEqual(args, []string{"--json", "--argv", "hostname"}) {
		t.Fatalf("alias=%q args=%v", alias, args)
	}
	if _, _, err := splitRunAlias([]string{"--json"}); err == nil {
		t.Fatal("accepted missing alias")
	}
}

func TestParseGlobalArgsRejectsEmptyMasterPassFile(t *testing.T) {
	old := masterPassFile
	t.Cleanup(func() { masterPassFile = old })
	masterPassFile = ""

	for _, args := range [][]string{
		{"--master-pass-file"},
		{"--master-pass-file="},
	} {
		if _, err := parseGlobalArgs(args); err == nil {
			t.Fatalf("parseGlobalArgs(%v) accepted missing path", args)
		}
	}
}

func TestRedactStringRemovesSensitiveFields(t *testing.T) {
	in := "password=hunter2 token:abc123 authorization: bearer deadbeef private_key=inline"
	got := redactString(in)
	for _, secret := range []string{"hunter2", "abc123", "deadbeef", "inline"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted string %q still contains %q", got, secret)
		}
	}
}

func TestRedactStringRemovesJSONStyleSensitiveFields(t *testing.T) {
	in := `{"password":"value-to-hide","token":"token-to-hide","private_key":"key-to-hide","authorization":"Bearer bearer-to-hide","nested":{"secret":"secret-to-hide"}}`
	got := redactString(in)
	for _, secret := range []string{"value-to-hide", "token-to-hide", "key-to-hide", "bearer-to-hide", "secret-to-hide"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted string %q still contains %q", got, secret)
		}
	}
}

func TestRedactStringRemovesPrivateKeyBlocks(t *testing.T) {
	in := "bad key -----BEGIN OPENSSH PRIVATE KEY-----\nsecret-key\n-----END OPENSSH PRIVATE KEY-----"
	got := redactString(in)
	if strings.Contains(got, "secret-key") || strings.Contains(got, "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatalf("private key block was not redacted: %q", got)
	}
}

func TestRedactStringKeepsPlainWrongPasswordDiagnostic(t *testing.T) {
	got := redactString("wrong password or corrupted file")
	if got != "wrong password or corrupted file" {
		t.Fatalf("diagnostic = %q", got)
	}
}

func TestRedactErrorCoversSecretBearingPaths(t *testing.T) {
	got := redactError(&os.PathError{Op: "open", Path: "/tmp/password=hunter2", Err: os.ErrNotExist})
	if strings.Contains(got, "hunter2") {
		t.Fatalf("redacted path still contains secret: %q", got)
	}
}

func TestLoadVaultConsumesUnlockedSnapshotThenReadsLaterSave(t *testing.T) {
	setTestHome(t, t.TempDir())
	oldPass, oldPassFile, oldVault := masterPass, masterPassFile, unlockedVault
	t.Cleanup(func() {
		masterPass, masterPassFile, unlockedVault = oldPass, oldPassFile, oldVault
	})

	const pass = "test-vault-pass"
	if err := config.Save(&config.Vault{Connections: []config.Connection{{Name: "before"}}}, pass); err != nil {
		t.Fatal(err)
	}
	passFile := filepath.Join(t.TempDir(), "master.pass")
	if err := os.WriteFile(passFile, []byte(pass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	masterPassFile = passFile
	unlockedVault = nil
	unlock()
	unlocked := unlockedVault

	first, err := loadVault()
	if err != nil {
		t.Fatal(err)
	}
	if first != unlocked || unlockedVault != nil || len(first.Connections) != 1 || first.Connections[0].Name != "before" {
		t.Fatalf("first vault = %+v", first)
	}

	if err := config.Save(&config.Vault{Connections: []config.Connection{{Name: "after"}}}, pass); err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadVault()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded == first || len(reloaded.Connections) != 1 || reloaded.Connections[0].Name != "after" {
		t.Fatalf("reloaded vault = %+v", reloaded)
	}
}

func TestStatusFailureAdapterSubprocessHelper(t *testing.T) {
	if os.Getenv("SSM_TEST_STATUS_FAILURE_HELPER") != "1" {
		return
	}

	setTestHome(t, t.TempDir())
	const canary = `config="{\"token\":\"STATUS_FAILURE_CONFIG_CANARY\"}"`
	if err := config.SaveSettings(&config.Settings{
		PasswordCache: "never",
		AutoSync:      true,
		LastPush:      canary,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.Path(), []byte("invalid encrypted vault"), 0o600); err != nil {
		t.Fatal(err)
	}

	machineJSON = true
	offlineMode = true
	masterPass = "status-failure-pass"
	masterPassFile = ""
	unlockedVault = nil
	runSSHCTLStatus()
	t.Fatal("failed status adapter returned")
}

func TestStatusFailureAdapterUsesFailureRenderer(t *testing.T) {
	t.Setenv("SSM_TEST_PUSH_HELPER", "1")
	t.Setenv("SSM_TEST_STATUS_FAILURE_HELPER", "1")
	t.Setenv("SSM_REUSE", "1")

	cmd := exec.Command(os.Args[0], "-test.run=^TestStatusFailureAdapterSubprocessHelper$", "-test.count=1") //nolint:gosec // executes this test binary with a fixed selector
	cmd.Env = os.Environ()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	processExit := 0
	if err := cmd.Run(); err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run failed-status adapter helper: %v", err)
		}
		processExit = exitErr.ExitCode()
	}
	if processExit != 1 || stderr.Len() != 0 {
		t.Fatalf("failed status placement/exit: exit=%d stdout=%q stderr=%q", processExit, stdout.String(), stderr.String())
	}
	if !strings.HasSuffix(stdout.String(), "\n") || !strings.Contains(stdout.String(), "\n  \"version\":") {
		t.Fatalf("failed status is not one indented JSON document: %q", stdout.String())
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode failed status: %v; stdout=%q", err, stdout.String())
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("failed status emitted more than one JSON value: %q", stdout.String())
	}
	if len(value) != 14 {
		t.Fatalf("failed status field count=%d, want 14; fields=%v", len(value), value)
	}
	for _, absent := range []string{"error", "message", "hint", "exit", "stage", "last_pull", "last_sync", "cache_age_seconds"} {
		if _, exists := value[absent]; exists {
			t.Fatalf("failed status unexpectedly added %q: %v", absent, value)
		}
	}
	if ok, _ := value["ok"].(bool); ok ||
		value["version"] != version ||
		value["hosts"] != float64(0) ||
		value["vault"] != "present" ||
		value["sync"] != "missing" ||
		value["redirects"] != float64(0) ||
		value["reuse"] != "on" ||
		value["reuse_scope"] != "process" ||
		value["last_push"] != "config=<redacted>" ||
		value["freshness"] != "unknown" ||
		value["remote_state"] != "not_configured" ||
		value["pending_changes"] != false ||
		value["offline"] != true {
		t.Fatalf("failed status fields changed: %v", value)
	}
	mutations, ok := value["pending_mutations"].([]any)
	if !ok || len(mutations) != 0 {
		t.Fatalf("failed status pending_mutations=%v, want []", value["pending_mutations"])
	}
	if strings.Contains(stdout.String(), "STATUS_FAILURE_CONFIG_CANARY") {
		t.Fatalf("failed status leaked config canary: %q", stdout.String())
	}
}
