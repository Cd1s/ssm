package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ssm/internal/config"
	"ssm/internal/update"
)

func TestMajorUpdateOptionsAreExplicit(t *testing.T) {
	major, yes, err := parseUpdateArgs([]string{"--major", "--yes"})
	if err != nil || !major || !yes {
		t.Fatalf("authorized options: major=%t yes=%t err=%v", major, yes, err)
	}
	major, yes, err = parseUpdateArgs([]string{"--major"})
	if err != nil || !major || yes {
		t.Fatalf("review options: major=%t yes=%t err=%v", major, yes, err)
	}
	for _, args := range [][]string{{"--yes"}, {"--force"}, {"--major", "--yes", "--skip-verification"}} {
		if _, _, err := parseUpdateArgs(args); err == nil {
			t.Fatalf("unsafe update options accepted: %q", args)
		}
	}
}

func TestMigrationJSONStreamsReviewBeforeTruthfulResult(t *testing.T) {
	review := update.MigrationReview{
		Current: "v1.4.4", Target: "v2.0.0", ReleaseNotes: "notes",
		Authorized: true, AuthorizationState: "authorized",
		RollbackGuidance: "rollback", Remediation: "remediate",
	}
	for _, test := range []struct {
		name string
		ok   bool
	}{
		{name: "success", ok: true},
		{name: "failure", ok: false},
	} {
		t.Run(test.name, func(t *testing.T) {
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
			prefix, err := os.ReadFile(output.Name())
			if err != nil {
				t.Fatal(err)
			}
			if json.Valid(prefix) || !bytes.Contains(prefix, []byte(`"authorization_state":"authorized"`)) || bytes.Contains(prefix, []byte(`"installed"`)) {
				t.Fatalf("pre-replacement prefix=%q", prefix)
			}

			failure := updateCommandFailure{}
			if !test.ok {
				failure = updateCommandFailure{Error: "update_failed", Message: "rename failed", Stage: "replace", Hint: "old executable preserved", Exit: 1}
			}
			if err := finish(test.ok, failure); err != nil {
				t.Fatal(err)
			}
			if err := output.Sync(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(output.Name())
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
			if document["ok"] != test.ok || document["installed"] != test.ok {
				t.Fatalf("result=%v", document)
			}
			if !test.ok && document["error"] != failure.Error {
				t.Fatalf("failure result=%v", document)
			}
		})
	}
}

func TestMachineErrorContractHasStableFields(t *testing.T) {
	value := machineErrorOutput{OK: false, Error: "alias_not_found", Message: "missing", Hint: "list aliases", Exit: 255, Stage: "lookup"}
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
	t.Setenv("HOME", t.TempDir())
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
