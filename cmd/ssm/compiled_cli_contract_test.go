package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"ssm/internal/config"
	securevault "ssm/internal/vault"
)

var compiledCLIPaths map[string]string

type compiledCLIResult struct {
	ProcessExit int
	Stdout      string
	Stderr      string
}

type compiledMachineContract struct {
	Name            string   `json:"name"`
	Command         string   `json:"command"`
	OK              bool     `json:"ok"`
	Error           string   `json:"error"`
	Stage           string   `json:"stage,omitempty"`
	JSONExit        int      `json:"json_exit"`
	ProcessExit     int      `json:"process_exit"`
	Hint            string   `json:"hint,omitempty"`
	Alias           string   `json:"alias,omitempty"`
	Candidates      []string `json:"candidates,omitempty"`
	Absent          []string `json:"absent,omitempty"`
	StdoutPlacement string   `json:"stdout_placement"`
	StderrPlacement string   `json:"stderr_placement"`
	Cardinality     string   `json:"cardinality"`
}

type compiledCLIHarness struct {
	home       string
	temp       string
	passphrase string
	passPath   string
	paths      map[string]string
}

func TestMain(m *testing.M) {
	buildDir, err := os.MkdirTemp("", "ssm-compiled-contracts-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create compiled CLI build directory: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(buildDir)
	compiledUpdateServer = newCompiledUpdateFixture()
	defer compiledUpdateServer.Close()

	extension := ""
	if filepath.Ext(os.Args[0]) == ".exe" {
		extension = ".exe"
	}
	ssmPath := filepath.Join(buildDir, "ssm"+extension)
	updateLDFlags := fmt.Sprintf(
		"-X=ssm/internal/update.apiBaseURL=%s -X=ssm/internal/update.downloadBaseURL=%s",
		compiledUpdateServer.URL(), compiledUpdateServer.URL(),
	)
	build := exec.Command("go", "build", "-ldflags", updateLDFlags, "-o", ssmPath, ".")
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		fmt.Fprintf(os.Stderr, "build compiled CLI: %v\n%s", buildErr, output)
		os.Exit(1)
	}
	sshctlPath := filepath.Join(buildDir, "sshctl"+extension)
	if linkErr := os.Link(ssmPath, sshctlPath); linkErr != nil {
		data, readErr := os.ReadFile(ssmPath)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "read compiled CLI for sshctl alias: %v\n", readErr)
			os.Exit(1)
		}
		info, statErr := os.Stat(ssmPath)
		if statErr != nil {
			fmt.Fprintf(os.Stderr, "stat compiled CLI for sshctl alias: %v\n", statErr)
			os.Exit(1)
		}
		if writeErr := os.WriteFile(sshctlPath, data, info.Mode()); writeErr != nil {
			fmt.Fprintf(os.Stderr, "write compiled CLI sshctl alias: %v\n", writeErr)
			os.Exit(1)
		}
	}
	compiledCLIPaths = map[string]string{"ssm": ssmPath, "sshctl": sshctlPath}

	os.Exit(m.Run())
}

func newCompiledCLIHarness(t *testing.T) *compiledCLIHarness {
	t.Helper()
	binDir := t.TempDir()
	paths := make(map[string]string, len(compiledCLIPaths))
	for executable, source := range compiledCLIPaths {
		destination := filepath.Join(binDir, filepath.Base(source))
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read test-built compiled CLI %s: %v", executable, err)
		}
		info, err := os.Stat(source)
		if err != nil {
			t.Fatalf("stat test-built compiled CLI %s: %v", executable, err)
		}
		if err := os.WriteFile(destination, data, info.Mode()); err != nil {
			t.Fatalf("copy test-built compiled CLI %s: %v", executable, err)
		}
		paths[executable] = destination
	}
	home := t.TempDir()
	configDir := filepath.Join(home, ".config", "ssm")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("create isolated compiled CLI config directory: %v", err)
	}
	passPath := filepath.Join(configDir, "master.pass")
	passphrase := "ISSUE17_MASTER_PASSPHRASE_CANARY"
	if err := os.WriteFile(passPath, []byte(passphrase+"\n"), 0o600); err != nil {
		t.Fatalf("write isolated compiled CLI master pass file: %v", err)
	}
	return &compiledCLIHarness{
		home:       home,
		temp:       t.TempDir(),
		passphrase: passphrase,
		passPath:   passPath,
		paths:      paths,
	}
}

func (h *compiledCLIHarness) Run(t *testing.T, executable string, stdin []byte, args ...string) compiledCLIResult {
	t.Helper()
	return h.run(t, executable, stdin, map[string]string{"SSM_MASTER_PASS_FILE": h.passPath}, args...)
}

func (h *compiledCLIHarness) RunWithoutMasterPass(t *testing.T, executable string, stdin []byte, args ...string) compiledCLIResult {
	t.Helper()
	return h.run(t, executable, stdin, nil, args...)
}

func (h *compiledCLIHarness) RunWithEnv(t *testing.T, executable string, stdin []byte, env map[string]string, args ...string) compiledCLIResult {
	t.Helper()
	overrides := make(map[string]string, len(env)+1)
	for key, value := range env {
		overrides[key] = value
	}
	if _, exists := overrides["SSM_MASTER_PASS_FILE"]; !exists {
		overrides["SSM_MASTER_PASS_FILE"] = h.passPath
	}
	return h.run(t, executable, stdin, overrides, args...)
}

func (h *compiledCLIHarness) run(t *testing.T, executable string, stdin []byte, env map[string]string, args ...string) compiledCLIResult {
	t.Helper()
	path, ok := h.paths[executable]
	if !ok {
		t.Fatalf("unknown compiled CLI executable name %q", executable)
	}
	cmd := exec.Command(path, args...) //nolint:gosec // executable is selected from test-owned fixed paths
	cmd.Env = isolatedCompiledCLIEnvironmentWith(h.home, h.temp, env)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	processExit := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run compiled %s: %v", executable, err)
		}
		processExit = exitErr.ExitCode()
	}
	return compiledCLIResult{
		ProcessExit: processExit,
		Stdout:      stdout.String(),
		Stderr:      stderr.String(),
	}
}

func (h *compiledCLIHarness) SaveVault(t *testing.T, value *config.Vault) {
	t.Helper()
	encrypted, err := config.EncryptVault(value, h.passphrase)
	if err != nil {
		t.Fatalf("encrypt isolated compiled CLI vault: %v", err)
	}
	path := filepath.Join(h.home, ".config", "ssm", "connections.enc")
	if err := os.WriteFile(path, encrypted, 0o600); err != nil {
		t.Fatalf("write isolated compiled CLI vault: %v", err)
	}
}

func isolatedCompiledCLIEnvironmentWith(home, temp string, overrides map[string]string) []string {
	blocked := map[string]bool{
		"HOME":                 true,
		"USERPROFILE":          true,
		"XDG_CONFIG_HOME":      true,
		"TMPDIR":               true,
		"TMP":                  true,
		"TEMP":                 true,
		"SSM_MASTER_PASS_FILE": true,
		"SSM_UPDATE_REPO":      true,
		"SSM_TRACE":            true,
		"SSM_TIMEOUT":          true,
		"SSM_DIAL_TIMEOUT":     true,
		"SSM_REUSE":            true,
		"SSM_FORWARD_STDIN":    true,
	}
	for key := range overrides {
		blocked[key] = true
	}
	env := make([]string, 0, len(os.Environ())+6+len(overrides))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !blocked[key] {
			env = append(env, entry)
		}
	}
	env = append(env,
		"HOME="+home,
		"USERPROFILE="+home,
		"TMPDIR="+temp,
		"TMP="+temp,
		"TEMP="+temp,
	)
	if _, overridden := overrides["SSM_UPDATE_REPO"]; !overridden {
		env = append(env, "SSM_UPDATE_REPO=off")
	}
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = append(env, key+"="+overrides[key])
	}
	return env
}

func assertCompiledMachineContract(t *testing.T, result compiledCLIResult, want compiledMachineContract) {
	t.Helper()
	if result.ProcessExit != want.ProcessExit {
		t.Fatalf("process exit = %d, want %d; output=%s", result.ProcessExit, want.ProcessExit, compiledOutputIdentity(result))
	}
	if result.Stderr != "" {
		t.Fatalf("machine stderr bytes = %d, want 0; output=%s", len(result.Stderr), compiledOutputIdentity(result))
	}
	value := decodeExactlyOneJSONObject(t, result.Stdout)
	if want.Cardinality == "one_line" && len(nonEmptyCompiledLines(result.Stdout)) != 1 {
		t.Fatalf("stdout line cardinality is not exactly one; output=%s", compiledOutputIdentity(result))
	}
	if got, ok := value["ok"].(bool); !ok || got != want.OK {
		t.Fatalf("ok = %v, want %t; output=%s", value["ok"], want.OK, compiledOutputIdentity(result))
	}
	assertCompiledStringField(t, value, "error", want.Error, result)
	if want.Stage != "" {
		assertCompiledStringField(t, value, "stage", want.Stage, result)
	}
	if want.Hint != "" {
		assertCompiledStringField(t, value, "hint", want.Hint, result)
	}
	if want.Alias != "" {
		assertCompiledStringField(t, value, "alias", want.Alias, result)
	}
	if want.Candidates != nil {
		raw, ok := value["candidates"].([]any)
		if !ok {
			t.Fatalf("candidates has unexpected type; output=%s", compiledOutputIdentity(result))
		}
		got := make([]string, len(raw))
		for i, candidate := range raw {
			got[i], ok = candidate.(string)
			if !ok {
				t.Fatalf("candidate %d has unexpected type; output=%s", i, compiledOutputIdentity(result))
			}
		}
		if !reflect.DeepEqual(got, want.Candidates) {
			t.Fatalf("candidates = %v, want %v; output=%s", got, want.Candidates, compiledOutputIdentity(result))
		}
	}
	if got, ok := value["exit"].(float64); !ok || int(got) != want.JSONExit {
		t.Fatalf("JSON exit = %v, want %d; output=%s", value["exit"], want.JSONExit, compiledOutputIdentity(result))
	}
	for _, field := range want.Absent {
		if _, ok := value[field]; ok {
			t.Fatalf("field %q unexpectedly present; output=%s", field, compiledOutputIdentity(result))
		}
	}
}

func reviewedCompiledMachineContracts(t *testing.T) map[string]compiledMachineContract {
	t.Helper()
	path := filepath.Join("testdata", "compiled_contracts", "v1_failure_matrix.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read reviewed compiled CLI contract matrix: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var rows []compiledMachineContract
	if err := decoder.Decode(&rows); err != nil {
		t.Fatalf("decode reviewed compiled CLI contract matrix: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("reviewed compiled CLI contract matrix contains trailing data")
	}
	contracts := make(map[string]compiledMachineContract, len(rows))
	for _, row := range rows {
		if row.Name == "" {
			t.Fatal("reviewed compiled CLI contract matrix contains an unnamed row")
		}
		if row.Command == "" || row.StdoutPlacement != "stdout" || row.StderrPlacement != "empty" ||
			(row.Cardinality != "one_value" && row.Cardinality != "one_line") {
			t.Fatalf("reviewed compiled CLI contract %q has incomplete tuple metadata", row.Name)
		}
		if _, duplicate := contracts[row.Name]; duplicate {
			t.Fatalf("reviewed compiled CLI contract matrix duplicates safe name %q", row.Name)
		}
		contracts[row.Name] = row
	}
	return contracts
}

func reviewedCompiledMachineContract(t *testing.T, name string) compiledMachineContract {
	t.Helper()
	contract, ok := reviewedCompiledMachineContracts(t)[name]
	if !ok {
		t.Fatalf("reviewed compiled CLI contract %q is missing", name)
	}
	return contract
}

func assertCompiledStringField(t *testing.T, value map[string]any, field, want string, result compiledCLIResult) {
	t.Helper()
	got, ok := value[field].(string)
	if !ok || got != want {
		t.Fatalf("%s = %q, want %q; output=%s", field, got, want, compiledOutputIdentity(result))
	}
}

func decodeExactlyOneJSONObject(t *testing.T, stdout string) map[string]any {
	t.Helper()
	value := decodeExactlyOneJSONValue(t, stdout)
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("stdout JSON value is not an object; bytes=%d sha256=%x", len(stdout), sha256.Sum256([]byte(stdout)))
	}
	return object
}

func decodeExactlyOneJSONValue(t *testing.T, stdout string) any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(stdout))
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode stdout JSON: %v; bytes=%d sha256=%x", err, len(stdout), sha256.Sum256([]byte(stdout)))
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("stdout cardinality is not exactly one JSON value; bytes=%d sha256=%x", len(stdout), sha256.Sum256([]byte(stdout)))
	}
	return value
}

func assertCompiledHelpContract(t *testing.T, result compiledCLIResult, executable string) {
	t.Helper()
	if result.ProcessExit != 0 || result.Stderr != "" || !strings.Contains(result.Stdout, "Usage:") || !strings.Contains(result.Stdout, executable) {
		t.Fatalf("compiled %s help contract failed; output=%s", executable, compiledOutputIdentity(result))
	}
}

func assertCompiledJSONSuccess(t *testing.T, result compiledCLIResult) map[string]any {
	t.Helper()
	if result.ProcessExit != 0 || result.Stderr != "" {
		t.Fatalf("compiled JSON success process contract failed; output=%s", compiledOutputIdentity(result))
	}
	value := decodeExactlyOneJSONObject(t, result.Stdout)
	if got, ok := value["ok"].(bool); !ok || !got {
		t.Fatalf("ok = %v, want true; output=%s", value["ok"], compiledOutputIdentity(result))
	}
	return value
}

func assertCompiledJSONArraySuccess(t *testing.T, result compiledCLIResult, wantLength int) []any {
	t.Helper()
	if result.ProcessExit != 0 || result.Stderr != "" {
		t.Fatalf("compiled JSON array success process contract failed; output=%s", compiledOutputIdentity(result))
	}
	value := decodeExactlyOneJSONValue(t, result.Stdout)
	items, ok := value.([]any)
	if !ok || len(items) != wantLength {
		t.Fatalf("JSON array length = %d, want %d; output=%s", len(items), wantLength, compiledOutputIdentity(result))
	}
	return items
}

func assertCompiledHumanSuccess(t *testing.T, result compiledCLIResult, safeText string) {
	t.Helper()
	if result.ProcessExit != 0 || result.Stderr != "" || !strings.Contains(result.Stdout, safeText) {
		t.Fatalf("compiled human success contract failed; output=%s", compiledOutputIdentity(result))
	}
}

func nonEmptyCompiledLines(value string) []string {
	raw := strings.Split(strings.TrimSpace(value), "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func assertCompiledNDJSONResults(t *testing.T, result compiledCLIResult, wantLines int, wantOK bool) []map[string]any {
	t.Helper()
	if result.ProcessExit != 0 || result.Stderr != "" {
		t.Fatalf("compiled NDJSON process contract failed; output=%s", compiledOutputIdentity(result))
	}
	lines := nonEmptyCompiledLines(result.Stdout)
	if len(lines) != wantLines {
		t.Fatalf("NDJSON line count = %d, want %d; output=%s", len(lines), wantLines, compiledOutputIdentity(result))
	}
	values := make([]map[string]any, len(lines))
	for i, line := range lines {
		if err := json.Unmarshal([]byte(line), &values[i]); err != nil {
			t.Fatalf("decode NDJSON line %d: %v; output=%s", i, err, compiledOutputIdentity(result))
		}
		if got, ok := values[i]["ok"].(bool); !ok || got != wantOK {
			t.Fatalf("NDJSON line %d ok = %v, want %t; output=%s", i, values[i]["ok"], wantOK, compiledOutputIdentity(result))
		}
	}
	return values
}

type compiledPutContract struct {
	Integrity string
	Atomic    bool
	Resume    string
	BytesSent int
	Present   []string
	Absent    []string
}

func assertCompiledPutContract(t *testing.T, result compiledCLIResult, want compiledPutContract) map[string]any {
	t.Helper()
	value := assertCompiledJSONSuccess(t, result)
	assertCompiledStringField(t, value, "action", "put", result)
	assertCompiledStringField(t, value, "stage", "complete", result)
	assertCompiledStringField(t, value, "integrity", want.Integrity, result)
	assertCompiledStringField(t, value, "resume", want.Resume, result)
	if got, ok := value["atomic"].(bool); !ok || got != want.Atomic {
		t.Fatalf("atomic = %v, want %t; output=%s", value["atomic"], want.Atomic, compiledOutputIdentity(result))
	}
	if got, ok := value["bytes_sent"].(float64); !ok || int(got) != want.BytesSent {
		t.Fatalf("bytes_sent = %v, want %d; output=%s", value["bytes_sent"], want.BytesSent, compiledOutputIdentity(result))
	}
	for _, field := range want.Present {
		if _, ok := value[field]; !ok {
			t.Fatalf("field %q unexpectedly absent; output=%s", field, compiledOutputIdentity(result))
		}
	}
	for _, field := range want.Absent {
		if _, ok := value[field]; ok {
			t.Fatalf("field %q unexpectedly present; output=%s", field, compiledOutputIdentity(result))
		}
	}
	return value
}

func assertCompiledGetContract(t *testing.T, result compiledCLIResult) map[string]any {
	t.Helper()
	value := assertCompiledJSONSuccess(t, result)
	assertCompiledStringField(t, value, "action", "get", result)
	for _, field := range []string{"direction", "kind", "stage", "bytes_sent", "integrity", "atomic", "resume", "local_sha256", "remote_sha256", "bytes_reused"} {
		if _, ok := value[field]; ok {
			t.Fatalf("get field %q unexpectedly present; output=%s", field, compiledOutputIdentity(result))
		}
	}
	return value
}

func assertCompiledFileDigest(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replaced compiled CLI fixture: %v", err)
	}
	gotDigest := sha256.Sum256(got)
	wantDigest := sha256.Sum256(want)
	if gotDigest != wantDigest {
		t.Fatalf("compiled CLI replacement digest = %x, want %x", gotDigest, wantDigest)
	}
}

func assertCompiledUpdateRequests(t *testing.T, got []string, version string) {
	t.Helper()
	asset := fmt.Sprintf("ssm-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		asset += ".exe"
	}
	want := []string{
		"/repos/fixture/repo/releases/latest",
		"/fixture/repo/releases/download/" + version + "/checksums.txt",
		"/fixture/repo/releases/download/" + version + "/" + asset,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("update request count = %d, want %d", len(got), len(want))
	}
}

func compiledTransactionID(t *testing.T, value map[string]any, result compiledCLIResult) string {
	t.Helper()
	id, ok := value["transaction_id"].(string)
	if !ok || len(id) != len("tx_")+32 || !strings.HasPrefix(id, "tx_") {
		t.Fatalf("transaction ID shape is invalid; output=%s", compiledOutputIdentity(result))
	}
	for _, char := range id[len("tx_"):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			t.Fatalf("transaction ID shape is invalid; output=%s", compiledOutputIdentity(result))
		}
	}
	return id
}

func compiledPendingTransactionIDs(t *testing.T, value map[string]any, result compiledCLIResult) []string {
	t.Helper()
	raw, ok := value["pending_mutations"].([]any)
	if !ok {
		t.Fatalf("pending_mutations has unexpected type; output=%s", compiledOutputIdentity(result))
	}
	ids := make([]string, len(raw))
	for i, item := range raw {
		mutation, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("pending mutation %d has unexpected type; output=%s", i, compiledOutputIdentity(result))
		}
		ids[i], ok = mutation["id"].(string)
		if !ok {
			t.Fatalf("pending mutation %d ID has unexpected type; output=%s", i, compiledOutputIdentity(result))
		}
	}
	return ids
}

type compiledVaultSummary struct {
	Aliases      []string
	KeyNames     []string
	Transactions []string
}

func decodeCompiledVaultSummary(t *testing.T, encrypted []byte, passphrase string) compiledVaultSummary {
	t.Helper()
	plaintext, err := securevault.Decrypt(encrypted, passphrase)
	if err != nil {
		t.Fatalf("decrypt compiled CLI fixture blob: %v; encrypted_bytes=%d sha256=%x", err, len(encrypted), sha256.Sum256(encrypted))
	}
	var value config.Vault
	if err := json.Unmarshal(plaintext, &value); err != nil {
		t.Fatalf("decode compiled CLI fixture vault: %v; encrypted_bytes=%d sha256=%x", err, len(encrypted), sha256.Sum256(encrypted))
	}
	summary := compiledVaultSummary{}
	for _, connection := range value.Connections {
		summary.Aliases = append(summary.Aliases, connection.Name)
	}
	for _, key := range value.Keys {
		summary.KeyNames = append(summary.KeyNames, key.Name)
	}
	for _, transaction := range value.PendingMutations {
		summary.Transactions = append(summary.Transactions, transaction.ID)
	}
	sort.Strings(summary.Aliases)
	sort.Strings(summary.KeyNames)
	sort.Strings(summary.Transactions)
	return summary
}

func (h *compiledCLIHarness) LoadVaultSummary(t *testing.T) compiledVaultSummary {
	t.Helper()
	path := filepath.Join(h.home, ".config", "ssm", "connections.enc")
	encrypted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read compiled CLI fixture vault: %v", err)
	}
	return decodeCompiledVaultSummary(t, encrypted, h.passphrase)
}

func assertCompiledVaultSummary(t *testing.T, got compiledVaultSummary, aliases, keyNames, transactions []string) {
	t.Helper()
	aliases = append([]string(nil), aliases...)
	keyNames = append([]string(nil), keyNames...)
	transactions = append([]string(nil), transactions...)
	sort.Strings(aliases)
	sort.Strings(keyNames)
	sort.Strings(transactions)
	if !equalCompiledStrings(got.Aliases, aliases) ||
		!equalCompiledStrings(got.KeyNames, keyNames) ||
		!equalCompiledStrings(got.Transactions, transactions) {
		t.Fatalf(
			"vault safe summary counts aliases=%d keys=%d transactions=%d, want aliases=%d keys=%d transactions=%d",
			len(got.Aliases), len(got.KeyNames), len(got.Transactions), len(aliases), len(keyNames), len(transactions),
		)
	}
}

func equalCompiledStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func assertNoCompiledCanaryLeak(t *testing.T, result compiledCLIResult, canaries map[string]string) {
	t.Helper()
	output := result.Stdout + result.Stderr
	for label, canary := range canaries {
		if canary != "" && strings.Contains(output, canary) {
			t.Fatalf("compiled CLI output leaked canary %q; output=%s", label, compiledOutputIdentity(result))
		}
	}
}

func compiledOutputIdentity(result compiledCLIResult) string {
	stdoutDigest := sha256.Sum256([]byte(result.Stdout))
	stderrDigest := sha256.Sum256([]byte(result.Stderr))
	return fmt.Sprintf("stdout_bytes=%d stdout_sha256=%x stderr_bytes=%d stderr_sha256=%x", len(result.Stdout), stdoutDigest, len(result.Stderr), stderrDigest)
}

func TestCompiledCLIContractMatrix(t *testing.T) {
	reviewed := reviewedCompiledMachineContracts(t)
	reviewedNames := []string{
		"unknown_sshctl", "unknown_ssm", "invalid_request_unknown_field", "unlock_file_required",
		"exact_alias_miss", "sync_etag_conflict", "transfer_local_read", "host_key_unknown",
		"dial_refused", "auth_failed", "session_failed", "remote_exit_255", "stream_refresh_failed",
	}
	if len(reviewed) != len(reviewedNames) {
		t.Fatalf("reviewed compiled CLI matrix rows = %d, want %d", len(reviewed), len(reviewedNames))
	}
	for _, name := range reviewedNames {
		if _, ok := reviewed[name]; !ok {
			t.Fatalf("reviewed compiled CLI matrix is missing safe row %q", name)
		}
	}

	cli := newCompiledCLIHarness(t)
	for _, test := range []struct {
		name         string
		executable   string
		contractName string
	}{
		{
			name:         "sshctl dispatch",
			executable:   "sshctl",
			contractName: "unknown_sshctl",
		},
		{
			name:         "ssm dispatch",
			executable:   "ssm",
			contractName: "unknown_ssm",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := cli.Run(t, test.executable, nil, "--json", "not-a-command")
			assertCompiledMachineContract(t, result, reviewedCompiledMachineContract(t, test.contractName))
		})
	}

	t.Run("strict request schema rejects unknown fields", func(t *testing.T) {
		requestCanary := "ISSUE17_REQUEST_BODY_CANARY"
		result := cli.Run(t, "sshctl", []byte(`{"version":1,"op":"run","alias":"prod","argv":["true"],"unexpected":"`+requestCanary+`"}`), "request", "-")
		assertNoCompiledCanaryLeak(t, result, map[string]string{"request_body": requestCanary})
		assertCompiledMachineContract(t, result, reviewedCompiledMachineContract(t, "invalid_request_unknown_field"))
	})

	t.Run("missing non-interactive unlock file", func(t *testing.T) {
		result := cli.RunWithoutMasterPass(t, "ssm", nil, "--json", "list")
		assertCompiledMachineContract(t, result, reviewedCompiledMachineContract(t, "unlock_file_required"))
	})

	t.Run("exact alias miss returns candidates without selecting", func(t *testing.T) {
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{
			{Name: "prod-one", Host: "192.0.2.10", Port: 22, User: "runner", Password: "ISSUE17_PASSWORD_CANARY"},
			{Name: "prod-two", Host: "192.0.2.11", Port: 22, User: "runner", Password: "ISSUE17_SECOND_PASSWORD_CANARY"},
		}})
		result := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "prod", "--argv", "true")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"password_one": "ISSUE17_PASSWORD_CANARY",
			"password_two": "ISSUE17_SECOND_PASSWORD_CANARY",
		})
		assertCompiledMachineContract(t, result, reviewedCompiledMachineContract(t, "exact_alias_miss"))
	})

	t.Run("two-sided ETag conflict preserves classified sync failure", func(t *testing.T) {
		sync := newCompiledSyncFixture(t)
		sync.SetRemote(t, []byte("opaque-remote-blob"), "remote-changed")
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{
			Name: "cached", Host: "192.0.2.20", Port: 22, User: "runner", Password: "ISSUE17_SYNC_PASSWORD_CANARY",
		}}})
		cli.SaveCloud(t, sync.URL(), "ISSUE17_SYNC_TOKEN_CANARY")
		cli.SaveRemoteETag(t, "cached-baseline")

		result := cli.Run(t, "sshctl", nil, "--json", "list")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"password": "ISSUE17_SYNC_PASSWORD_CANARY",
			"token":    "ISSUE17_SYNC_TOKEN_CANARY",
		})
		assertCompiledMachineContract(t, result, reviewedCompiledMachineContract(t, "sync_etag_conflict"))
		if got := sync.MethodCount("GET"); got != 0 {
			t.Fatalf("sync GET count = %d, want 0 after conflict preflight", got)
		}
	})

	t.Run("transfer preparation failure keeps the public transfer envelope", func(t *testing.T) {
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{
			Name: "transfer", Host: "192.0.2.30", Port: 22, User: "runner", Password: "ISSUE17_TRANSFER_PASSWORD_CANARY",
		}}})
		missing := filepath.Join(cli.home, "missing-artifact")
		result := cli.Run(t, "sshctl", nil, "--offline", "--json", "put", "transfer", missing, "/srv/artifact")
		assertNoCompiledCanaryLeak(t, result, map[string]string{"password": "ISSUE17_TRANSFER_PASSWORD_CANARY"})
		assertCompiledMachineContract(t, result, reviewedCompiledMachineContract(t, "transfer_local_read"))
	})

	t.Run("host key is inspected and accepted only by exact fingerprint", func(t *testing.T) {
		password := "ISSUE17_HOST_KEY_PASSWORD_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("host-key", password)}})

		unknown := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "host-key", "--argv", "true")
		assertNoCompiledCanaryLeak(t, unknown, map[string]string{"password": password})
		assertCompiledMachineContract(t, unknown, reviewedCompiledMachineContract(t, "host_key_unknown"))

		inspection := cli.Run(t, "sshctl", nil, "--offline", "--json", "host-key", "inspect", "host-key")
		inspectionValue := assertCompiledJSONSuccess(t, inspection)
		assertCompiledStringField(t, inspectionValue, "status", "new", inspection)
		fingerprint, ok := inspectionValue["observed_fingerprint"].(string)
		if !ok || !strings.HasPrefix(fingerprint, "SHA256:") {
			t.Fatalf("inspection fingerprint contract failed; output=%s", compiledOutputIdentity(inspection))
		}

		accepted := cli.Run(t, "sshctl", nil, "--offline", "--json", "host-key", "accept", "host-key", "--fingerprint", fingerprint, "--yes")
		acceptedValue := assertCompiledJSONSuccess(t, accepted)
		assertCompiledStringField(t, acceptedValue, "status", "trusted", accepted)
		if value, ok := acceptedValue["accepted"].(bool); !ok || !value {
			t.Fatalf("accepted = %v, want true; output=%s", acceptedValue["accepted"], compiledOutputIdentity(accepted))
		}
	})

	t.Run("dial refusal is distinct from remote exit", func(t *testing.T) {
		host, port := closedCompiledTCPPort(t)
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{
			Name: "refused", Host: host, Port: port, User: "runner", Password: "ISSUE17_DIAL_PASSWORD_CANARY",
		}}})
		result := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "refused", "--argv", "true")
		assertNoCompiledCanaryLeak(t, result, map[string]string{"password": "ISSUE17_DIAL_PASSWORD_CANARY"})
		assertCompiledMachineContract(t, result, reviewedCompiledMachineContract(t, "dial_refused"))
	})

	t.Run("authentication failure remains classified at dial stage", func(t *testing.T) {
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: "ISSUE17_EXPECTED_AUTH_CANARY"})
		cli.TrustSSHHost(t, server)
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{
			server.Connection("auth", "ISSUE17_REJECTED_AUTH_CANARY"),
		}})
		result := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "auth", "--argv", "true")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"expected_password": "ISSUE17_EXPECTED_AUTH_CANARY",
			"rejected_password": "ISSUE17_REJECTED_AUTH_CANARY",
		})
		assertCompiledMachineContract(t, result, reviewedCompiledMachineContract(t, "auth_failed"))
	})

	t.Run("session failure retains its own class", func(t *testing.T) {
		password := "ISSUE17_SESSION_PASSWORD_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password, RejectSessions: true})
		cli.TrustSSHHost(t, server)
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("session", password)}})
		result := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "session", "--argv", "true")
		assertNoCompiledCanaryLeak(t, result, map[string]string{"password": password})
		assertCompiledMachineContract(t, result, reviewedCompiledMachineContract(t, "session_failed"))
	})

	t.Run("remote process exit 255 is not a connection failure", func(t *testing.T) {
		password := "ISSUE17_REMOTE_EXIT_PASSWORD_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
		cli.TrustSSHHost(t, server)
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("remote-255", password)}})
		result := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "remote-255", "--argv", "sh", "-c", "exit 255")
		assertNoCompiledCanaryLeak(t, result, map[string]string{"password": password})
		assertCompiledMachineContract(t, result, reviewedCompiledMachineContract(t, "remote_exit_255"))
	})

	t.Run("stream decode preserves one compact result per non-empty line", func(t *testing.T) {
		streamCLI := newCompiledCLIHarness(t)
		password := "ISSUE17_STREAM_DECODE_PASSWORD_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
		streamCLI.TrustSSHHost(t, server)
		streamCLI.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("stream", password)}})
		result := streamCLI.Run(t, "sshctl", []byte("\n{bad}\n[\"true\"]\n"), "--offline", "--json", "run", "stream", "--stream", "--refresh=0")
		assertNoCompiledCanaryLeak(t, result, map[string]string{"password": password})
		if result.ProcessExit != 2 || result.Stderr != "" {
			t.Fatalf("stream decode process contract failed; output=%s", compiledOutputIdentity(result))
		}
		lines := nonEmptyCompiledLines(result.Stdout)
		if len(lines) != 2 {
			t.Fatalf("stream decode line count = %d, want 2; output=%s", len(lines), compiledOutputIdentity(result))
		}
		var invalid map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &invalid); err != nil {
			t.Fatalf("decode stream error line: %v; output=%s", err, compiledOutputIdentity(result))
		}
		assertCompiledStringField(t, invalid, "error", "invalid_request", result)
		assertCompiledStringField(t, invalid, "stage", "decode", result)
		if got := int(invalid["exit"].(float64)); got != 2 {
			t.Fatalf("stream decode JSON exit = %d, want 2; output=%s", got, compiledOutputIdentity(result))
		}
		var success map[string]any
		if err := json.Unmarshal([]byte(lines[1]), &success); err != nil {
			t.Fatalf("decode stream success line: %v; output=%s", err, compiledOutputIdentity(result))
		}
		if got, ok := success["ok"].(bool); !ok || !got {
			t.Fatalf("stream success ok = %v, want true; output=%s", success["ok"], compiledOutputIdentity(result))
		}
	})

	t.Run("stream refresh failure is the triggering line's only terminal result", func(t *testing.T) {
		streamCLI := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		sync.SetRemote(t, []byte("unused-opaque-blob"), "stream-current")
		sync.SetStatusAfter(t, "HEAD", 1, 500)
		streamCLI.SaveVault(t, &config.Vault{})
		streamCLI.SaveCloud(t, sync.URL(), "ISSUE17_STREAM_REFRESH_TOKEN_CANARY")
		streamCLI.SaveRemoteETag(t, "stream-current")
		result := streamCLI.Run(t, "sshctl", []byte("[\"true\"]\n[\"true\"]\n"), "--json", "run", "unused", "--stream", "--refresh=1ns")
		assertNoCompiledCanaryLeak(t, result, map[string]string{"token": "ISSUE17_STREAM_REFRESH_TOKEN_CANARY"})
		assertCompiledMachineContract(t, result, reviewedCompiledMachineContract(t, "stream_refresh_failed"))
		if lines := nonEmptyCompiledLines(result.Stdout); len(lines) != 1 {
			t.Fatalf("stream refresh line count = %d, want 1; output=%s", len(lines), compiledOutputIdentity(result))
		}
		if got := sync.MethodCount("HEAD"); got != 2 {
			t.Fatalf("stream refresh HEAD count = %d, want 2", got)
		}
	})

	t.Run("compiled mutation IDs remain stable and scoped push stays isolated", func(t *testing.T) {
		mutationCLI := newCompiledCLIHarness(t)
		mutationCLI.SaveVault(t, &config.Vault{})
		alphaPassword := filepath.Join(mutationCLI.temp, "alpha.password")
		betaPassword := filepath.Join(mutationCLI.temp, "beta.password")
		if err := os.WriteFile(alphaPassword, []byte("ISSUE17_ALPHA_PASSWORD_CANARY\n"), 0o600); err != nil {
			t.Fatalf("write alpha password fixture: %v", err)
		}
		if err := os.WriteFile(betaPassword, []byte("ISSUE17_BETA_PASSWORD_CANARY\n"), 0o600); err != nil {
			t.Fatalf("write beta password fixture: %v", err)
		}
		alpha := mutationCLI.Run(t, "sshctl", nil, "--json", "host", "add", "alpha", "--host", "192.0.2.70", "--user", "runner", "--password-file", alphaPassword, "--offline")
		alphaValue := assertCompiledJSONSuccess(t, alpha)
		alphaID := compiledTransactionID(t, alphaValue, alpha)
		beta := mutationCLI.Run(t, "sshctl", nil, "--json", "host", "add", "beta", "--host", "192.0.2.71", "--user", "runner", "--password-file", betaPassword, "--offline")
		betaValue := assertCompiledJSONSuccess(t, beta)
		betaID := compiledTransactionID(t, betaValue, beta)
		if alphaID == betaID {
			t.Fatal("compiled host mutations reused a transaction ID")
		}

		for i := 0; i < 2; i++ {
			status := mutationCLI.Run(t, "sshctl", nil, "--offline", "--json", "status")
			value := assertCompiledJSONSuccess(t, status)
			if got := compiledPendingTransactionIDs(t, value, status); !reflect.DeepEqual(got, []string{alphaID, betaID}) {
				t.Fatalf("pending transaction count = %d, want 2 stable IDs", len(got))
			}
		}

		sync := newCompiledSyncFixture(t)
		sync.SetRemote(t, nil, "scoped-push")
		mutationCLI.SaveCloud(t, sync.URL(), "ISSUE17_SCOPED_PUSH_TOKEN_CANARY")
		pushed := mutationCLI.Run(t, "sshctl", nil, "--json", "push", "--only", betaID)
		pushedValue := assertCompiledJSONSuccess(t, pushed)
		assertCompiledStringField(t, pushedValue, "transaction_id", betaID, pushed)
		assertNoCompiledCanaryLeak(t, pushed, map[string]string{
			"alpha_password": "ISSUE17_ALPHA_PASSWORD_CANARY",
			"beta_password":  "ISSUE17_BETA_PASSWORD_CANARY",
			"token":          "ISSUE17_SCOPED_PUSH_TOKEN_CANARY",
		})
		assertCompiledVaultSummary(t, decodeCompiledVaultSummary(t, sync.UploadedBlob(), mutationCLI.passphrase), []string{"beta"}, nil, nil)
		assertCompiledVaultSummary(t, mutationCLI.LoadVaultSummary(t), []string{"alpha", "beta"}, nil, []string{alphaID})
	})
}

func TestApprovedV2BreakingChangeBaselines(t *testing.T) {
	t.Run("compiled help is non-interactive for both names", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		assertCompiledHelpContract(t, cli.Run(t, "ssm", nil, "--help"), "ssm")
		assertCompiledHelpContract(t, cli.Run(t, "sshctl", nil, "--help"), "sshctl")
	})

	t.Run("BC-1 malformed and unreadable cloud configuration differs by command family", func(t *testing.T) {
		for _, variant := range []string{"malformed", "unreadable"} {
			t.Run(variant, func(t *testing.T) {
				cli := newCompiledCLIHarness(t)
				cli.SaveVault(t, &config.Vault{})
				if variant == "malformed" {
					cli.writeConfigFile(t, "cloud.json", []byte(`{"server":"https://sync.invalid","token":"ISSUE17_CONFIG_TOKEN_CANARY"`))
				} else {
					path := filepath.Join(cli.home, ".config", "ssm", "cloud.json")
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatalf("create unreadable cloud configuration fixture: %v", err)
					}
				}

				generic := cli.Run(t, "sshctl", nil, "--json", "list")
				assertCompiledJSONArraySuccess(t, generic, 0)
				assertNoCompiledCanaryLeak(t, generic, map[string]string{
					"cloud_token":    "ISSUE17_CONFIG_TOKEN_CANARY",
					"config_content": "sync.invalid",
				})

				host := cli.Run(t, "sshctl", nil, "--json", "host", "list")
				assertNoCompiledCanaryLeak(t, host, map[string]string{
					"cloud_token":    "ISSUE17_CONFIG_TOKEN_CANARY",
					"config_content": "sync.invalid",
				})
				assertCompiledMachineContract(t, host, compiledMachineContract{
					OK: false, Error: "sync_pull_failed", Stage: "sync_pull", JSONExit: 1, ProcessExit: 1,
					Hint:   "fix sync connectivity or retry explicitly with --offline",
					Absent: []string{"alias", "candidates"},
				})

				offline := cli.Run(t, "sshctl", nil, "--json", "host", "list", "--offline")
				assertCompiledJSONArraySuccess(t, offline, 0)
			})
		}
	})

	t.Run("BC-2 cross-alias saved-key publication is currently permitted", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		sync.SetRemote(t, nil, "bc2-upload")
		keyCanary := "ISSUE17_CROSS_ALIAS_PRIVATE_KEY_CANARY"
		key := config.SSHKey{Name: "shared-key", PrivateKey: keyCanary}
		alpha := config.Connection{Name: "alpha", Host: "192.0.2.40", Port: 22, User: "runner", KeyName: key.Name}
		beta := config.Connection{Name: "beta", Host: "192.0.2.41", Port: 22, User: "runner", KeyName: key.Name}
		cli.SaveVault(t, &config.Vault{
			Connections: []config.Connection{alpha, beta},
			Keys:        []config.SSHKey{key},
			PendingBase: &config.InventorySnapshot{},
			PendingMutations: []config.PendingMutation{
				{ID: "tx_alpha", Alias: alpha.Name, Operation: "created", CreatedAt: "2026-01-01T00:00:00Z", After: &alpha, KeysAfter: []config.SSHKey{key}},
				{ID: "tx_beta", Alias: beta.Name, Operation: "created", CreatedAt: "2026-01-01T00:00:01Z", After: &beta, KeysBefore: []config.SSHKey{key}, KeysAfter: []config.SSHKey{key}},
			},
		})
		cli.SaveCloud(t, sync.URL(), "ISSUE17_BC2_TOKEN_CANARY")

		result := cli.Run(t, "sshctl", nil, "--json", "push", "--only", "tx_beta")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"private_key":         keyCanary,
			"token":               "ISSUE17_BC2_TOKEN_CANARY",
			"passphrase":          cli.passphrase,
			"passphrase_fragment": "MASTER_PASSPHRASE",
		})
		value := assertCompiledJSONSuccess(t, result)
		assertCompiledStringField(t, value, "scope", "only", result)
		assertCompiledStringField(t, value, "transaction_id", "tx_beta", result)
		if got := sync.MethodCount("PUT"); got != 1 {
			t.Fatalf("sync PUT count = %d, want 1", got)
		}
		published := decodeCompiledVaultSummary(t, sync.UploadedBlob(), cli.passphrase)
		assertCompiledVaultSummary(t, published, []string{"beta"}, nil, nil)
		local := cli.LoadVaultSummary(t)
		assertCompiledVaultSummary(t, local, []string{"alpha", "beta"}, []string{"shared-key"}, []string{"tx_alpha"})

		sameAliasCLI := newCompiledCLIHarness(t)
		sameAliasSync := newCompiledSyncFixture(t)
		first := config.Connection{Name: "same", Host: "192.0.2.42", Port: 22, User: "runner", Password: "ISSUE17_SAME_ALIAS_FIRST_CANARY"}
		second := first
		second.Host = "192.0.2.43"
		sameAliasCLI.SaveVault(t, &config.Vault{
			Connections: []config.Connection{second},
			PendingBase: &config.InventorySnapshot{},
			PendingMutations: []config.PendingMutation{
				{ID: "tx_same_first", Alias: "same", Operation: "created", CreatedAt: "2026-01-01T00:00:00Z", After: &first},
				{ID: "tx_same_second", Alias: "same", Operation: "updated", CreatedAt: "2026-01-01T00:00:01Z", Before: &first, After: &second},
			},
		})
		sameAliasCLI.SaveCloud(t, sameAliasSync.URL(), "ISSUE17_SAME_ALIAS_TOKEN_CANARY")
		rejected := sameAliasCLI.Run(t, "sshctl", nil, "--json", "push", "--only", "tx_same_second")
		assertNoCompiledCanaryLeak(t, rejected, map[string]string{
			"first_password": first.Password,
			"token":          "ISSUE17_SAME_ALIAS_TOKEN_CANARY",
		})
		assertCompiledMachineContract(t, rejected, compiledMachineContract{
			OK: false, Error: "sync_push_failed", JSONExit: 1, ProcessExit: 1,
			Hint:   "local vault remains pending; fix sync and retry push",
			Absent: []string{"stage", "alias", "candidates"},
		})
		if got := sameAliasSync.MethodCount("PUT"); got != 0 {
			t.Fatalf("same-alias rejected push PUT count = %d, want 0", got)
		}
	})

	t.Run("BC-3 stream startup failure is ordinary indented JSON", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		sync.SetStatus(t, "HEAD", 500)
		cli.SaveVault(t, &config.Vault{})
		cli.SaveCloud(t, sync.URL(), "ISSUE17_STREAM_TOKEN_CANARY")
		inputCanary := "ISSUE17_STREAM_INPUT_CANARY"
		result := cli.Run(t, "sshctl", []byte(inputCanary+"\n"), "--json", "run", "missing", "--stream", "--refresh=0")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"token":               "ISSUE17_STREAM_TOKEN_CANARY",
			"input":               inputCanary,
			"passphrase":          cli.passphrase,
			"passphrase_fragment": "MASTER_PASSPHRASE",
		})
		assertCompiledMachineContract(t, result, compiledMachineContract{
			OK: false, Error: "sync_pull_failed", Stage: "sync_pull", JSONExit: 1, ProcessExit: 1,
			Hint:   "fix sync connectivity or retry explicitly with --offline",
			Absent: []string{"alias", "candidates"},
		})
		if lines := nonEmptyCompiledLines(result.Stdout); len(lines) <= 1 {
			t.Fatalf("startup failure lines = %d, want indented multi-line JSON; output=%s", len(lines), compiledOutputIdentity(result))
		}
	})

	t.Run("BC-4 legacy mutations persist directly with their current publication effects", func(t *testing.T) {
		t.Run("legacy remove auto-pushes without a transaction", func(t *testing.T) {
			cli := newCompiledCLIHarness(t)
			sync := newCompiledSyncFixture(t)
			sync.SetRemote(t, nil, "legacy-remove")
			cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{
				Name: "legacy-remove", Host: "192.0.2.50", Port: 22, User: "runner", Password: "ISSUE17_LEGACY_REMOVE_PASSWORD_CANARY",
			}}})
			cli.SaveCloud(t, sync.URL(), "ISSUE17_LEGACY_REMOVE_TOKEN_CANARY")
			result := cli.Run(t, "ssm", nil, "remove", "legacy-remove")
			assertCompiledHumanSuccess(t, result, "legacy-remove")
			assertNoCompiledCanaryLeak(t, result, map[string]string{
				"password": "ISSUE17_LEGACY_REMOVE_PASSWORD_CANARY",
				"token":    "ISSUE17_LEGACY_REMOVE_TOKEN_CANARY",
			})
			if got := sync.MethodCount("PUT"); got != 1 {
				t.Fatalf("legacy remove PUT count = %d, want 1", got)
			}
			assertCompiledVaultSummary(t, cli.LoadVaultSummary(t), nil, nil, nil)
		})

		t.Run("legacy key remove auto-pushes without a transaction", func(t *testing.T) {
			cli := newCompiledCLIHarness(t)
			sync := newCompiledSyncFixture(t)
			sync.SetRemote(t, nil, "legacy-key-remove")
			cli.SaveVault(t, &config.Vault{Keys: []config.SSHKey{{
				Name: "legacy-key", PrivateKey: "ISSUE17_LEGACY_PRIVATE_KEY_CANARY",
			}}})
			cli.SaveCloud(t, sync.URL(), "ISSUE17_LEGACY_KEY_TOKEN_CANARY")
			result := cli.Run(t, "ssm", nil, "keys", "remove", "legacy-key")
			assertCompiledHumanSuccess(t, result, "legacy-key")
			assertNoCompiledCanaryLeak(t, result, map[string]string{
				"private_key": "ISSUE17_LEGACY_PRIVATE_KEY_CANARY",
				"token":       "ISSUE17_LEGACY_KEY_TOKEN_CANARY",
			})
			if got := sync.MethodCount("PUT"); got != 1 {
				t.Fatalf("legacy key remove PUT count = %d, want 1", got)
			}
			assertCompiledVaultSummary(t, cli.LoadVaultSummary(t), nil, nil, nil)
		})

		for _, mode := range []string{"merge", "replace"} {
			t.Run("import "+mode+" saves without publication or transaction", func(t *testing.T) {
				cli := newCompiledCLIHarness(t)
				sync := newCompiledSyncFixture(t)
				cli.SaveVault(t, &config.Vault{})
				cli.SaveCloud(t, sync.URL(), "ISSUE17_IMPORT_TOKEN_CANARY")
				importPath := filepath.Join(cli.temp, "import-"+mode+".json")
				importBody := `[{"alias":"imported-` + mode + `","host":"192.0.2.60","port":22,"user":"runner","auth_type":"password","password":"ISSUE17_IMPORT_PASSWORD_CANARY"}]`
				if err := os.WriteFile(importPath, []byte(importBody), 0o600); err != nil {
					t.Fatalf("write import fixture: %v", err)
				}
				args := []string{"--json", "import-json", importPath, "--" + mode}
				if mode == "replace" {
					args = append(args, "--yes")
				}
				result := cli.Run(t, "ssm", nil, args...)
				assertCompiledJSONSuccess(t, result)
				assertNoCompiledCanaryLeak(t, result, map[string]string{
					"password": "ISSUE17_IMPORT_PASSWORD_CANARY",
					"token":    "ISSUE17_IMPORT_TOKEN_CANARY",
				})
				if got := sync.MethodCount("PUT"); got != 0 {
					t.Fatalf("legacy import %s PUT count = %d, want 0", mode, got)
				}
				assertCompiledVaultSummary(t, cli.LoadVaultSummary(t), []string{"imported-" + mode}, nil, nil)
			})
		}
	})

	t.Run("BC-5 bare and empty-ledger push both publish the full blob", func(t *testing.T) {
		for _, args := range [][]string{{"--json", "push"}, {"--json", "push", "--all"}} {
			name := "bare"
			if len(args) == 3 {
				name = "explicit-all"
			}
			t.Run(name, func(t *testing.T) {
				cli := newCompiledCLIHarness(t)
				sync := newCompiledSyncFixture(t)
				sync.SetRemote(t, nil, "empty-ledger")
				cli.SaveVault(t, &config.Vault{})
				cli.SaveCloud(t, sync.URL(), "ISSUE17_EMPTY_LEDGER_TOKEN_CANARY")
				result := cli.Run(t, "sshctl", nil, args...)
				value := assertCompiledJSONSuccess(t, result)
				assertCompiledStringField(t, value, "scope", "all", result)
				assertNoCompiledCanaryLeak(t, result, map[string]string{"token": "ISSUE17_EMPTY_LEDGER_TOKEN_CANARY"})
				if got := sync.MethodCount("PUT"); got != 1 {
					t.Fatalf("%s push PUT count = %d, want 1", name, got)
				}
			})
		}
	})

	t.Run("BC-6 zero refresh remains valid online and refreshes only at startup", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		password := "ISSUE17_ZERO_REFRESH_PASSWORD_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
		cli.TrustSSHHost(t, server)
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("zero-refresh", password)}})
		cli.SaveCloud(t, sync.URL(), "ISSUE17_ZERO_REFRESH_TOKEN_CANARY")
		cli.SaveRemoteETag(t, "startup-current")
		sync.SetRemote(t, []byte("unused-opaque-blob"), "startup-current")
		result := cli.Run(t, "sshctl", []byte("[\"true\"]\n\n[\"true\"]\n"), "--json", "run", "zero-refresh", "--stream", "--refresh=0")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"password": password,
			"token":    "ISSUE17_ZERO_REFRESH_TOKEN_CANARY",
		})
		assertCompiledNDJSONResults(t, result, 2, true)
		if got := sync.MethodCount("HEAD"); got != 1 {
			t.Fatalf("zero-refresh HEAD count = %d, want startup-only count 1", got)
		}
		if connections, sessions := server.ConnectionCount(), server.SessionCount(); connections != 1 || sessions != 2 {
			t.Fatalf("zero-refresh SSH counts connections=%d sessions=%d, want 1 and 2", connections, sessions)
		}
	})

	t.Run("BC-7 direct and request-v1 transfer fields retain current omissions", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		password := "ISSUE17_TRANSFER_LIVE_PASSWORD_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
		cli.TrustSSHHost(t, server)
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("transfer-live", password)}})

		localFile := filepath.Join(cli.temp, "artifact.bin")
		fileBody := []byte("ISSUE17_TRANSFER_FILE_CONTENT_CANARY\n")
		if err := os.WriteFile(localFile, fileBody, 0o600); err != nil {
			t.Fatalf("write regular transfer fixture: %v", err)
		}
		remoteRoot := t.TempDir()
		remoteFile := filepath.Join(remoteRoot, "direct-file.bin")
		directFile := cli.Run(t, "sshctl", nil, "--offline", "--json", "put", "transfer-live", localFile, remoteFile, "--resume=v1", "--sha256")
		assertCompiledPutContract(t, directFile, compiledPutContract{
			Integrity: "sha256_verified", Atomic: true, Resume: "started", BytesSent: len(fileBody),
			Present: []string{"local_sha256", "remote_sha256"},
			Absent:  []string{"direction", "kind"},
		})

		requestRemoteFile := filepath.Join(remoteRoot, "request-file.bin")
		requestBody, err := json.Marshal(map[string]any{
			"version": 1, "op": "put", "alias": "transfer-live",
			"local_path": localFile, "remote_path": requestRemoteFile,
			"resume": "v1", "sha256": true,
		})
		if err != nil {
			t.Fatalf("marshal file transfer request fixture: %v", err)
		}
		requestFile := cli.Run(t, "sshctl", requestBody, "request", "-")
		assertCompiledPutContract(t, requestFile, compiledPutContract{
			Integrity: "sha256_verified", Atomic: true, Resume: "started", BytesSent: len(fileBody),
			Present: []string{"local_sha256", "remote_sha256"},
			Absent:  []string{"direction", "kind"},
		})

		localDirectory := filepath.Join(cli.temp, "directory")
		if err := os.Mkdir(localDirectory, 0o700); err != nil {
			t.Fatalf("create directory transfer fixture: %v", err)
		}
		if err := os.WriteFile(filepath.Join(localDirectory, "item.txt"), []byte("directory fixture\n"), 0o600); err != nil {
			t.Fatalf("write directory transfer fixture: %v", err)
		}
		remoteDirectory := filepath.Join(remoteRoot, "direct-directory")
		directDirectory := cli.Run(t, "sshctl", nil, "--offline", "--json", "put", "transfer-live", localDirectory, remoteDirectory)
		assertCompiledPutContract(t, directDirectory, compiledPutContract{
			Integrity: "not_available", Atomic: false, Resume: "unsupported", BytesSent: 0,
			Absent: []string{"direction", "kind", "local_sha256", "remote_sha256", "bytes_reused"},
		})

		requestRemoteDirectory := filepath.Join(remoteRoot, "request-directory")
		requestBody, err = json.Marshal(map[string]any{
			"version": 1, "op": "put", "alias": "transfer-live",
			"local_path": localDirectory, "remote_path": requestRemoteDirectory,
		})
		if err != nil {
			t.Fatalf("marshal directory transfer request fixture: %v", err)
		}
		requestDirectory := cli.Run(t, "sshctl", requestBody, "request", "-")
		assertCompiledPutContract(t, requestDirectory, compiledPutContract{
			Integrity: "not_available", Atomic: false, Resume: "unsupported", BytesSent: 0,
			Absent: []string{"direction", "kind", "local_sha256", "remote_sha256", "bytes_reused"},
		})

		getFile := cli.Run(t, "sshctl", nil, "--offline", "--json", "get", "transfer-live", remoteFile, filepath.Join(cli.temp, "downloaded-file.bin"))
		assertCompiledGetContract(t, getFile)
		getDirectory := cli.Run(t, "sshctl", nil, "--offline", "--json", "get", "transfer-live", remoteDirectory, filepath.Join(cli.temp, "downloaded-directory"))
		assertCompiledGetContract(t, getDirectory)

		blocker := filepath.Join(remoteRoot, "blocked-parent")
		if err := os.WriteFile(blocker, []byte("preserve\n"), 0o600); err != nil {
			t.Fatalf("write blocked remote parent fixture: %v", err)
		}
		failedRemote := filepath.Join(blocker, "artifact.bin")
		failed := cli.Run(t, "sshctl", nil, "--offline", "--json", "put", "transfer-live", localFile, failedRemote, "--sha256")
		assertCompiledMachineContract(t, failed, compiledMachineContract{
			OK: false, Error: "remote_write_failed", Stage: "remote_write", JSONExit: 1, ProcessExit: 1,
			Hint:   "check remote path permissions and available space; the final path was not replaced",
			Alias:  "transfer-live",
			Absent: []string{"direction", "kind"},
		})
		if data, err := os.ReadFile(blocker); err != nil || string(data) != "preserve\n" {
			t.Fatalf("failed transfer did not preserve safe blocker fixture")
		}
		if _, err := os.Stat(failedRemote); err == nil {
			t.Fatal("failed transfer published a final path")
		}

		assertNoCompiledCanaryLeak(t, directFile, map[string]string{"password": password, "file_body": string(fileBody)})
		assertNoCompiledCanaryLeak(t, requestFile, map[string]string{"password": password, "file_body": string(fileBody)})
		assertNoCompiledCanaryLeak(t, failed, map[string]string{"password": password, "file_body": string(fileBody)})
	})

	t.Run("BC-8 latest automatic replacement crosses the current major", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		cli.SaveVault(t, &config.Vault{})
		replacement := []byte("ISSUE17_CROSS_MAJOR_REPLACEMENT_FIXTURE\n")
		compiledUpdateServer.ConfigureRelease("v2.0.0", replacement)
		result := cli.RunWithEnv(t, "ssm", nil, map[string]string{"SSM_UPDATE_REPO": "fixture/repo"}, "list", "--json")
		assertCompiledJSONArraySuccess(t, result, 0)
		assertNoCompiledCanaryLeak(t, result, map[string]string{"replacement": string(replacement)})
		assertCompiledFileDigest(t, cli.paths["ssm"], replacement)
	})

	t.Run("BC-9 an adjacent checksum alone authorizes replacement", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		cli.SaveVault(t, &config.Vault{})
		replacement := []byte("ISSUE17_CHECKSUM_ONLY_REPLACEMENT_FIXTURE\n")
		compiledUpdateServer.ConfigureRelease("v1.5.0", replacement)
		result := cli.RunWithEnv(t, "ssm", nil, map[string]string{"SSM_UPDATE_REPO": "fixture/repo"}, "list", "--json")
		assertCompiledJSONArraySuccess(t, result, 0)
		assertCompiledFileDigest(t, cli.paths["ssm"], replacement)
		paths := compiledUpdateServer.RequestPaths()
		assertCompiledUpdateRequests(t, paths, "v1.5.0")
	})

	t.Run("BC-10 make check is a mutating format-lint-build subset", func(t *testing.T) {
		command := exec.Command("make", "-n", "check")
		command.Dir = filepath.Join("..", "..")
		output, err := command.Output()
		if err != nil {
			t.Fatalf("inspect make check membership: %v", err)
		}
		lines := nonEmptyCompiledLines(string(output))
		want := []string{
			"gofmt -w .",
			"golangci-lint run ./...",
			`go build -ldflags="-s -w -X main.version=dev" -o ssm ./cmd/ssm`,
		}
		if !reflect.DeepEqual(lines, want) {
			t.Fatalf("make check command count = %d, want %d", len(lines), len(want))
		}
		for _, forbidden := range []string{"go test", "go vet", "-race", "govulncheck"} {
			if strings.Contains(string(output), forbidden) {
				t.Fatalf("make check unexpectedly includes %q", forbidden)
			}
		}

		scratch := t.TempDir()
		makefile, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
		if err != nil {
			t.Fatalf("read Makefile for isolated mutation proof: %v", err)
		}
		if err := os.WriteFile(filepath.Join(scratch, "Makefile"), makefile, 0o600); err != nil {
			t.Fatalf("write isolated Makefile fixture: %v", err)
		}
		unformatted := []byte("package fixture\nfunc value( )int{return 1}\n")
		sourcePath := filepath.Join(scratch, "fixture.go")
		if err := os.WriteFile(sourcePath, unformatted, 0o600); err != nil {
			t.Fatalf("write unformatted Go fixture: %v", err)
		}
		format := exec.Command("make", "fmt")
		format.Dir = scratch
		if output, err := format.CombinedOutput(); err != nil {
			t.Fatalf("run isolated make fmt: %v; bytes=%d sha256=%x", err, len(output), sha256.Sum256(output))
		}
		formatted, err := os.ReadFile(sourcePath)
		if err != nil {
			t.Fatalf("read formatted Go fixture: %v", err)
		}
		if bytes.Equal(formatted, unformatted) {
			t.Fatal("make fmt did not mutate the isolated tracked-file analogue")
		}
	})
}
