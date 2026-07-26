package main

import (
	"bytes"
	"context"
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
	"time"

	"ssm/internal/config"
	securevault "ssm/internal/vault"
)

var compiledCLIPaths map[string]string

const compiledCLISubprocessTimeout = 15 * time.Second
const compiledCLIBuildTimeout = 2 * time.Minute

type compiledCLIResult struct {
	ProcessExit int
	Stdout      string
	Stderr      string
}

type compiledMachineContract struct {
	Name            string   `json:"name"`
	Command         string   `json:"command"`
	Executable      string   `json:"executable"`
	Args            []string `json:"args"`
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
	os.Exit(runCompiledCLITestMain(m))
}

func runCompiledCLITestMain(m *testing.M) (exitCode int) {
	buildDir, err := os.MkdirTemp("", "ssm-compiled-contracts-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create compiled CLI build directory: %v\n", err)
		return 1
	}
	defer func() {
		if err := os.RemoveAll(buildDir); err != nil {
			fmt.Fprintf(os.Stderr, "remove compiled CLI build directory: %v\n", err)
			exitCode = 1
		}
	}()
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
	ctx, cancel := context.WithTimeout(context.Background(), compiledCLIBuildTimeout)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-ldflags", updateLDFlags, "-o", ssmPath, ".")
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			fmt.Fprintf(os.Stderr, "build compiled CLI exceeded deadline %s\n", compiledCLIBuildTimeout)
			return 1
		}
		fmt.Fprintf(os.Stderr, "build compiled CLI: %v\n%s", buildErr, output)
		return 1
	}
	sshctlPath := filepath.Join(buildDir, "sshctl"+extension)
	if linkErr := os.Link(ssmPath, sshctlPath); linkErr != nil {
		data, readErr := os.ReadFile(ssmPath)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "read compiled CLI for sshctl alias: %v\n", readErr)
			return 1
		}
		info, statErr := os.Stat(ssmPath)
		if statErr != nil {
			fmt.Fprintf(os.Stderr, "stat compiled CLI for sshctl alias: %v\n", statErr)
			return 1
		}
		if writeErr := os.WriteFile(sshctlPath, data, info.Mode()); writeErr != nil {
			fmt.Fprintf(os.Stderr, "write compiled CLI sshctl alias: %v\n", writeErr)
			return 1
		}
	}
	compiledCLIPaths = map[string]string{"ssm": ssmPath, "sshctl": sshctlPath}

	return m.Run()
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

func (h *compiledCLIHarness) RunWithHeldOpenStdin(t *testing.T, executable string, args ...string) compiledCLIResult {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create held-open compiled CLI stdin pipe: %v", err)
	}
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()
	return h.runWithStdin(t, executable, reader, map[string]string{"SSM_MASTER_PASS_FILE": h.passPath}, args...)
}

func (h *compiledCLIHarness) RunReviewed(
	t *testing.T,
	contract compiledMachineContract,
	stdin []byte,
	replacements map[string]string,
) compiledCLIResult {
	t.Helper()
	args := append([]string(nil), contract.Args...)
	for index, arg := range args {
		if replacement, ok := replacements[arg]; ok {
			args[index] = replacement
		}
	}
	return h.Run(t, contract.Executable, stdin, args...)
}

func (h *compiledCLIHarness) RunReviewedWithoutMasterPass(t *testing.T, contract compiledMachineContract) compiledCLIResult {
	t.Helper()
	return h.RunWithoutMasterPass(t, contract.Executable, nil, contract.Args...)
}

func (h *compiledCLIHarness) RunWithPhysicalBasename(t *testing.T, executable string, args ...string) compiledCLIResult {
	t.Helper()
	path, ok := h.paths[executable]
	if !ok {
		t.Fatalf("unknown compiled CLI executable name %q", executable)
	}
	return h.runWithStdinAndArgv0(
		t,
		executable,
		filepath.Base(path),
		bytes.NewReader(nil),
		map[string]string{"SSM_MASTER_PASS_FILE": h.passPath},
		args...,
	)
}

func (h *compiledCLIHarness) run(t *testing.T, executable string, stdin []byte, env map[string]string, args ...string) compiledCLIResult {
	t.Helper()
	return h.runWithStdin(t, executable, bytes.NewReader(stdin), env, args...)
}

func (h *compiledCLIHarness) runWithStdin(t *testing.T, executable string, stdin io.Reader, env map[string]string, args ...string) compiledCLIResult {
	t.Helper()
	return h.runWithStdinAndArgv0(t, executable, executable, stdin, env, args...)
}

func (h *compiledCLIHarness) runWithStdinAndArgv0(
	t *testing.T,
	executable, argv0 string,
	stdin io.Reader,
	env map[string]string,
	args ...string,
) compiledCLIResult {
	t.Helper()
	path, ok := h.paths[executable]
	if !ok {
		t.Fatalf("unknown compiled CLI executable name %q", executable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), compiledCLISubprocessTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // executable is selected from test-owned fixed paths
	cmd.Args[0] = argv0
	cmd.Env = isolatedCompiledCLIEnvironmentWith(h.home, h.temp, env)
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	processExit := 0
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf(
				"compiled %s exceeded subprocess deadline %s; output=%s",
				executable, compiledCLISubprocessTimeout, compiledOutputIdentity(compiledCLIResult{Stdout: stdout.String(), Stderr: stderr.String()}),
			)
		}
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
	if !compiledJSONExitEquals(value["exit"], want.JSONExit) {
		t.Fatalf("JSON exit = %v, want %d; output=%s", value["exit"], want.JSONExit, compiledOutputIdentity(result))
	}
	for _, field := range want.Absent {
		if _, ok := value[field]; ok {
			t.Fatalf("field %q unexpectedly present; output=%s", field, compiledOutputIdentity(result))
		}
	}
}

func compiledJSONExitEquals(value any, want int) bool {
	got, ok := value.(float64)
	return ok && got == float64(want)
}

func TestCompiledJSONExitComparisonRejectsFraction(t *testing.T) {
	if compiledJSONExitEquals(float64(1.5), 1) {
		t.Fatal("fractional JSON number satisfied an integer exit contract")
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
		if row.Command == "" || row.Executable == "" || row.Args == nil ||
			row.StdoutPlacement != "stdout" || row.StderrPlacement != "empty" ||
			(row.Cardinality != "one_value" && row.Cardinality != "one_line") {
			t.Fatalf("reviewed compiled CLI contract %q has incomplete tuple metadata", row.Name)
		}
		if got := renderCompiledInvocation(row.Executable, row.Args); got != row.Command {
			t.Fatalf("reviewed compiled CLI contract %q command drifted from executable+args", row.Name)
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

func renderCompiledInvocation(executable string, args []string) string {
	words := make([]string, 0, len(args)+1)
	words = append(words, executable)
	for _, arg := range args {
		if arg != "" && !strings.ContainsAny(arg, " \t\r\n'") {
			words = append(words, arg)
			continue
		}
		words = append(words, "'"+strings.ReplaceAll(arg, "'", "'\"'\"'")+"'")
	}
	return strings.Join(words, " ")
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

func assertCompiledExactMachineOutput(t *testing.T, result compiledCLIResult, want string) {
	t.Helper()
	if result.ProcessExit != 0 || result.Stderr != "" || result.Stdout != want {
		t.Fatalf("compiled exact machine output contract failed; output=%s", compiledOutputIdentity(result))
	}
	decodeExactlyOneJSONObject(t, result.Stdout)
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

func assertCompiledTransferSnapshot(t *testing.T, result compiledCLIResult, want map[string]any) {
	t.Helper()
	wantExit := 0
	if rawExit, ok := want["exit"]; ok {
		switch value := rawExit.(type) {
		case int:
			wantExit = value
		case float64:
			wantExit = int(value)
		default:
			t.Fatalf("compiled transfer snapshot has unsupported exit type %T", rawExit)
		}
	}
	if result.ProcessExit != wantExit || result.Stderr != "" {
		t.Fatalf(
			"compiled transfer process exit=%d stderr_bytes=%d, want exit=%d stderr empty; output=%s",
			result.ProcessExit, len(result.Stderr), wantExit,
			compiledOutputIdentity(result),
		)
	}
	got := decodeExactlyOneJSONObject(t, result.Stdout)
	encodedWant, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal compiled transfer snapshot: %v", err)
	}
	var normalizedWant map[string]any
	if err := json.Unmarshal(encodedWant, &normalizedWant); err != nil {
		t.Fatalf("normalize compiled transfer snapshot: %v", err)
	}
	if reflect.DeepEqual(got, normalizedWant) {
		return
	}
	gotFields := make([]string, 0, len(got))
	for field := range got {
		gotFields = append(gotFields, field)
	}
	wantFields := make([]string, 0, len(normalizedWant))
	for field := range normalizedWant {
		wantFields = append(wantFields, field)
	}
	sort.Strings(gotFields)
	sort.Strings(wantFields)
	t.Fatalf(
		"compiled transfer snapshot mismatch; fields=%v want=%v; output=%s",
		gotFields, wantFields, compiledOutputIdentity(result),
	)
}

type compiledFileIdentity struct {
	ByteLength int
	Digest     [sha256.Size]byte
}

func loadCompiledFileIdentity(t *testing.T, path string) compiledFileIdentity {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read compiled CLI fixture identity: %v", err)
	}
	return compiledFileIdentity{ByteLength: len(data), Digest: sha256.Sum256(data)}
}

func assertCompiledFileMatches(t *testing.T, path string, want []byte) {
	t.Helper()
	got := loadCompiledFileIdentity(t, path)
	wantIdentity := compiledFileIdentity{ByteLength: len(want), Digest: sha256.Sum256(want)}
	if got != wantIdentity {
		t.Fatal("compiled CLI executable does not match the downloaded replacement fixture")
	}
}

func assertCompiledFileUnchanged(t *testing.T, path string, before compiledFileIdentity) {
	t.Helper()
	if got := loadCompiledFileIdentity(t, path); got != before {
		t.Fatal("compiled CLI executable changed after the characterized replacement failure")
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

type compiledMakeRule struct {
	dependencies []string
	commands     []string
}

func compiledMakeTargetCommands(makefile []byte, target string) ([]string, error) {
	variables := map[string]string{}
	rules := map[string]compiledMakeRule{}
	currentTarget := ""
	for lineNumber, rawLine := range strings.Split(string(makefile), "\n") {
		if strings.HasPrefix(rawLine, "\t") {
			if currentTarget == "" {
				return nil, fmt.Errorf("recipe without target at line %d", lineNumber+1)
			}
			rule := rules[currentTarget]
			rule.commands = append(rule.commands, expandCompiledMakeVariables(strings.TrimSpace(rawLine), variables))
			rules[currentTarget] = rule
			continue
		}
		currentTarget = ""
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if key, value, ok := strings.Cut(line, "?="); ok {
			key = strings.TrimSpace(key)
			if _, exists := variables[key]; !exists {
				variables[key] = strings.TrimSpace(value)
			}
			continue
		}
		targets, dependencies, ok := strings.Cut(line, ":")
		if !ok || strings.Contains(targets, "=") {
			continue
		}
		targetNames := strings.Fields(targets)
		if len(targetNames) != 1 {
			return nil, fmt.Errorf("unsupported target declaration at line %d", lineNumber+1)
		}
		currentTarget = targetNames[0]
		rule := rules[currentTarget]
		rule.dependencies = append(rule.dependencies, strings.Fields(dependencies)...)
		rules[currentTarget] = rule
	}

	var commands []string
	visiting := map[string]bool{}
	visited := map[string]bool{}
	var collect func(string) error
	collect = func(name string) error {
		if visiting[name] {
			return fmt.Errorf("cyclic Makefile dependency at %q", name)
		}
		if visited[name] {
			return nil
		}
		rule, ok := rules[name]
		if !ok {
			return fmt.Errorf("Makefile target %q is missing", name)
		}
		visiting[name] = true
		for _, dependency := range rule.dependencies {
			if err := collect(dependency); err != nil {
				return err
			}
		}
		visiting[name] = false
		visited[name] = true
		commands = append(commands, rule.commands...)
		return nil
	}
	if err := collect(target); err != nil {
		return nil, err
	}
	return commands, nil
}

func expandCompiledMakeVariables(command string, variables map[string]string) string {
	for key, value := range variables {
		command = strings.ReplaceAll(command, "$("+key+")", value)
	}
	return command
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

func compiledPendingTransactionViews(t *testing.T, value map[string]any, result compiledCLIResult) []pendingMutationView {
	t.Helper()
	transactions, err := parseCompiledPendingTransactionViews(value)
	if err != nil {
		t.Fatalf("%v; output=%s", err, compiledOutputIdentity(result))
	}
	return transactions
}

func parseCompiledPendingTransactionViews(value map[string]any) ([]pendingMutationView, error) {
	if got, want := sortedCompiledJSONFields(value), []string{
		"freshness", "hosts", "offline", "ok", "pending_changes", "pending_mutations", "redirects",
		"remote_state", "reuse", "reuse_scope", "sync", "vault", "version",
	}; !reflect.DeepEqual(got, want) {
		return nil, fmt.Errorf("pending status top-level field set changed")
	}
	raw, ok := value["pending_mutations"].([]any)
	if !ok {
		return nil, fmt.Errorf("pending_mutations has unexpected type")
	}
	transactions := make([]pendingMutationView, len(raw))
	for i, item := range raw {
		mutation, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("pending mutation %d has unexpected type", i)
		}
		if got, want := sortedCompiledJSONFields(mutation), []string{"alias", "created_at", "id", "operation"}; !reflect.DeepEqual(got, want) {
			return nil, fmt.Errorf("pending mutation %d field set changed", i)
		}
		for field, destination := range map[string]*string{
			"id": &transactions[i].ID, "alias": &transactions[i].Alias,
			"operation": &transactions[i].Operation, "created_at": &transactions[i].CreatedAt,
		} {
			*destination, ok = mutation[field].(string)
			if !ok {
				return nil, fmt.Errorf("pending mutation %d field %q has unexpected type", i, field)
			}
		}
	}
	return transactions, nil
}

func sortedCompiledJSONFields(value map[string]any) []string {
	fields := make([]string, 0, len(value))
	for field := range value {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return fields
}

func TestCompiledPendingTransactionViewParserRejectsUnexpectedFields(t *testing.T) {
	fixture := func() map[string]any {
		return map[string]any{
			"ok": true, "version": "test", "hosts": float64(1), "vault": "present",
			"sync": "configured", "redirects": float64(0), "reuse": "on", "reuse_scope": "process",
			"freshness": "unknown", "remote_state": "not_checked", "pending_changes": true,
			"pending_mutations": []any{map[string]any{
				"id": "tx_safe", "alias": "safe", "operation": "created", "created_at": "2026-01-01T00:00:00Z",
			}},
			"offline": true,
		}
	}
	t.Run("top level", func(t *testing.T) {
		value := fixture()
		value["unexpected"] = true
		if _, err := parseCompiledPendingTransactionViews(value); err == nil {
			t.Fatal("pending transaction view parser accepted an unexpected top-level field")
		}
	})
	t.Run("nested mutation", func(t *testing.T) {
		value := fixture()
		value["pending_mutations"].([]any)[0].(map[string]any)["unexpected"] = true
		if _, err := parseCompiledPendingTransactionViews(value); err == nil {
			t.Fatal("pending transaction view parser accepted an unexpected nested field")
		}
	})
}

type compiledSecretIdentity struct {
	Present    bool
	ByteLength int
	Digest     [sha256.Size]byte
}

type compiledConnectionIdentity struct {
	Name     string                 `safe:"name"`
	Host     string                 `safe:"host"`
	Port     int                    `safe:"port"`
	User     string                 `safe:"user"`
	Password compiledSecretIdentity `safe:"password"`
	KeyName  string                 `safe:"key_name"`
	Group    string                 `safe:"group"`
}

type compiledKeyIdentity struct {
	Name       string                 `safe:"name"`
	PrivateKey compiledSecretIdentity `safe:"private_key"`
}

type compiledInventoryIdentity struct {
	Connections []compiledConnectionIdentity `safe:"connections"`
	Keys        []compiledKeyIdentity        `safe:"keys"`
}

type compiledMutationIdentity struct {
	ID         string                      `safe:"id"`
	Alias      string                      `safe:"alias"`
	Operation  string                      `safe:"operation"`
	CreatedAt  string                      `safe:"created_at"`
	Before     *compiledConnectionIdentity `safe:"before"`
	After      *compiledConnectionIdentity `safe:"after"`
	KeysBefore []compiledKeyIdentity       `safe:"keys_before"`
	KeysAfter  []compiledKeyIdentity       `safe:"keys_after"`
}

type compiledVaultIdentity struct {
	Connections      []compiledConnectionIdentity `safe:"connections"`
	Keys             []compiledKeyIdentity        `safe:"keys"`
	PendingBase      *compiledInventoryIdentity   `safe:"pending_base"`
	PendingMutations []compiledMutationIdentity   `safe:"pending_mutations"`
}

func decodeCompiledVaultIdentity(t *testing.T, encrypted []byte, passphrase string) compiledVaultIdentity {
	t.Helper()
	plaintext, err := securevault.Decrypt(encrypted, passphrase)
	if err != nil {
		t.Fatalf("decrypt compiled CLI fixture blob: %v; encrypted_bytes=%d sha256=%x", err, len(encrypted), sha256.Sum256(encrypted))
	}
	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()
	var value config.Vault
	if err := json.Unmarshal(plaintext, &value); err != nil {
		t.Fatalf("decode compiled CLI fixture vault: %v; encrypted_bytes=%d sha256=%x", err, len(encrypted), sha256.Sum256(encrypted))
	}
	return compiledVaultSafeIdentity(&value)
}

func TestCompiledVaultPublicationIdentityCoversPersistedFields(t *testing.T) {
	assertCompiledPersistedFields(t, reflect.TypeOf(config.Vault{}), []string{
		"Connections", "Keys", "PendingBase", "PendingMutations",
	})
	assertCompiledPersistedFields(t, reflect.TypeOf(config.Connection{}), []string{
		"Name", "Host", "Port", "User", "Password", "KeyName", "Group",
	})
	assertCompiledPersistedFields(t, reflect.TypeOf(config.SSHKey{}), []string{
		"Name", "PrivateKey",
	})
	assertCompiledPersistedFields(t, reflect.TypeOf(config.InventorySnapshot{}), []string{
		"Connections", "Keys",
	})
	assertCompiledPersistedFields(t, reflect.TypeOf(config.PendingMutation{}), []string{
		"ID", "Alias", "Operation", "CreatedAt", "Before", "After", "KeysBefore", "KeysAfter",
	})

	passphrase := "ISSUE17_NORMALIZATION_PASSPHRASE_CANARY"
	identity := func(value *config.Vault) compiledVaultIdentity {
		t.Helper()
		encrypted, err := config.EncryptVault(value, passphrase)
		if err != nil {
			t.Fatalf("encrypt compiled vault normalization fixture: %v", err)
		}
		return decodeCompiledVaultIdentity(t, encrypted, passphrase)
	}
	fixture := func() *config.Vault {
		before := config.Connection{
			Name: "before", Host: "192.0.2.80", Port: 2200, User: "before-user",
			Password: "ISSUE17_NORMALIZATION_BEFORE_PASSWORD_CANARY", KeyName: "before-key", Group: "before-group",
		}
		after := config.Connection{
			Name: "after", Host: "192.0.2.81", Port: 2201, User: "after-user",
			Password: "ISSUE17_NORMALIZATION_AFTER_PASSWORD_CANARY", KeyName: "after-key", Group: "after-group",
		}
		beforeKey := config.SSHKey{Name: "before-key", PrivateKey: "ISSUE17_NORMALIZATION_BEFORE_PRIVATE_KEY_CANARY"}
		afterKey := config.SSHKey{Name: "after-key", PrivateKey: "ISSUE17_NORMALIZATION_AFTER_PRIVATE_KEY_CANARY"}
		return &config.Vault{
			Connections: []config.Connection{before, after},
			Keys:        []config.SSHKey{beforeKey, afterKey},
			PendingBase: &config.InventorySnapshot{
				Connections: []config.Connection{before},
				Keys:        []config.SSHKey{beforeKey},
			},
			PendingMutations: []config.PendingMutation{{
				ID: "tx_normalized", Alias: after.Name, Operation: "updated", CreatedAt: "2026-01-02T03:04:05Z",
				Before: &before, After: &after, KeysBefore: []config.SSHKey{beforeKey}, KeysAfter: []config.SSHKey{afterKey},
			}},
		}
	}
	tests := []struct {
		path   string
		mutate func(*config.Vault)
	}{
		{path: "connections order", mutate: func(v *config.Vault) { v.Connections[0], v.Connections[1] = v.Connections[1], v.Connections[0] }},
		{path: "connections presence", mutate: func(v *config.Vault) { v.Connections = nil }},
		{path: "connection name", mutate: func(v *config.Vault) { v.Connections[0].Name = "changed" }},
		{path: "connection host", mutate: func(v *config.Vault) { v.Connections[0].Host = "192.0.2.82" }},
		{path: "connection port", mutate: func(v *config.Vault) { v.Connections[0].Port++ }},
		{path: "connection user", mutate: func(v *config.Vault) { v.Connections[0].User = "changed" }},
		{path: "connection password value", mutate: func(v *config.Vault) { v.Connections[0].Password = "ISSUE17_NORMALIZATION_CHANGED_PASSWORD_CANARY" }},
		{path: "connection password presence", mutate: func(v *config.Vault) { v.Connections[0].Password = "" }},
		{path: "connection key reference", mutate: func(v *config.Vault) { v.Connections[0].KeyName = "changed" }},
		{path: "connection group", mutate: func(v *config.Vault) { v.Connections[0].Group = "changed" }},
		{path: "keys order", mutate: func(v *config.Vault) { v.Keys[0], v.Keys[1] = v.Keys[1], v.Keys[0] }},
		{path: "keys presence", mutate: func(v *config.Vault) { v.Keys = nil }},
		{path: "key name", mutate: func(v *config.Vault) { v.Keys[0].Name = "changed" }},
		{path: "private key value", mutate: func(v *config.Vault) { v.Keys[0].PrivateKey = "ISSUE17_NORMALIZATION_CHANGED_PRIVATE_KEY_CANARY" }},
		{path: "private key length", mutate: func(v *config.Vault) { v.Keys[0].PrivateKey += "x" }},
		{path: "pending base presence", mutate: func(v *config.Vault) { v.PendingBase = nil }},
		{path: "pending base inventory", mutate: func(v *config.Vault) { v.PendingBase.Connections[0].Host = "192.0.2.83" }},
		{path: "pending base keys", mutate: func(v *config.Vault) { v.PendingBase.Keys[0].Name = "changed" }},
		{path: "pending mutation order", mutate: func(v *config.Vault) { v.PendingMutations = append(v.PendingMutations, v.PendingMutations[0]) }},
		{path: "pending mutation id", mutate: func(v *config.Vault) { v.PendingMutations[0].ID = "tx_changed" }},
		{path: "pending mutation alias", mutate: func(v *config.Vault) { v.PendingMutations[0].Alias = "changed" }},
		{path: "pending mutation operation", mutate: func(v *config.Vault) { v.PendingMutations[0].Operation = "changed" }},
		{path: "pending mutation state", mutate: func(v *config.Vault) { v.PendingMutations[0].CreatedAt = "2026-02-03T04:05:06Z" }},
		{path: "pending mutation before presence", mutate: func(v *config.Vault) { v.PendingMutations[0].Before = nil }},
		{path: "pending mutation before", mutate: func(v *config.Vault) { v.PendingMutations[0].Before.User = "changed" }},
		{path: "pending mutation after presence", mutate: func(v *config.Vault) { v.PendingMutations[0].After = nil }},
		{path: "pending mutation after", mutate: func(v *config.Vault) { v.PendingMutations[0].After.Group = "changed" }},
		{path: "pending mutation keys before", mutate: func(v *config.Vault) { v.PendingMutations[0].KeysBefore[0].Name = "changed" }},
		{path: "pending mutation keys after", mutate: func(v *config.Vault) { v.PendingMutations[0].KeysAfter[0].Name = "changed" }},
	}
	baseline := identity(fixture())
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			changed := fixture()
			test.mutate(changed)
			if reflect.DeepEqual(baseline, identity(changed)) {
				t.Fatalf("safe vault publication identity ignored %s", test.path)
			}
		})
	}

	t.Run("mismatch rendering reports only safe path and category", func(t *testing.T) {
		left := fixture()
		right := fixture()
		right.Connections[0].Password = "ISSUE17_NORMALIZATION_BEFORE_PASSW0RD_CANARY"
		leftIdentity := identity(left)
		rightIdentity := identity(right)
		path, category, mismatch := compiledVaultIdentityMismatch(
			reflect.ValueOf(leftIdentity), reflect.ValueOf(rightIdentity), "vault",
		)
		if !mismatch {
			t.Fatal("safe vault comparison accepted a changed secret identity")
		}
		report := compiledVaultMismatchReport(path, category)
		if report != "safe normalized vault mismatch at vault.connections[0].password (secret identity mismatch)" {
			t.Fatal("safe vault mismatch report included more than its field path and mismatch category")
		}
	})
}

func assertCompiledPersistedFields(t *testing.T, valueType reflect.Type, want []string) {
	t.Helper()
	got := make([]string, valueType.NumField())
	for i := 0; i < valueType.NumField(); i++ {
		got[i] = valueType.Field(i).Name
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("persisted field coverage for %s changed", valueType.Name())
	}
}

func compiledVaultSafeIdentity(value *config.Vault) compiledVaultIdentity {
	identity := compiledVaultIdentity{
		Connections: compiledConnectionIdentities(value.Connections),
		Keys:        compiledKeyIdentities(value.Keys),
	}
	if value.PendingBase != nil {
		identity.PendingBase = &compiledInventoryIdentity{
			Connections: compiledConnectionIdentities(value.PendingBase.Connections),
			Keys:        compiledKeyIdentities(value.PendingBase.Keys),
		}
	}
	if value.PendingMutations != nil {
		identity.PendingMutations = make([]compiledMutationIdentity, len(value.PendingMutations))
		for i, mutation := range value.PendingMutations {
			identity.PendingMutations[i] = compiledMutationIdentity{
				ID:         mutation.ID,
				Alias:      mutation.Alias,
				Operation:  mutation.Operation,
				CreatedAt:  mutation.CreatedAt,
				Before:     compiledOptionalConnectionIdentity(mutation.Before),
				After:      compiledOptionalConnectionIdentity(mutation.After),
				KeysBefore: compiledKeyIdentities(mutation.KeysBefore),
				KeysAfter:  compiledKeyIdentities(mutation.KeysAfter),
			}
		}
	}
	return identity
}

func compiledConnectionIdentities(values []config.Connection) []compiledConnectionIdentity {
	if values == nil {
		return nil
	}
	identities := make([]compiledConnectionIdentity, len(values))
	for i := range values {
		identities[i] = *compiledOptionalConnectionIdentity(&values[i])
	}
	return identities
}

func compiledOptionalConnectionIdentity(value *config.Connection) *compiledConnectionIdentity {
	if value == nil {
		return nil
	}
	return &compiledConnectionIdentity{
		Name:     value.Name,
		Host:     value.Host,
		Port:     value.Port,
		User:     value.User,
		Password: compiledSensitiveIdentity(value.Password, value.Password != ""),
		KeyName:  value.KeyName,
		Group:    value.Group,
	}
}

func compiledKeyIdentities(values []config.SSHKey) []compiledKeyIdentity {
	if values == nil {
		return nil
	}
	identities := make([]compiledKeyIdentity, len(values))
	for i, value := range values {
		identities[i] = compiledKeyIdentity{
			Name:       value.Name,
			PrivateKey: compiledSensitiveIdentity(value.PrivateKey, true),
		}
	}
	return identities
}

func compiledSensitiveIdentity(value string, present bool) compiledSecretIdentity {
	identity := compiledSecretIdentity{Present: present}
	if !present {
		return identity
	}
	identity.ByteLength = len(value)
	identity.Digest = sha256.Sum256([]byte(value))
	return identity
}

func (h *compiledCLIHarness) LoadVaultIdentity(t *testing.T) compiledVaultIdentity {
	t.Helper()
	path := filepath.Join(h.home, ".config", "ssm", "connections.enc")
	encrypted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read compiled CLI fixture vault: %v", err)
	}
	return decodeCompiledVaultIdentity(t, encrypted, h.passphrase)
}

func assertCompiledVaultIdentity(t *testing.T, got compiledVaultIdentity, want *config.Vault) {
	t.Helper()
	path, category, mismatch := compiledVaultIdentityMismatch(reflect.ValueOf(got), reflect.ValueOf(compiledVaultSafeIdentity(want)), "vault")
	if mismatch {
		t.Fatal(compiledVaultMismatchReport(path, category))
	}
}

var compiledSecretIdentityType = reflect.TypeOf(compiledSecretIdentity{})

func compiledVaultMismatchReport(path, category string) string {
	return fmt.Sprintf("safe normalized vault mismatch at %s (%s mismatch)", path, category)
}

func compiledVaultIdentityMismatch(got, want reflect.Value, path string) (string, string, bool) {
	if got.Type() != want.Type() {
		return path, "type", true
	}
	if got.Type() == compiledSecretIdentityType {
		switch {
		case got.FieldByName("Present").Bool() != want.FieldByName("Present").Bool():
			return path, "presence", true
		case got.FieldByName("ByteLength").Int() != want.FieldByName("ByteLength").Int():
			return path, "length", true
		case !reflect.DeepEqual(got.FieldByName("Digest").Interface(), want.FieldByName("Digest").Interface()):
			return path, "secret identity", true
		default:
			return "", "", false
		}
	}
	switch got.Kind() {
	case reflect.Pointer:
		if got.IsNil() != want.IsNil() {
			return path, "presence", true
		}
		if got.IsNil() {
			return "", "", false
		}
		return compiledVaultIdentityMismatch(got.Elem(), want.Elem(), path)
	case reflect.Slice:
		if got.IsNil() != want.IsNil() {
			return path, "presence", true
		}
		if got.Len() != want.Len() {
			return path, "count", true
		}
		for i := 0; i < got.Len(); i++ {
			if mismatchPath, category, mismatch := compiledVaultIdentityMismatch(
				got.Index(i), want.Index(i), fmt.Sprintf("%s[%d]", path, i),
			); mismatch {
				return mismatchPath, category, true
			}
		}
		return "", "", false
	case reflect.Struct:
		for i := 0; i < got.NumField(); i++ {
			field := got.Type().Field(i)
			name := field.Tag.Get("safe")
			if name == "" {
				name = field.Name
			}
			if mismatchPath, category, mismatch := compiledVaultIdentityMismatch(
				got.Field(i), want.Field(i), path+"."+name,
			); mismatch {
				return mismatchPath, category, true
			}
		}
		return "", "", false
	default:
		if !reflect.DeepEqual(got.Interface(), want.Interface()) {
			return path, "value", true
		}
		return "", "", false
	}
}

func assertCompiledEncryptedPublication(
	t *testing.T,
	encrypted []byte,
	passphrase string,
	plaintextCanaries map[string]string,
	want *config.Vault,
) {
	t.Helper()
	if len(encrypted) == 0 {
		t.Fatal("captured compiled CLI publication body is empty")
	}
	for label, canary := range plaintextCanaries {
		if canary != "" && bytes.Contains(encrypted, []byte(canary)) {
			t.Fatalf(
				"captured compiled CLI publication contains plaintext canary %q; encrypted_bytes=%d sha256=%x",
				label, len(encrypted), sha256.Sum256(encrypted),
			)
		}
	}
	assertCompiledVaultIdentity(t, decodeCompiledVaultIdentity(t, encrypted, passphrase), want)
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

func mergeCompiledCanaries(base map[string]string, label, canary string) map[string]string {
	merged := make(map[string]string, len(base)+1)
	for key, value := range base {
		merged[key] = value
	}
	merged[label] = canary
	return merged
}

func assertCompiledKnownHostsFileAbsent(t *testing.T, cli *compiledCLIHarness) {
	t.Helper()
	path := filepath.Join(cli.home, ".ssh", "known_hosts")
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatalf("inspect compiled CLI known_hosts after rejected fingerprint: %v", err)
	}
	t.Fatalf("rejected fingerprint installed a known_hosts file with %d bytes", info.Size())
}

func compiledLegacyImportStartingVault() *config.Vault {
	baseConnection := config.Connection{
		Name: "import-existing-password", Host: "192.0.2.80", Port: 2280, User: "base-user",
		Password: "ISSUE17_IMPORT_BASE_PASSWORD_CANARY", Group: "base-group",
	}
	existingConnection := config.Connection{
		Name: "import-existing-password", Host: "192.0.2.81", Port: 2281, User: "existing-user",
		Password: "ISSUE17_IMPORT_EXISTING_PASSWORD_CANARY", Group: "existing-group",
	}
	keyConnection := config.Connection{
		Name: "import-existing-key", Host: "192.0.2.82", Port: 2282, User: "key-user",
		KeyName: "import-existing-key", Group: "key-group",
	}
	baseKey := config.SSHKey{
		Name: "import-base-key", PrivateKey: "ISSUE17_IMPORT_BASE_PRIVATE_KEY_CANARY",
	}
	existingKey := config.SSHKey{
		Name: "import-existing-key", PrivateKey: "ISSUE17_IMPORT_EXISTING_PRIVATE_KEY_CANARY",
	}
	return &config.Vault{
		Connections: []config.Connection{existingConnection, keyConnection},
		Keys:        []config.SSHKey{baseKey, existingKey},
		PendingBase: &config.InventorySnapshot{
			Connections: []config.Connection{baseConnection},
			Keys:        []config.SSHKey{baseKey},
		},
		PendingMutations: []config.PendingMutation{
			{
				ID: "tx_import_existing_update", Alias: existingConnection.Name,
				Operation: "updated", CreatedAt: "2026-01-03T00:00:00Z",
				Before: &baseConnection, After: &existingConnection,
				KeysBefore: []config.SSHKey{baseKey}, KeysAfter: []config.SSHKey{baseKey},
			},
			{
				ID: "tx_import_existing_key", Alias: keyConnection.Name,
				Operation: "created", CreatedAt: "2026-01-03T00:00:01Z",
				After:      &keyConnection,
				KeysBefore: []config.SSHKey{baseKey}, KeysAfter: []config.SSHKey{baseKey, existingKey},
			},
		},
	}
}

func compiledLegacyPendingLedger() (*config.InventorySnapshot, []config.PendingMutation) {
	baseConnection := config.Connection{
		Name: "legacy-ledger-alpha", Host: "192.0.2.90", Port: 2290, User: "ledger-base-user",
		Password: "ISSUE17_LEGACY_LEDGER_BASE_PASSWORD_CANARY", Group: "ledger-base-group",
	}
	updatedConnection := config.Connection{
		Name: "legacy-ledger-alpha", Host: "192.0.2.91", Port: 2291, User: "ledger-updated-user",
		Password: "ISSUE17_LEGACY_LEDGER_UPDATED_PASSWORD_CANARY", Group: "ledger-updated-group",
	}
	createdConnection := config.Connection{
		Name: "legacy-ledger-beta", Host: "192.0.2.92", Port: 2292, User: "ledger-key-user",
		KeyName: "legacy-ledger-pending-key", Group: "ledger-key-group",
	}
	baseKey := config.SSHKey{
		Name: "legacy-ledger-base-key", PrivateKey: "ISSUE17_LEGACY_LEDGER_BASE_PRIVATE_KEY_CANARY",
	}
	pendingKey := config.SSHKey{
		Name: "legacy-ledger-pending-key", PrivateKey: "ISSUE17_LEGACY_LEDGER_PENDING_PRIVATE_KEY_CANARY",
	}
	return &config.InventorySnapshot{
			Connections: []config.Connection{baseConnection},
			Keys:        []config.SSHKey{baseKey},
		}, []config.PendingMutation{
			{
				ID: "tx_legacy_ledger_alpha", Alias: updatedConnection.Name,
				Operation: "updated", CreatedAt: "2026-01-04T00:00:00Z",
				Before: &baseConnection, After: &updatedConnection,
				KeysBefore: []config.SSHKey{baseKey}, KeysAfter: []config.SSHKey{baseKey},
			},
			{
				ID: "tx_legacy_ledger_beta", Alias: createdConnection.Name,
				Operation: "created", CreatedAt: "2026-01-04T00:00:01Z",
				After:      &createdConnection,
				KeysBefore: []config.SSHKey{baseKey}, KeysAfter: []config.SSHKey{baseKey, pendingKey},
			},
		}
}

func compiledOutputIdentity(result compiledCLIResult) string {
	stdoutDigest := sha256.Sum256([]byte(result.Stdout))
	stderrDigest := sha256.Sum256([]byte(result.Stderr))
	return fmt.Sprintf("stdout_bytes=%d stdout_sha256=%x stderr_bytes=%d stderr_sha256=%x", len(result.Stdout), stdoutDigest, len(result.Stderr), stderrDigest)
}

func TestCompiledCLIHarnessCrossPlatformDesign(t *testing.T) {
	for _, path := range []string{"compiled_cli_contract_test.go", "compiled_cli_fixtures_test.go"} {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read compiled CLI harness source %s: %v", path, err)
		}
		for _, forbidden := range []string{
			"exec." + "LookPath(\"sh\")",
			"exec." + "Command(\"sh\"",
			"exec." + "Command(\"make\"",
		} {
			if bytes.Contains(source, []byte(forbidden)) {
				t.Fatalf("compiled CLI harness source %s retains native dependency %q", path, forbidden)
			}
		}
	}

	extension := ""
	if runtime.GOOS == "windows" {
		extension = ".exe"
	}
	for _, executable := range []string{"ssm", "sshctl"} {
		if got, want := filepath.Base(compiledCLIPaths[executable]), executable+extension; got != want {
			t.Fatalf("compiled %s fixture basename = %q, want %q", executable, got, want)
		}
	}
}

func TestCompiledCLIContractMatrix(t *testing.T) {
	reviewed := reviewedCompiledMachineContracts(t)
	reviewedNames := []string{
		"unknown_sshctl", "unknown_ssm", "invalid_request_unknown_field", "unlock_file_required",
		"exact_alias_miss", "sync_etag_conflict", "transfer_local_read", "host_key_unknown",
		"dial_refused", "dial_refused_windows", "auth_failed", "session_failed", "remote_exit_255", "stream_refresh_failed",
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
		contractName string
	}{
		{
			name:         "sshctl dispatch",
			contractName: "unknown_sshctl",
		},
		{
			name:         "ssm dispatch",
			contractName: "unknown_ssm",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			contract := reviewedCompiledMachineContract(t, test.contractName)
			result := cli.RunReviewed(t, contract, nil, nil)
			assertCompiledMachineContract(t, result, contract)
		})
	}

	t.Run("physical sshctl basename freezes the Windows extension discrepancy", func(t *testing.T) {
		invocation := reviewedCompiledMachineContract(t, "unknown_sshctl")
		want := invocation
		if runtime.GOOS == "windows" {
			want = reviewedCompiledMachineContract(t, "unknown_ssm")
		}
		result := cli.RunWithPhysicalBasename(t, "sshctl", invocation.Args...)
		assertCompiledMachineContract(t, result, want)
	})

	t.Run("strict request schema rejects unknown fields", func(t *testing.T) {
		requestCanary := "ISSUE17_REQUEST_BODY_CANARY"
		contract := reviewedCompiledMachineContract(t, "invalid_request_unknown_field")
		result := cli.RunReviewed(t, contract, []byte(`{"version":1,"op":"run","alias":"prod","argv":["true"],"unexpected":"`+requestCanary+`"}`), nil)
		assertNoCompiledCanaryLeak(t, result, map[string]string{"request_body": requestCanary})
		assertCompiledMachineContract(t, result, contract)
	})

	t.Run("missing non-interactive unlock file", func(t *testing.T) {
		contract := reviewedCompiledMachineContract(t, "unlock_file_required")
		result := cli.RunReviewedWithoutMasterPass(t, contract)
		assertCompiledMachineContract(t, result, contract)
	})

	t.Run("exact alias miss returns candidates without selecting", func(t *testing.T) {
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{
			{Name: "prod-one", Host: "192.0.2.10", Port: 22, User: "runner", Password: "ISSUE17_PASSWORD_CANARY"},
			{Name: "prod-two", Host: "192.0.2.11", Port: 22, User: "runner", Password: "ISSUE17_SECOND_PASSWORD_CANARY"},
		}})
		contract := reviewedCompiledMachineContract(t, "exact_alias_miss")
		result := cli.RunReviewed(t, contract, nil, nil)
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"password_one": "ISSUE17_PASSWORD_CANARY",
			"password_two": "ISSUE17_SECOND_PASSWORD_CANARY",
		})
		assertCompiledMachineContract(t, result, contract)
	})

	t.Run("two-sided ETag conflict preserves classified sync failure", func(t *testing.T) {
		sync := newCompiledSyncFixture(t)
		sync.SetRemote(t, []byte("opaque-remote-blob"), "remote-changed")
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{
			Name: "cached", Host: "192.0.2.20", Port: 22, User: "runner", Password: "ISSUE17_SYNC_PASSWORD_CANARY",
		}}})
		cli.SaveCloud(t, sync.URL(), "ISSUE17_SYNC_TOKEN_CANARY")
		cli.SaveRemoteETag(t, "cached-baseline")

		contract := reviewedCompiledMachineContract(t, "sync_etag_conflict")
		result := cli.RunReviewed(t, contract, nil, nil)
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"password": "ISSUE17_SYNC_PASSWORD_CANARY",
			"token":    "ISSUE17_SYNC_TOKEN_CANARY",
		})
		assertCompiledMachineContract(t, result, contract)
		if got := sync.MethodCount("GET"); got != 0 {
			t.Fatalf("sync GET count = %d, want 0 after conflict preflight", got)
		}
	})

	t.Run("transfer preparation failure keeps the public transfer envelope", func(t *testing.T) {
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{
			Name: "transfer", Host: "192.0.2.30", Port: 22, User: "runner", Password: "ISSUE17_TRANSFER_PASSWORD_CANARY",
		}}})
		missing := filepath.Join(cli.home, "missing-artifact")
		contract := reviewedCompiledMachineContract(t, "transfer_local_read")
		result := cli.RunReviewed(t, contract, nil, map[string]string{"<missing>": missing})
		assertNoCompiledCanaryLeak(t, result, map[string]string{"password": "ISSUE17_TRANSFER_PASSWORD_CANARY"})
		assertCompiledMachineContract(t, result, contract)
	})

	t.Run("host key is inspected and accepted only by exact fingerprint", func(t *testing.T) {
		password := "ISSUE17_HOST_KEY_PASSWORD_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
		privateKey := "ISSUE17_HOST_KEY_PRIVATE_KEY_CANARY"
		token := "ISSUE17_HOST_KEY_TOKEN_CANARY"
		configCanary := "ISSUE17_HOST_KEY_CONFIG_CANARY"
		inventoryCanary := "ISSUE17_HOST_KEY_DECRYPTED_INVENTORY_CANARY"
		cli.SaveVault(t, &config.Vault{
			Connections: []config.Connection{
				server.Connection("host-key", password),
				{Name: inventoryCanary, Host: "192.0.2.55", Port: 22, User: "runner", Password: "ISSUE17_HOST_KEY_UNRELATED_PASSWORD_CANARY"},
			},
			Keys: []config.SSHKey{{Name: "host-key-unrelated", PrivateKey: privateKey}},
		})
		cli.writeConfigFile(t, "cloud.json", []byte(`{"server":"https://`+configCanary+`.invalid","token":"`+token+`"`))
		canaries := map[string]string{
			"password":            password,
			"private_key":         privateKey,
			"token":               token,
			"configuration":       configCanary,
			"decrypted_inventory": inventoryCanary,
			"passphrase":          cli.passphrase,
		}

		hostKeyUnknownContract := reviewedCompiledMachineContract(t, "host_key_unknown")
		unknown := cli.RunReviewed(t, hostKeyUnknownContract, nil, nil)
		assertNoCompiledCanaryLeak(t, unknown, canaries)
		assertCompiledMachineContract(t, unknown, hostKeyUnknownContract)

		inspection := cli.Run(t, "sshctl", nil, "--offline", "--json", "host-key", "inspect", "host-key")
		assertNoCompiledCanaryLeak(t, inspection, canaries)
		inspectionValue := assertCompiledJSONSuccess(t, inspection)
		assertCompiledStringField(t, inspectionValue, "status", "new", inspection)
		fingerprint, ok := inspectionValue["observed_fingerprint"].(string)
		if !ok || !strings.HasPrefix(fingerprint, "SHA256:") {
			t.Fatalf("inspection fingerprint contract failed; output=%s", compiledOutputIdentity(inspection))
		}

		rejected := cli.Run(
			t,
			"sshctl",
			nil,
			"--offline", "--json", "host-key", "accept", "host-key",
			"--fingerprint", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "--yes",
		)
		assertNoCompiledCanaryLeak(t, rejected, canaries)
		assertCompiledMachineContract(t, rejected, compiledMachineContract{
			OK: false, Error: "fingerprint_mismatch", Stage: "host_key", JSONExit: 1, ProcessExit: 1,
			Hint:   "compare the fingerprint through a trusted channel; do not accept an unexpected key",
			Absent: []string{"alias", "candidates"},
		})
		assertCompiledKnownHostsFileAbsent(t, cli)

		stillUnknown := cli.RunReviewed(t, hostKeyUnknownContract, nil, nil)
		assertNoCompiledCanaryLeak(t, stillUnknown, canaries)
		assertCompiledMachineContract(t, stillUnknown, hostKeyUnknownContract)

		accepted := cli.Run(t, "sshctl", nil, "--offline", "--json", "host-key", "accept", "host-key", "--fingerprint", fingerprint, "--yes")
		assertNoCompiledCanaryLeak(t, accepted, canaries)
		acceptedValue := assertCompiledJSONSuccess(t, accepted)
		assertCompiledStringField(t, acceptedValue, "status", "trusted", accepted)
		if value, ok := acceptedValue["accepted"].(bool); !ok || !value {
			t.Fatalf("accepted = %v, want true; output=%s", acceptedValue["accepted"], compiledOutputIdentity(accepted))
		}

		trustedRun := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "host-key", "--argv", "true")
		assertNoCompiledCanaryLeak(t, trustedRun, canaries)
		assertCompiledJSONSuccess(t, trustedRun)
	})

	t.Run("dial refusal is distinct from remote exit", func(t *testing.T) {
		refused := newCompiledRefusedTCPPort(t)
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{
			Name: "refused", Host: refused.host, Port: refused.port, User: "runner", Password: "ISSUE17_DIAL_PASSWORD_CANARY",
		}}})
		contractName := "dial_refused"
		if runtime.GOOS == "windows" {
			contractName = "dial_refused_windows"
		}
		contract := reviewedCompiledMachineContract(t, contractName)
		result := cli.RunReviewed(t, contract, nil, nil)
		assertNoCompiledCanaryLeak(t, result, map[string]string{"password": "ISSUE17_DIAL_PASSWORD_CANARY"})
		assertCompiledMachineContract(t, result, contract)
	})

	t.Run("authentication failure remains classified at dial stage", func(t *testing.T) {
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: "ISSUE17_EXPECTED_AUTH_CANARY"})
		cli.TrustSSHHost(t, server)
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{
			server.Connection("auth", "ISSUE17_REJECTED_AUTH_CANARY"),
		}})
		contract := reviewedCompiledMachineContract(t, "auth_failed")
		result := cli.RunReviewed(t, contract, nil, nil)
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"expected_password": "ISSUE17_EXPECTED_AUTH_CANARY",
			"rejected_password": "ISSUE17_REJECTED_AUTH_CANARY",
		})
		assertCompiledMachineContract(t, result, contract)
	})

	t.Run("session failure retains its own class", func(t *testing.T) {
		password := "ISSUE17_SESSION_PASSWORD_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password, RejectSessions: true})
		cli.TrustSSHHost(t, server)
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("session", password)}})
		contract := reviewedCompiledMachineContract(t, "session_failed")
		result := cli.RunReviewed(t, contract, nil, nil)
		assertNoCompiledCanaryLeak(t, result, map[string]string{"password": password})
		assertCompiledMachineContract(t, result, contract)
	})

	t.Run("remote process exit 255 is not a connection failure", func(t *testing.T) {
		password := "ISSUE17_REMOTE_EXIT_PASSWORD_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
		cli.TrustSSHHost(t, server)
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("remote-255", password)}})
		contract := reviewedCompiledMachineContract(t, "remote_exit_255")
		result := cli.RunReviewed(t, contract, nil, nil)
		assertNoCompiledCanaryLeak(t, result, map[string]string{"password": password})
		assertCompiledMachineContract(t, result, contract)
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
		if !compiledJSONExitEquals(invalid["exit"], 2) {
			t.Fatalf("stream decode JSON exit = %v, want 2; output=%s", invalid["exit"], compiledOutputIdentity(result))
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
		contract := reviewedCompiledMachineContract(t, "stream_refresh_failed")
		result := streamCLI.RunReviewed(t, contract, []byte("[\"true\"]\n[\"true\"]\n"), nil)
		assertNoCompiledCanaryLeak(t, result, map[string]string{"token": "ISSUE17_STREAM_REFRESH_TOKEN_CANARY"})
		assertCompiledMachineContract(t, result, contract)
		if lines := nonEmptyCompiledLines(result.Stdout); len(lines) != 1 {
			t.Fatalf("stream refresh line count = %d, want 1; output=%s", len(lines), compiledOutputIdentity(result))
		}
		if got := sync.MethodCount("HEAD"); got != 2 {
			t.Fatalf("stream refresh HEAD count = %d, want 2", got)
		}
	})

	t.Run("compiled mutation IDs remain stable and scoped push stays isolated", func(t *testing.T) {
		mutationCLI := newCompiledCLIHarness(t)
		statusPassword := "ISSUE17_STATUS_UNRELATED_PASSWORD_CANARY"
		statusPrivateKey := "ISSUE17_STATUS_PRIVATE_KEY_CANARY"
		statusToken := "ISSUE17_STATUS_TOKEN_CANARY"
		statusConfig := "ISSUE17_STATUS_CONFIG_CANARY"
		statusInventory := "ISSUE17_STATUS_DECRYPTED_INVENTORY_CANARY"
		statusKey := config.SSHKey{Name: "status-key", PrivateKey: statusPrivateKey}
		statusKeyConnection := config.Connection{
			Name: "status-key-host", Host: "192.0.2.68", Port: 2268, User: "key-user",
			KeyName: statusKey.Name, Group: "status-key-group",
		}
		statusPasswordConnection := config.Connection{
			Name: "status-password-host", Host: "192.0.2.69", Port: 2269, User: "password-user",
			Password: statusPassword, Group: statusInventory,
		}
		mutationCLI.SaveVault(t, &config.Vault{
			Connections: []config.Connection{statusKeyConnection, statusPasswordConnection},
			Keys:        []config.SSHKey{statusKey},
		})
		mutationCLI.writeConfigFile(
			t,
			"cloud.json",
			[]byte(`{"server":"https://`+statusConfig+`.invalid","token":"`+statusToken+`"}`),
		)
		alphaPassword := filepath.Join(mutationCLI.temp, "alpha.password")
		betaPassword := filepath.Join(mutationCLI.temp, "beta.password")
		if err := os.WriteFile(alphaPassword, []byte("ISSUE17_ALPHA_PASSWORD_CANARY\n"), 0o600); err != nil {
			t.Fatalf("write alpha password fixture: %v", err)
		}
		if err := os.WriteFile(betaPassword, []byte("ISSUE17_BETA_PASSWORD_CANARY\n"), 0o600); err != nil {
			t.Fatalf("write beta password fixture: %v", err)
		}
		alpha := mutationCLI.Run(t, "sshctl", nil, "--json", "host", "add", "alpha", "--host", "192.0.2.70", "--user", "runner", "--password-file", alphaPassword, "--offline")
		assertNoCompiledCanaryLeak(t, alpha, map[string]string{
			"password":   "ISSUE17_ALPHA_PASSWORD_CANARY",
			"passphrase": mutationCLI.passphrase,
		})
		alphaValue := assertCompiledJSONSuccess(t, alpha)
		alphaID := compiledTransactionID(t, alphaValue, alpha)
		requestCanary := "ISSUE17_STATUS_REQUEST_BODY_CANARY"
		betaRequest, err := json.Marshal(map[string]any{
			"version": 1, "op": "host.add", "alias": "beta",
			"host": map[string]any{
				"address": "192.0.2.71", "user": "runner", "group": requestCanary,
				"password_file": betaPassword, "offline": true, "verify": false,
			},
		})
		if err != nil {
			t.Fatalf("marshal status request canary fixture: %v", err)
		}
		beta := mutationCLI.Run(t, "sshctl", betaRequest, "request", "-")
		assertNoCompiledCanaryLeak(t, beta, map[string]string{
			"password":   "ISSUE17_BETA_PASSWORD_CANARY",
			"passphrase": mutationCLI.passphrase,
		})
		betaValue := assertCompiledJSONSuccess(t, beta)
		betaID := compiledTransactionID(t, betaValue, beta)
		if alphaID == betaID {
			t.Fatal("compiled host mutations reused a transaction ID")
		}

		var pendingTransactions []pendingMutationView
		for i := 0; i < 2; i++ {
			status := mutationCLI.Run(t, "sshctl", nil, "--offline", "--json", "status")
			assertNoCompiledCanaryLeak(t, status, map[string]string{
				"alpha_password":      "ISSUE17_ALPHA_PASSWORD_CANARY",
				"beta_password":       "ISSUE17_BETA_PASSWORD_CANARY",
				"unrelated_password":  statusPassword,
				"private_key":         statusPrivateKey,
				"token":               statusToken,
				"configuration":       statusConfig,
				"request":             requestCanary,
				"request_body":        string(betaRequest),
				"decrypted_inventory": statusInventory,
				"passphrase":          mutationCLI.passphrase,
			})
			value := assertCompiledJSONSuccess(t, status)
			got := compiledPendingTransactionViews(t, value, status)
			if i == 0 {
				pendingTransactions = got
			}
			if !reflect.DeepEqual(got, pendingTransactions) ||
				len(got) != 2 ||
				got[0].ID != alphaID || got[0].Alias != "alpha" || got[0].Operation != "created" ||
				got[1].ID != betaID || got[1].Alias != "beta" || got[1].Operation != "created" {
				t.Fatalf("pending transaction public views do not retain two stable ordered mutations")
			}
		}

		sync := newCompiledSyncFixture(t)
		sync.SetRemote(t, nil, "scoped-push")
		mutationCLI.SaveCloud(t, sync.URL(), "ISSUE17_SCOPED_PUSH_TOKEN_CANARY")
		pushed := mutationCLI.Run(t, "sshctl", nil, "--json", "push", "--only", betaID)
		pushedValue := assertCompiledJSONSuccess(t, pushed)
		assertCompiledStringField(t, pushedValue, "transaction_id", betaID, pushed)
		assertNoCompiledCanaryLeak(t, pushed, map[string]string{
			"alpha_password":      "ISSUE17_ALPHA_PASSWORD_CANARY",
			"beta_password":       "ISSUE17_BETA_PASSWORD_CANARY",
			"unrelated_password":  statusPassword,
			"private_key":         statusPrivateKey,
			"decrypted_inventory": statusInventory,
			"token":               "ISSUE17_SCOPED_PUSH_TOKEN_CANARY",
			"passphrase":          mutationCLI.passphrase,
		})
		alphaConnection := config.Connection{
			Name: "alpha", Host: "192.0.2.70", Port: 22, User: "runner", Password: "ISSUE17_ALPHA_PASSWORD_CANARY",
		}
		betaConnection := config.Connection{
			Name: "beta", Host: "192.0.2.71", Port: 22, User: "runner",
			Password: "ISSUE17_BETA_PASSWORD_CANARY", Group: requestCanary,
		}
		assertCompiledVaultIdentity(
			t,
			decodeCompiledVaultIdentity(t, sync.UploadedBlob(), mutationCLI.passphrase),
			&config.Vault{
				Connections: []config.Connection{betaConnection, statusKeyConnection, statusPasswordConnection},
				Keys:        []config.SSHKey{statusKey},
			},
		)
		assertCompiledVaultIdentity(t, mutationCLI.LoadVaultIdentity(t), &config.Vault{
			Connections: []config.Connection{statusKeyConnection, statusPasswordConnection, alphaConnection, betaConnection},
			Keys:        []config.SSHKey{statusKey},
			PendingBase: &config.InventorySnapshot{
				Connections: []config.Connection{betaConnection, statusKeyConnection, statusPasswordConnection},
				Keys:        []config.SSHKey{statusKey},
			},
			PendingMutations: []config.PendingMutation{{
				ID: pendingTransactions[0].ID, Alias: pendingTransactions[0].Alias,
				Operation: pendingTransactions[0].Operation, CreatedAt: pendingTransactions[0].CreatedAt,
				After: &alphaConnection, KeysBefore: []config.SSHKey{statusKey}, KeysAfter: []config.SSHKey{statusKey},
			}},
		})
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
		assertCompiledVaultIdentity(
			t,
			decodeCompiledVaultIdentity(t, sync.UploadedBlob(), cli.passphrase),
			&config.Vault{Connections: []config.Connection{beta}},
		)
		assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), &config.Vault{
			Connections: []config.Connection{alpha, beta},
			Keys:        []config.SSHKey{key},
			PendingBase: &config.InventorySnapshot{Connections: []config.Connection{beta}},
			PendingMutations: []config.PendingMutation{{
				ID: "tx_alpha", Alias: alpha.Name, Operation: "created", CreatedAt: "2026-01-01T00:00:00Z",
				After: &alpha, KeysAfter: []config.SSHKey{key},
			}},
		})

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
		result := cli.RunWithHeldOpenStdin(t, "sshctl", "--json", "run", "missing", "--stream", "--refresh=0")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"token":               "ISSUE17_STREAM_TOKEN_CANARY",
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
			removedPassword := "ISSUE17_LEGACY_REMOVE_PASSWORD_CANARY"
			preservedPassword := "ISSUE17_LEGACY_PRESERVED_PASSWORD_CANARY"
			preservedPrivateKey := "ISSUE17_LEGACY_PRESERVED_PRIVATE_KEY_CANARY"
			removedConnection := config.Connection{
				Name: "legacy-remove", Host: "192.0.2.50", Port: 2200, User: "removed-user",
				Password: removedPassword, Group: "removed-group",
			}
			preservedConnection := config.Connection{
				Name: "legacy-preserved", Host: "192.0.2.51", Port: 2201, User: "preserved-user",
				Password: preservedPassword, Group: "preserved-group",
			}
			preservedKeyConnection := config.Connection{
				Name: "legacy-key-reference", Host: "192.0.2.52", Port: 2202, User: "key-user",
				KeyName: "preserved-key", Group: "key-group",
			}
			preservedKey := config.SSHKey{Name: "preserved-key", PrivateKey: preservedPrivateKey}
			pendingBase, pendingMutations := compiledLegacyPendingLedger()
			want := &config.Vault{
				Connections: []config.Connection{preservedConnection, preservedKeyConnection},
				Keys:        []config.SSHKey{preservedKey},
				PendingBase: pendingBase, PendingMutations: pendingMutations,
			}
			cli.SaveVault(t, &config.Vault{
				Connections: []config.Connection{removedConnection, preservedConnection, preservedKeyConnection},
				Keys:        []config.SSHKey{preservedKey},
				PendingBase: pendingBase, PendingMutations: pendingMutations,
			})
			cli.SaveCloud(t, sync.URL(), "ISSUE17_LEGACY_REMOVE_TOKEN_CANARY")
			result := cli.Run(t, "ssm", nil, "remove", "legacy-remove")
			assertCompiledHumanSuccess(t, result, "legacy-remove")
			assertNoCompiledCanaryLeak(t, result, map[string]string{
				"removed_password":           removedPassword,
				"preserved_password":         preservedPassword,
				"private_key":                preservedPrivateKey,
				"ledger_base_password":       "ISSUE17_LEGACY_LEDGER_BASE_PASSWORD_CANARY",
				"ledger_updated_password":    "ISSUE17_LEGACY_LEDGER_UPDATED_PASSWORD_CANARY",
				"ledger_base_private_key":    "ISSUE17_LEGACY_LEDGER_BASE_PRIVATE_KEY_CANARY",
				"ledger_pending_private_key": "ISSUE17_LEGACY_LEDGER_PENDING_PRIVATE_KEY_CANARY",
				"token":                      "ISSUE17_LEGACY_REMOVE_TOKEN_CANARY",
				"passphrase":                 cli.passphrase,
			})
			if got := sync.MethodCount("PUT"); got != 1 {
				t.Fatalf("legacy remove PUT count = %d, want 1", got)
			}
			assertCompiledEncryptedPublication(t, sync.UploadedBlob(), cli.passphrase, map[string]string{
				"removed_password":           removedPassword,
				"preserved_password":         preservedPassword,
				"private_key":                preservedPrivateKey,
				"ledger_base_password":       "ISSUE17_LEGACY_LEDGER_BASE_PASSWORD_CANARY",
				"ledger_updated_password":    "ISSUE17_LEGACY_LEDGER_UPDATED_PASSWORD_CANARY",
				"ledger_base_private_key":    "ISSUE17_LEGACY_LEDGER_BASE_PRIVATE_KEY_CANARY",
				"ledger_pending_private_key": "ISSUE17_LEGACY_LEDGER_PENDING_PRIVATE_KEY_CANARY",
			}, want)
			assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), want)
		})

		t.Run("legacy key remove auto-pushes without a transaction", func(t *testing.T) {
			cli := newCompiledCLIHarness(t)
			sync := newCompiledSyncFixture(t)
			sync.SetRemote(t, nil, "legacy-key-remove")
			removedKey := "ISSUE17_LEGACY_PRIVATE_KEY_CANARY"
			preservedKey := "ISSUE17_LEGACY_UNRELATED_PRIVATE_KEY_CANARY"
			password := "ISSUE17_LEGACY_UNRELATED_PASSWORD_CANARY"
			connection := config.Connection{
				Name: "legacy-unrelated", Host: "192.0.2.53", Port: 2203, User: "unrelated-user",
				Password: password, KeyName: "unrelated-key", Group: "unrelated-group",
			}
			unrelatedKey := config.SSHKey{Name: "unrelated-key", PrivateKey: preservedKey}
			pendingBase, pendingMutations := compiledLegacyPendingLedger()
			want := &config.Vault{
				Connections: []config.Connection{connection},
				Keys:        []config.SSHKey{unrelatedKey},
				PendingBase: pendingBase, PendingMutations: pendingMutations,
			}
			cli.SaveVault(t, &config.Vault{
				Connections: []config.Connection{connection},
				Keys: []config.SSHKey{
					{Name: "legacy-key", PrivateKey: removedKey},
					unrelatedKey,
				},
				PendingBase: pendingBase, PendingMutations: pendingMutations,
			})
			cli.SaveCloud(t, sync.URL(), "ISSUE17_LEGACY_KEY_TOKEN_CANARY")
			result := cli.Run(t, "ssm", nil, "keys", "remove", "legacy-key")
			assertCompiledHumanSuccess(t, result, "legacy-key")
			assertNoCompiledCanaryLeak(t, result, map[string]string{
				"removed_private_key":        removedKey,
				"preserved_private_key":      preservedKey,
				"password":                   password,
				"ledger_base_password":       "ISSUE17_LEGACY_LEDGER_BASE_PASSWORD_CANARY",
				"ledger_updated_password":    "ISSUE17_LEGACY_LEDGER_UPDATED_PASSWORD_CANARY",
				"ledger_base_private_key":    "ISSUE17_LEGACY_LEDGER_BASE_PRIVATE_KEY_CANARY",
				"ledger_pending_private_key": "ISSUE17_LEGACY_LEDGER_PENDING_PRIVATE_KEY_CANARY",
				"token":                      "ISSUE17_LEGACY_KEY_TOKEN_CANARY",
				"passphrase":                 cli.passphrase,
			})
			if got := sync.MethodCount("PUT"); got != 1 {
				t.Fatalf("legacy key remove PUT count = %d, want 1", got)
			}
			assertCompiledEncryptedPublication(t, sync.UploadedBlob(), cli.passphrase, map[string]string{
				"removed_private_key":        removedKey,
				"preserved_private_key":      preservedKey,
				"password":                   password,
				"ledger_base_password":       "ISSUE17_LEGACY_LEDGER_BASE_PASSWORD_CANARY",
				"ledger_updated_password":    "ISSUE17_LEGACY_LEDGER_UPDATED_PASSWORD_CANARY",
				"ledger_base_private_key":    "ISSUE17_LEGACY_LEDGER_BASE_PRIVATE_KEY_CANARY",
				"ledger_pending_private_key": "ISSUE17_LEGACY_LEDGER_PENDING_PRIVATE_KEY_CANARY",
			}, want)
			assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), want)
		})

		for _, mode := range []string{"merge", "replace"} {
			t.Run("import "+mode+" saves without publication or transaction", func(t *testing.T) {
				cli := newCompiledCLIHarness(t)
				sync := newCompiledSyncFixture(t)
				starting := compiledLegacyImportStartingVault()
				cli.SaveVault(t, starting)
				token := "ISSUE17_IMPORT_TOKEN_CANARY"
				cli.SaveCloud(t, sync.URL(), token)
				importPath := filepath.Join(cli.temp, "import-"+mode+".json")
				importPassword := "ISSUE17_IMPORT_PASSWORD_CANARY"
				importBody := `[{"alias":"imported-` + mode + `","host":"192.0.2.60","port":22,"user":"runner","auth_type":"password","password":"` + importPassword + `"}]`
				if err := os.WriteFile(importPath, []byte(importBody), 0o600); err != nil {
					t.Fatalf("write import fixture: %v", err)
				}
				args := []string{"--json", "import-json", importPath, "--" + mode}
				if mode == "replace" {
					args = append(args, "--yes")
				}
				result := cli.Run(t, "ssm", nil, args...)
				assertNoCompiledCanaryLeak(t, result, map[string]string{
					"imported_password":    importPassword,
					"base_password":        "ISSUE17_IMPORT_BASE_PASSWORD_CANARY",
					"existing_password":    "ISSUE17_IMPORT_EXISTING_PASSWORD_CANARY",
					"base_private_key":     "ISSUE17_IMPORT_BASE_PRIVATE_KEY_CANARY",
					"existing_private_key": "ISSUE17_IMPORT_EXISTING_PRIVATE_KEY_CANARY",
					"token":                token,
					"passphrase":           cli.passphrase,
				})
				action := mode + "d"
				assertCompiledExactMachineOutput(t, result, "{\n  \"ok\": true,\n  \"action\": \""+action+"\",\n  \"connections\": 1,\n  \"keys\": 0\n}\n")
				if got := sync.MethodCount("PUT"); got != 0 {
					t.Fatalf("legacy import %s PUT count = %d, want 0", mode, got)
				}
				imported := config.Connection{
					Name: "imported-" + mode, Host: "192.0.2.60", Port: 22, User: "runner",
					Password: importPassword, Group: "imported",
				}
				want := starting
				if mode == "merge" {
					want.Connections = append(want.Connections, imported)
					want.PendingBase = nil
					want.PendingMutations = nil
				} else {
					want.Connections = []config.Connection{imported}
					want.Keys = nil
				}
				assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), want)
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
				password := "ISSUE17_EMPTY_LEDGER_PASSWORD_CANARY"
				privateKey := "ISSUE17_EMPTY_LEDGER_PRIVATE_KEY_CANARY"
				want := &config.Vault{
					Connections: []config.Connection{
						{
							Name: "empty-ledger-password", Host: "192.0.2.54", Port: 2204, User: "password-user",
							Password: password, Group: "password-group",
						},
						{
							Name: "empty-ledger-key-reference", Host: "192.0.2.55", Port: 2205, User: "key-user",
							KeyName: "empty-ledger-key", Group: "key-group",
						},
					},
					Keys: []config.SSHKey{{Name: "empty-ledger-key", PrivateKey: privateKey}},
				}
				cli.SaveVault(t, want)
				cli.SaveCloud(t, sync.URL(), "ISSUE17_EMPTY_LEDGER_TOKEN_CANARY")
				result := cli.Run(t, "sshctl", nil, args...)
				value := assertCompiledJSONSuccess(t, result)
				assertCompiledStringField(t, value, "scope", "all", result)
				assertNoCompiledCanaryLeak(t, result, map[string]string{
					"password":    password,
					"private_key": privateKey,
					"token":       "ISSUE17_EMPTY_LEDGER_TOKEN_CANARY",
				})
				if got := sync.MethodCount("PUT"); got != 1 {
					t.Fatalf("%s push PUT count = %d, want 1", name, got)
				}
				assertCompiledEncryptedPublication(t, sync.UploadedBlob(), cli.passphrase, map[string]string{
					"password":    password,
					"private_key": privateKey,
				}, want)
				assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), want)
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
		privateKey := "ISSUE17_TRANSFER_PRIVATE_KEY_CANARY"
		inventoryCanary := "ISSUE17_DECRYPTED_INVENTORY_CANARY"
		configCanary := "ISSUE17_TRANSFER_CONFIG_CANARY"
		tokenCanary := "ISSUE17_TRANSFER_TOKEN_CANARY"
		cli.SaveVault(t, &config.Vault{
			Connections: []config.Connection{
				server.Connection("transfer-live", password),
				{Name: inventoryCanary, Host: "192.0.2.54", Port: 22, User: "runner", Password: "ISSUE17_UNRELATED_INVENTORY_PASSWORD_CANARY"},
			},
			Keys: []config.SSHKey{{Name: "unrelated-key", PrivateKey: privateKey}},
		})
		cli.writeConfigFile(t, "cloud.json", []byte(`{"server":"https://`+configCanary+`.invalid","token":"`+tokenCanary+`"`))
		secretCanaries := map[string]string{
			"password":            password,
			"private_key":         privateKey,
			"file_content":        "ISSUE17_TRANSFER_FILE_CONTENT_CANARY",
			"directory_content":   "ISSUE17_TRANSFER_DIRECTORY_CONTENT_CANARY",
			"token":               tokenCanary,
			"configuration":       configCanary,
			"decrypted_inventory": inventoryCanary,
		}

		localFile := filepath.Join(cli.temp, "artifact.bin")
		fileBody := []byte("ISSUE17_TRANSFER_FILE_CONTENT_CANARY\n")
		if err := os.WriteFile(localFile, fileBody, 0o600); err != nil {
			t.Fatalf("write regular transfer fixture: %v", err)
		}
		remoteRoot := t.TempDir()
		remoteFile := filepath.Join(remoteRoot, "direct-file.bin")
		directFile := cli.Run(t, "sshctl", nil, "--offline", "--json", "put", "transfer-live", localFile, remoteFile, "--resume=v1", "--sha256")
		assertCompiledTransferSnapshot(t, directFile, map[string]any{
			"action": "put", "alias": "transfer-live", "local": localFile, "remote": remoteFile,
			"ok": true, "stage": "complete", "bytes_sent": len(fileBody),
			"integrity": "sha256_verified", "local_sha256": "3d8d6a88369017fda7fd16f16b3536c0c583cd040f9b6b865c0de9eaa5e021e0",
			"remote_sha256": "3d8d6a88369017fda7fd16f16b3536c0c583cd040f9b6b865c0de9eaa5e021e0",
			"atomic":        true, "resume": "started",
		})
		assertNoCompiledCanaryLeak(t, directFile, secretCanaries)

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
		assertCompiledTransferSnapshot(t, requestFile, map[string]any{
			"action": "put", "alias": "transfer-live", "local": localFile, "remote": requestRemoteFile,
			"ok": true, "stage": "complete", "bytes_sent": len(fileBody),
			"integrity": "sha256_verified", "local_sha256": "3d8d6a88369017fda7fd16f16b3536c0c583cd040f9b6b865c0de9eaa5e021e0",
			"remote_sha256": "3d8d6a88369017fda7fd16f16b3536c0c583cd040f9b6b865c0de9eaa5e021e0",
			"atomic":        true, "resume": "started",
		})
		assertNoCompiledCanaryLeak(t, requestFile, mergeCompiledCanaries(secretCanaries, "request", string(requestBody)))

		localDirectory := filepath.Join(cli.temp, "directory")
		if err := os.Mkdir(localDirectory, 0o700); err != nil {
			t.Fatalf("create directory transfer fixture: %v", err)
		}
		directoryBody := []byte("ISSUE17_TRANSFER_DIRECTORY_CONTENT_CANARY\n")
		if err := os.WriteFile(filepath.Join(localDirectory, "item.txt"), directoryBody, 0o600); err != nil {
			t.Fatalf("write directory transfer fixture: %v", err)
		}
		remoteDirectory := filepath.Join(remoteRoot, "direct-directory")
		directDirectory := cli.Run(t, "sshctl", nil, "--offline", "--json", "put", "transfer-live", localDirectory, remoteDirectory)
		assertCompiledTransferSnapshot(t, directDirectory, map[string]any{
			"action": "put", "alias": "transfer-live", "local": localDirectory, "remote": remoteDirectory,
			"ok": true, "stage": "complete", "bytes_sent": 0,
			"integrity": "not_available", "atomic": false, "resume": "unsupported",
		})
		assertNoCompiledCanaryLeak(t, directDirectory, secretCanaries)

		requestRemoteDirectory := filepath.Join(remoteRoot, "request-directory")
		requestBody, err = json.Marshal(map[string]any{
			"version": 1, "op": "put", "alias": "transfer-live",
			"local_path": localDirectory, "remote_path": requestRemoteDirectory,
		})
		if err != nil {
			t.Fatalf("marshal directory transfer request fixture: %v", err)
		}
		requestDirectory := cli.Run(t, "sshctl", requestBody, "request", "-")
		assertCompiledTransferSnapshot(t, requestDirectory, map[string]any{
			"action": "put", "alias": "transfer-live", "local": localDirectory, "remote": requestRemoteDirectory,
			"ok": true, "stage": "complete", "bytes_sent": 0,
			"integrity": "not_available", "atomic": false, "resume": "unsupported",
		})
		assertNoCompiledCanaryLeak(t, requestDirectory, mergeCompiledCanaries(secretCanaries, "request", string(requestBody)))

		downloadedFile := filepath.Join(cli.temp, "downloaded-file.bin")
		getFile := cli.Run(t, "sshctl", nil, "--offline", "--json", "get", "transfer-live", remoteFile, downloadedFile)
		assertCompiledTransferSnapshot(t, getFile, map[string]any{
			"ok": true, "action": "get", "alias": "transfer-live", "remote": remoteFile, "local": downloadedFile,
		})
		assertNoCompiledCanaryLeak(t, getFile, secretCanaries)

		downloadedDirectory := filepath.Join(cli.temp, "downloaded-directory")
		getDirectory := cli.Run(t, "sshctl", nil, "--offline", "--json", "get", "transfer-live", remoteDirectory, downloadedDirectory)
		assertCompiledTransferSnapshot(t, getDirectory, map[string]any{
			"ok": true, "action": "get", "alias": "transfer-live", "remote": remoteDirectory, "local": downloadedDirectory,
		})
		assertNoCompiledCanaryLeak(t, getDirectory, secretCanaries)

		for _, requestGet := range []struct {
			name       string
			remotePath string
			localPath  string
		}{
			{name: "file", remotePath: requestRemoteFile, localPath: filepath.Join(cli.temp, "request-downloaded-file.bin")},
			{name: "directory", remotePath: requestRemoteDirectory, localPath: filepath.Join(cli.temp, "request-downloaded-directory")},
		} {
			t.Run("request-v1 get "+requestGet.name+" remains unsupported", func(t *testing.T) {
				body, err := json.Marshal(map[string]any{
					"version": 1, "op": "get", "alias": "transfer-live",
					"remote_path": requestGet.remotePath, "local_path": requestGet.localPath,
				})
				if err != nil {
					t.Fatalf("marshal request-v1 get fixture: %v", err)
				}
				result := cli.Run(t, "sshctl", body, "request", "-")
				assertCompiledTransferSnapshot(t, result, map[string]any{
					"ok": false, "error": "invalid_request", "message": `unsupported request op "get"`,
					"hint": "use run, plan, check, doctor, put, or host.list/search/show/add/update/upsert/remove",
					"exit": 2, "alias": "transfer-live",
				})
				assertNoCompiledCanaryLeak(t, result, mergeCompiledCanaries(secretCanaries, "request", string(body)))
			})
		}

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

		assertNoCompiledCanaryLeak(t, failed, secretCanaries)
	})

	t.Run("BC-8 latest automatic replacement crosses the current major", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		cli.SaveVault(t, &config.Vault{})
		replacement := []byte("ISSUE17_CROSS_MAJOR_REPLACEMENT_FIXTURE\n")
		compiledUpdateServer.ConfigureRelease("v2.0.0", replacement)
		before := loadCompiledFileIdentity(t, cli.paths["ssm"])
		result := cli.RunWithEnv(t, "ssm", nil, map[string]string{"SSM_UPDATE_REPO": "fixture/repo"}, "list", "--json")
		assertNoCompiledCanaryLeak(t, result, map[string]string{"replacement": string(replacement)})
		assertCompiledAutomaticUpdateOutcome(t, result, cli.paths["ssm"], before, replacement)
		assertCompiledUpdateRequests(t, compiledUpdateServer.RequestPaths(), "v2.0.0")
	})

	t.Run("BC-9 an adjacent checksum alone authorizes replacement", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		cli.SaveVault(t, &config.Vault{})
		replacement := []byte("ISSUE17_CHECKSUM_ONLY_REPLACEMENT_FIXTURE\n")
		compiledUpdateServer.ConfigureRelease("v1.5.0", replacement)
		cli.writeConfigFile(t, ".update-available", []byte("-\n"+fmt.Sprint(time.Now().Unix())))
		before := loadCompiledFileIdentity(t, cli.paths["ssm"])
		result := cli.RunWithEnv(t, "ssm", nil, map[string]string{"SSM_UPDATE_REPO": "fixture/repo"}, "update")
		assertNoCompiledCanaryLeak(t, result, map[string]string{"replacement": string(replacement)})
		assertCompiledExplicitUpdateOutcome(t, result, cli.paths["ssm"], before, replacement, "v1.5.0")
		paths := compiledUpdateServer.RequestPaths()
		assertCompiledUpdateRequests(t, paths, "v1.5.0")
	})

	t.Run("BC-10 make check is a mutating format-lint-build subset", func(t *testing.T) {
		makefile, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
		if err != nil {
			t.Fatalf("read Makefile for check membership: %v", err)
		}
		lines, err := compiledMakeTargetCommands(makefile, "check")
		if err != nil {
			t.Fatalf("inspect make check membership: %v", err)
		}
		want := []string{
			"gofmt -w .",
			"golangci-lint run ./...",
			`go build -ldflags="-s -w -X main.version=dev" -o ssm ./cmd/ssm`,
		}
		if !reflect.DeepEqual(lines, want) {
			t.Fatalf("make check command count = %d, want %d", len(lines), len(want))
		}
		for _, forbidden := range []string{"go test", "go vet", "-race", "govulncheck"} {
			if strings.Contains(strings.Join(lines, "\n"), forbidden) {
				t.Fatalf("make check unexpectedly includes %q", forbidden)
			}
		}

		scratch := t.TempDir()
		unformatted := []byte("package fixture\nfunc value( )int{return 1}\n")
		sourcePath := filepath.Join(scratch, "fixture.go")
		if err := os.WriteFile(sourcePath, unformatted, 0o600); err != nil {
			t.Fatalf("write unformatted Go fixture: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), compiledCLISubprocessTimeout)
		defer cancel()
		format := exec.CommandContext(ctx, "gofmt", "-w", sourcePath)
		if output, err := format.CombinedOutput(); err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatalf("isolated gofmt exceeded subprocess deadline %s", compiledCLISubprocessTimeout)
			}
			t.Fatalf("run isolated gofmt: %v; bytes=%d sha256=%x", err, len(output), sha256.Sum256(output))
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
