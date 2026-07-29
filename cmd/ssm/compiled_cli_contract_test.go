package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
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
	"ssm/internal/machinecontract"
	securevault "ssm/internal/vault"
)

var compiledCLIPaths map[string]string

const compiledCLISubprocessTimeout = 15 * time.Second
const compiledCLIBuildTimeout = 2 * time.Minute
const reviewedCompiledMachineContractPath = "testdata/compiled_contracts/v1_failure_matrix.json"

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
	Direction       string   `json:"direction,omitempty"`
	Kind            string   `json:"kind,omitempty"`
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
	if os.Getenv("SSM_TEST_TAR_HELPER") == "1" {
		_, _ = io.WriteString(os.Stdout, "compiled fixture invalid tar payload\n")
		_, _ = io.WriteString(os.Stderr, "config=\"{\\\"token\\\":\\\"FALLBACK_LOCAL_TAR_DIAGNOSTIC\\\"}\"\n")
		os.Exit(31)
	}
	if os.Getenv("SSM_TEST_PUSH_HELPER") == "1" {
		os.Exit(m.Run())
	}
	os.Exit(runCompiledCLITestMain(m))
}

func TestCompiledCLIBuildArgs(t *testing.T) {
	updateLDFlags := "-X=example.test=value"
	outputPath := filepath.Join("test-output", "ssm")
	want := []string{
		"build",
		"-buildvcs=false",
		"-ldflags", updateLDFlags,
		"-o", outputPath,
		".",
	}

	if got := compiledCLIBuildArgs(updateLDFlags, outputPath); !reflect.DeepEqual(got, want) {
		t.Fatalf("compiled CLI build args = %q, want %q", got, want)
	}
}

func TestCompiledCLITestMainPushHelperBypassesBuild(t *testing.T) {
	if os.Getenv("SSM_TEST_PUSH_HELPER") == "1" {
		if compiledCLIPaths != nil {
			t.Fatal("push helper initialized compiled CLI paths")
		}
		return
	}
	if len(compiledCLIPaths) != 2 {
		t.Fatalf("normal TestMain compiled CLI path count = %d, want 2", len(compiledCLIPaths))
	}

	t.Setenv("SSM_TEST_PUSH_HELPER", "1")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCompiledCLITestMainPushHelperBypassesBuild$", "-test.count=1") //nolint:gosec // executes this test binary with a fixed test selector
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run push helper TestMain probe: %v: %s", err, output)
	}
}

func compiledCLIBuildArgs(updateLDFlags, outputPath string) []string {
	return []string{"build", "-buildvcs=false", "-ldflags", updateLDFlags, "-o", outputPath, "."}
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
	build := exec.CommandContext(ctx, "go", compiledCLIBuildArgs(updateLDFlags, ssmPath)...) //nolint:gosec // fixed Go tool receives only loopback fixture URLs and a test-owned temporary output path
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
		data, readErr := os.ReadFile(ssmPath) //nolint:gosec // path is the compiled binary in the test-owned temporary build directory
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "read compiled CLI for sshctl alias: %v\n", readErr)
			return 1
		}
		info, statErr := os.Stat(ssmPath)
		if statErr != nil {
			fmt.Fprintf(os.Stderr, "stat compiled CLI for sshctl alias: %v\n", statErr)
			return 1
		}
		if writeErr := os.WriteFile(sshctlPath, data, info.Mode()); writeErr != nil { //nolint:gosec // destination is constrained to the test-owned temporary build directory
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
		data, err := os.ReadFile(source) //nolint:gosec // source is selected only from TestMain's test-owned compiled binary paths
		if err != nil {
			t.Fatalf("read test-built compiled CLI %s: %v", executable, err)
		}
		info, err := os.Stat(source)
		if err != nil {
			t.Fatalf("stat test-built compiled CLI %s: %v", executable, err)
		}
		if err := os.WriteFile(destination, data, info.Mode()); err != nil { //nolint:gosec // destination is constrained to this harness's t.TempDir
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

func (h *compiledCLIHarness) TarFailureHelperDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	name := "tar"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	source := os.Args[0]
	data, err := os.ReadFile(source) //nolint:gosec // source is the running test binary used as a controlled subprocess helper
	if err != nil {
		t.Fatalf("read compiled tar helper source: %v", err)
	}
	info, err := os.Stat(source) //nolint:gosec // source is the running test binary selected by the test harness
	if err != nil {
		t.Fatalf("stat compiled tar helper source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, name), data, info.Mode()); err != nil { //nolint:gosec // destination is constrained to the test-owned temporary directory
		t.Fatalf("write compiled tar helper: %v", err)
	}
	return directory
}

func (h *compiledCLIHarness) RunWithHeldOpenStdin(t *testing.T, executable string, args ...string) compiledCLIResult {
	return h.RunWithHeldOpenStdinAndEnv(t, executable, nil, args...)
}

func (h *compiledCLIHarness) RunWithHeldOpenStdinAndEnv(t *testing.T, executable string, env map[string]string, args ...string) compiledCLIResult {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create held-open compiled CLI stdin pipe: %v", err)
	}
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()
	overrides := make(map[string]string, len(env)+1)
	for key, value := range env {
		overrides[key] = value
	}
	overrides["SSM_MASTER_PASS_FILE"] = h.passPath
	return h.runWithStdin(t, executable, reader, overrides, args...)
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

func (h *compiledCLIHarness) VaultBlob(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(h.home, ".config", "ssm", "connections.enc")
	blob, err := os.ReadFile(path) //nolint:gosec // path is fixed beneath this harness's isolated t.TempDir home
	if err != nil {
		t.Fatalf("read isolated compiled CLI encrypted vault: %v", err)
	}
	return blob
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

func compiledSafeMachineFields(stdout string) string {
	var value map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &value); err != nil {
		return "unavailable"
	}
	return fmt.Sprintf("error=%q stage=%q", value["error"], value["stage"])
}

func assertCompiledMachineContract(t *testing.T, result compiledCLIResult, want compiledMachineContract) {
	t.Helper()
	if result.ProcessExit != want.ProcessExit {
		t.Fatalf(
			"process exit = %d, want %d; fields=%s output=%s",
			result.ProcessExit,
			want.ProcessExit,
			compiledSafeMachineFields(result.Stdout),
			compiledOutputIdentity(result),
		)
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
	if want.Direction != "" {
		assertCompiledStringField(t, value, "direction", want.Direction, result)
	}
	if want.Kind != "" {
		assertCompiledStringField(t, value, "kind", want.Kind, result)
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
	data, err := os.ReadFile(reviewedCompiledMachineContractPath)
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

func assertCompiledEmptyJSONArraySuccess(t *testing.T, result compiledCLIResult) []any {
	t.Helper()
	if result.ProcessExit != 0 || result.Stderr != "" {
		t.Fatalf("compiled JSON array success process contract failed; output=%s", compiledOutputIdentity(result))
	}
	value := decodeExactlyOneJSONValue(t, result.Stdout)
	items, ok := value.([]any)
	if !ok || len(items) != 0 {
		t.Fatalf("JSON array length = %d, want 0; output=%s", len(items), compiledOutputIdentity(result))
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

func assertTwoCompiledNDJSONSuccesses(t *testing.T, result compiledCLIResult) {
	t.Helper()
	if result.ProcessExit != 0 || result.Stderr != "" {
		t.Fatalf("compiled NDJSON process contract failed; output=%s", compiledOutputIdentity(result))
	}
	lines := nonEmptyCompiledLines(result.Stdout)
	if len(lines) != 2 {
		t.Fatalf("NDJSON line count = %d, want 2; output=%s", len(lines), compiledOutputIdentity(result))
	}
	values := make([]map[string]any, len(lines))
	for i, line := range lines {
		if err := json.Unmarshal([]byte(line), &values[i]); err != nil {
			t.Fatalf("decode NDJSON line %d: %v; output=%s", i, err, compiledOutputIdentity(result))
		}
		if got, ok := values[i]["ok"].(bool); !ok || !got {
			t.Fatalf("NDJSON line %d ok = %v, want true; output=%s", i, values[i]["ok"], compiledOutputIdentity(result))
		}
	}
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
		"compiled transfer snapshot mismatch; fields=%v want=%v got=%#v normalized_want=%#v; output=%s",
		gotFields, wantFields, got, normalizedWant, compiledOutputIdentity(result),
	)
}

type compiledFileIdentity struct {
	ByteLength int
	Digest     [sha256.Size]byte
}

func loadCompiledFileIdentity(t *testing.T, path string) compiledFileIdentity {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // callers pass only compiled executable paths copied into the harness's t.TempDir
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

func assertCompiledUpdateRequests(t *testing.T, got []string, version string) {
	t.Helper()
	asset := fmt.Sprintf("ssm-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		asset += ".exe"
	}
	want := []string{
		"/repos/fixture/repo/releases",
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
	encrypted, err := os.ReadFile(path) //nolint:gosec // path is fixed beneath this harness's isolated t.TempDir home
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
		source, err := os.ReadFile(path) //nolint:gosec // path comes from the fixed two-file test-source allowlist above
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

func TestCompiledLegacyGlobalJSONFailuresPreserveFixedPointBytes(t *testing.T) {
	loginFlagUsage := "flag provided but not defined: -bad\n" +
		"Usage of login:\n" +
		"  -email string\n" +
		"    \taccount email\n" +
		"  -password-file string\n" +
		"    \tfile containing account password\n" +
		"  -server string\n" +
		"    \tsync server URL\n"
	registerFlagUsage := "flag provided but not defined: -bad\n" +
		"Usage of register:\n" +
		"  -email string\n" +
		"    \taccount email\n" +
		"  -password-file string\n" +
		"    \tfile containing account password\n" +
		"  -server string\n" +
		"    \tsync server URL\n"
	serverFlagUsage := "flag provided but not defined: -bad\n" +
		"Usage of server:\n" +
		"  -data-dir string\n" +
		"    \tsync server data directory (default \"/srv/ssm-sync\")\n" +
		"  -listen string\n" +
		"    \tlisten address (default \"127.0.0.1:8787\")\n"
	loginHelp := strings.TrimPrefix(loginFlagUsage, "flag provided but not defined: -bad\n")
	registerHelp := strings.TrimPrefix(registerFlagUsage, "flag provided but not defined: -bad\n")
	serverHelp := strings.TrimPrefix(serverFlagUsage, "flag provided but not defined: -bad\n")
	registerNoFlagsJSON := "{\n" +
		"  \"ok\": false,\n" +
		"  \"error\": \"invalid_arguments\",\n" +
		"  \"message\": \"register requires explicit flags\",\n" +
		"  \"hint\": \"use --server, --email, and --password-file\",\n" +
		"  \"exit\": 2\n" +
		"}\n"

	tests := []struct {
		name       string
		args       []string
		wantExit   int
		wantStdout string
		wantStderr string
	}{
		{
			name: "legacy remove usage stays raw despite global json", args: []string{"--json", "remove"},
			wantExit: 1, wantStdout: "Usage: ssm remove <name>\n",
		},
		{
			name: "login flag parser stays raw despite global json", args: []string{"--json", "login", "--bad"},
			wantExit: 2, wantStderr: loginFlagUsage,
		},
		{
			name: "register flag parser stays raw despite global json", args: []string{"--json", "register", "--bad"},
			wantExit: 2, wantStderr: registerFlagUsage,
		},
		{
			name:     "login email requirement stays raw despite global json",
			args:     []string{"--json", "login", "--server", "https://sync.invalid"},
			wantExit: 1, wantStderr: "Error: --email required\n",
		},
		{
			name:     "login server requirement stays raw despite global json",
			args:     []string{"--json", "login", "--email", "user@example.invalid"},
			wantExit: 1, wantStderr: "Error: --server required\n",
		},
		{
			name:     "login password file requirement stays raw despite global json",
			args:     []string{"--json", "login", "--server", "https://sync.invalid", "--email", "user@example.invalid"},
			wantExit: 1, wantStderr: "Error: --password-file required for noninteractive login\n",
		},
		{
			name:     "register password file requirement stays raw despite global json",
			args:     []string{"--json", "register", "--server", "https://sync.invalid", "--email", "user@example.invalid"},
			wantExit: 1, wantStderr: "Error: --password-file required for noninteractive register\n",
		},
		{
			name: "server flag parser stays raw despite global json", args: []string{"--json", "server", "--bad"},
			wantExit: 2, wantStderr: serverFlagUsage,
		},
		{
			name: "approved register no-args machine document remains json", args: []string{"--json", "register"},
			wantExit: 2, wantStdout: registerNoFlagsJSON,
		},
	}
	for _, help := range []struct {
		command string
		output  string
	}{
		{command: "login", output: loginHelp},
		{command: "register", output: registerHelp},
		{command: "server", output: serverHelp},
	} {
		for _, spelling := range []string{"-h", "--help"} {
			for _, globalJSON := range []bool{false, true} {
				args := []string{help.command, spelling}
				name := help.command + " " + spelling
				if globalJSON {
					args = append([]string{"--json"}, args...)
					name += " stays raw despite global json"
				}
				tests = append(tests, struct {
					name       string
					args       []string
					wantExit   int
					wantStdout string
					wantStderr string
				}{
					name: name, args: args, wantExit: 0, wantStderr: help.output,
				})
			}
		}
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			cli := newCompiledCLIHarness(t)
			result := cli.RunWithoutMasterPass(t, "ssm", nil, test.args...)
			if result.ProcessExit != test.wantExit || result.Stdout != test.wantStdout || result.Stderr != test.wantStderr {
				t.Fatalf(
					"legacy global-json bytes changed: exit=%d stdout=%q stderr=%q, want exit=%d stdout=%q stderr=%q",
					result.ProcessExit, result.Stdout, result.Stderr,
					test.wantExit, test.wantStdout, test.wantStderr,
				)
			}
		})
	}
}

func TestCompiledTransferAdaptersPreserveFailureProjections(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	const (
		alias    = "transfer-adapter"
		password = "TRANSFER_ADAPTER_PASSWORD_CANARY"
	)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password: password, RejectSessions: true,
	})
	cli.TrustSSHHost(t, server)
	cli.SaveVault(t, &config.Vault{
		Connections: []config.Connection{server.Connection(alias, password)},
	})

	assertHuman := func(t *testing.T, result compiledCLIResult, wantExit int, wantStderr string) {
		t.Helper()
		if result.ProcessExit != wantExit || result.Stdout != "" || result.Stderr != wantStderr {
			t.Fatalf(
				"human transfer projection changed: exit=%d stdout=%q stderr=%q, want exit=%d stdout empty stderr=%q",
				result.ProcessExit, result.Stdout, result.Stderr, wantExit, wantStderr,
			)
		}
	}

	missingLocal := filepath.Join(cli.temp, "missing-transfer-source")
	_, statErr := os.Stat(missingLocal)
	if statErr == nil {
		t.Fatalf("missing transfer source unexpectedly exists: %s", missingLocal)
	}
	carriedHuman := cli.Run(t, "sshctl", nil, "--offline", "put", alias, missingLocal, "/remote/carried")
	assertHuman(t, carriedHuman, 1,
		"ssm: error=internal alias="+alias+" address="+server.Address()+"\n"+
			"Error: "+statErr.Error()+"\n",
	)
	carriedMachine := cli.Run(t, "sshctl", nil, "--offline", "--json", "put", alias, missingLocal, "/remote/carried")
	assertCompiledTransferSnapshot(t, carriedMachine, map[string]any{
		"ok": false, "error": "local_read_failed", "message": statErr.Error(),
		"hint": "verify the local path and read permissions", "exit": 1, "stage": "local_read",
		"direction": "put", "kind": "unknown",
		"alias": alias, "bytes_sent": 0, "integrity": "not_checked", "atomic": false, "resume": "unsupported",
	})

	localFile := filepath.Join(cli.temp, "regular-transfer-source")
	if err := os.WriteFile(localFile, []byte("regular transfer body\n"), 0o600); err != nil {
		t.Fatalf("write regular transfer source: %v", err)
	}
	regularSessionHuman := cli.Run(t, "sshctl", nil, "--offline", "put", alias, localFile, "/remote/session")
	assertHuman(t, regularSessionHuman, machinecontract.ExitConnectionFailed,
		"ssm: error=session_failed alias="+alias+" address="+server.Address()+"\n"+
			"Error: ssh: rejected: resource shortage (fixture session rejected)\n"+
			"ssm: hint=SSH connected but session failed; remote sshd or resources may be unhealthy\n",
	)
	regularSessionMachine := cli.Run(t, "sshctl", nil, "--offline", "--json", "put", alias, localFile, "/remote/session")
	assertCompiledTransferSnapshot(t, regularSessionMachine, map[string]any{
		"ok": false, "error": "session_failed",
		"message": "ssh: rejected: resource shortage (fixture session rejected)",
		"hint":    "retry after checking SSH session limits",
		"exit":    machinecontract.ExitConnectionFailed, "stage": "dial",
		"direction": "put", "kind": "file",
		"alias": alias, "bytes_sent": 0, "integrity": "not_checked", "atomic": true, "resume": "unsupported",
	})

	localDirectory := filepath.Join(cli.temp, "fallback-directory")
	if err := os.Mkdir(localDirectory, 0o700); err != nil {
		t.Fatalf("create fallback transfer directory: %v", err)
	}
	const (
		sessionMessage = "ssh: rejected: resource shortage (fixture session rejected)"
		sessionHint    = "SSH connected but session failed; remote sshd or resources may be unhealthy"
	)
	fallbackStderr := "ssm: error=session_failed alias=" + alias + " address=" + server.Address() + "\n" +
		"Error: " + sessionMessage + "\n" +
		"ssm: hint=" + sessionHint + "\n"

	fallbackHuman := cli.Run(t, "sshctl", nil, "--offline", "put", alias, localDirectory, "/remote/fallback")
	assertHuman(t, fallbackHuman, machinecontract.ExitConnectionFailed, fallbackStderr)
	fallbackMachine := cli.Run(t, "sshctl", nil, "--offline", "--json", "put", alias, localDirectory, "/remote/fallback")
	assertCompiledTransferSnapshot(t, fallbackMachine, map[string]any{
		"ok": false, "error": "session_failed", "message": sessionMessage,
		"hint": sessionHint, "exit": machinecontract.ExitConnectionFailed, "stage": "remote_write",
		"direction": "put", "kind": "directory",
		"alias": alias, "bytes_sent": 0, "integrity": "not_available", "atomic": false, "resume": "unsupported",
	})

	downloaded := filepath.Join(cli.temp, "downloaded")
	getHuman := cli.Run(t, "sshctl", nil, "--offline", "get", alias, "/remote/fallback", downloaded)
	assertHuman(t, getHuman, machinecontract.ExitConnectionFailed, fallbackStderr)
	getMachine := cli.Run(t, "sshctl", nil, "--offline", "--json", "get", alias, "/remote/fallback", downloaded)
	assertCompiledTransferSnapshot(t, getMachine, map[string]any{
		"ok": false, "error": "session_failed", "message": sessionMessage,
		"hint": sessionHint, "alias": alias, "exit": machinecontract.ExitConnectionFailed,
		"direction": "get", "kind": "unknown", "stage": "session",
		"local": downloaded, "remote": "/remote/fallback",
	})

	const requestedAlias = "requested-transfer-adapter"
	redirectData, err := json.Marshal(config.Redirects{requestedAlias: alias})
	if err != nil {
		t.Fatalf("marshal transfer redirect fixture: %v", err)
	}
	cli.writeConfigFile(t, "redirects.json", append(redirectData, '\n'))
	redirectHumanPath := filepath.Join(cli.temp, "redirect-human")
	redirectHuman := cli.Run(t, "sshctl", nil, "--offline", "get", requestedAlias, "/remote/fallback", redirectHumanPath)
	assertHuman(t, redirectHuman, machinecontract.ExitConnectionFailed, fallbackStderr)
	redirectMachinePath := filepath.Join(cli.temp, "redirect-machine")
	redirectMachine := cli.Run(t, "sshctl", nil, "--offline", "--json", "get", requestedAlias, "/remote/fallback", redirectMachinePath)
	assertCompiledTransferSnapshot(t, redirectMachine, map[string]any{
		"ok": false, "error": "session_failed", "message": sessionMessage,
		"hint": sessionHint, "alias": requestedAlias, "exit": machinecontract.ExitConnectionFailed,
		"direction": "get", "kind": "unknown", "stage": "session",
		"local": redirectMachinePath, "remote": "/remote/fallback",
	})
}

func TestCompiledFailedStatusUsesFailureRenderer(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	cli.SaveVault(t, &config.Vault{})
	const canary = "COMPILED_STATUS_FAILURE_CONFIG_CANARY"
	settings, err := json.Marshal(config.Settings{
		PasswordCache: "never",
		AutoSync:      true,
		LastPush:      `config="{\"token\":\"` + canary + `\"}"`,
	})
	if err != nil {
		t.Fatalf("marshal failed-status settings: %v", err)
	}
	cli.writeConfigFile(t, "settings.json", settings)
	sync := newCompiledSyncFixture(t)
	sync.SetRemote(t, []byte("invalid encrypted vault"), "")
	cli.SaveCloud(t, sync.URL(), "COMPILED_STATUS_FAILURE_TOKEN_CANARY")

	result := cli.Run(t, "sshctl", nil, "--json", "status")
	if result.ProcessExit != 1 || result.Stderr != "" {
		t.Fatalf(
			"failed status placement/exit changed: exit=%d stderr=%q output=%s",
			result.ProcessExit, result.Stderr, compiledOutputIdentity(result),
		)
	}
	if !strings.HasSuffix(result.Stdout, "\n") || !strings.Contains(result.Stdout, "\n  \"version\":") {
		t.Fatalf("failed status is not one indented JSON document: output=%s", compiledOutputIdentity(result))
	}
	value := decodeExactlyOneJSONObject(t, result.Stdout)
	assertNoCompiledCanaryLeak(t, result, map[string]string{
		"status_configuration": canary,
		"cloud_token":          "COMPILED_STATUS_FAILURE_TOKEN_CANARY",
	})
	for _, absent := range []string{"error", "message", "hint", "exit", "stage"} {
		if _, exists := value[absent]; exists {
			t.Fatalf("failed status unexpectedly added %q: fields=%v", absent, value)
		}
	}
	if ok, _ := value["ok"].(bool); ok ||
		value["hosts"] != float64(0) ||
		value["vault"] != "present" ||
		value["sync"] != "configured" ||
		value["redirects"] != float64(0) ||
		value["reuse_scope"] != "process" ||
		value["last_push"] != "config=<redacted>" ||
		value["pending_changes"] != false ||
		value["offline"] != false {
		t.Fatalf("failed status fields changed: %v", value)
	}
	mutations, ok := value["pending_mutations"].([]any)
	if !ok || len(mutations) != 0 {
		t.Fatalf("failed status pending_mutations=%v, want []", value["pending_mutations"])
	}
	lastPull, pullOK := value["last_pull"].(string)
	lastSync, syncOK := value["last_sync"].(string)
	if !pullOK || !syncOK || lastPull == "" || lastSync != lastPull {
		t.Fatalf("failed status sync timestamps changed: last_pull=%v last_sync=%v", value["last_pull"], value["last_sync"])
	}
}

func TestCompiledSuccessfulTransferDiagnosticsRemainByteExact(t *testing.T) {
	const (
		alias              = "successful-diagnostics"
		password           = "SUCCESSFUL_DIAGNOSTICS_PASSWORD_CANARY"
		uploadStdout       = `token="UPLOAD_SUCCESS_STDOUT_CANARY"` + "\n"
		uploadDiagnostic   = `config="{\"token\":\"UPLOAD_SUCCESS_DIAGNOSTIC_CANARY\"}"` + "\n"
		downloadDiagnostic = `request_body="{\"argv\":[\"DOWNLOAD_SUCCESS_DIAGNOSTIC_CANARY\"]}"` + "\n"
		fileDiagnostic     = `decrypted_inventory="{\"hosts\":[\"FILE_SUCCESS_DIAGNOSTIC_CANARY\"]}"` + "\n"
	)
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password:                  password,
		UploadTarSuccessStdout:    uploadStdout,
		UploadTarSuccessStderr:    uploadDiagnostic,
		DownloadTarSuccessStderr:  downloadDiagnostic,
		DownloadFileSuccessStderr: fileDiagnostic,
	})
	cli.TrustSSHHost(t, server)
	cli.SaveVault(t, &config.Vault{
		Connections: []config.Connection{server.Connection(alias, password)},
	})
	assertSuccessDiagnostic := func(t *testing.T, result compiledCLIResult, wantStdout, wantStderr string) {
		t.Helper()
		if result.ProcessExit != 0 || result.Stdout != wantStdout || result.Stderr != wantStderr {
			t.Fatalf(
				"successful transfer diagnostic changed: exit=%d stdout=%q stderr=%q, want exit=0 stdout=%q stderr=%q",
				result.ProcessExit, result.Stdout, result.Stderr, wantStdout, wantStderr,
			)
		}
	}

	localUpload := filepath.Join(cli.temp, "upload-directory")
	if err := os.Mkdir(localUpload, 0o700); err != nil {
		t.Fatalf("create upload diagnostic directory: %v", err)
	}
	const body = "successful diagnostic transfer body\n"
	if err := os.WriteFile(filepath.Join(localUpload, "item.txt"), []byte(body), 0o600); err != nil {
		t.Fatalf("write upload diagnostic file: %v", err)
	}
	remoteUpload := filepath.Join(t.TempDir(), "uploaded")
	uploaded := cli.Run(t, "sshctl", nil, "--offline", "put", alias, localUpload, remoteUpload)
	assertSuccessDiagnostic(t, uploaded, uploadStdout, uploadDiagnostic)
	if data, err := os.ReadFile(filepath.Join(remoteUpload, "item.txt")); err != nil || string(data) != body { //nolint:gosec // path is beneath the test-owned remote upload directory
		t.Fatalf("uploaded diagnostic fixture data=%q err=%v", data, err)
	}

	remoteDirectory := filepath.Join(t.TempDir(), "remote-directory")
	if err := os.Mkdir(remoteDirectory, 0o700); err != nil {
		t.Fatalf("create remote diagnostic directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(remoteDirectory, "item.txt"), []byte(body), 0o600); err != nil {
		t.Fatalf("write remote diagnostic directory file: %v", err)
	}
	localDownload := filepath.Join(cli.temp, "downloaded-directory")
	downloaded := cli.Run(t, "sshctl", nil, "--offline", "get", alias, remoteDirectory, localDownload)
	assertSuccessDiagnostic(t, downloaded, "", downloadDiagnostic)
	if data, err := os.ReadFile(filepath.Join(localDownload, "item.txt")); err != nil || string(data) != body { //nolint:gosec // path is beneath the test-owned local download directory
		t.Fatalf("downloaded diagnostic directory data=%q err=%v", data, err)
	}

	remoteFile := filepath.Join(t.TempDir(), "remote-file")
	if err := os.WriteFile(remoteFile, []byte(body), 0o600); err != nil {
		t.Fatalf("write remote diagnostic file: %v", err)
	}
	localFile := filepath.Join(cli.temp, "downloaded-file")
	fileDownloaded := cli.Run(t, "sshctl", nil, "--offline", "get", alias, remoteFile, localFile)
	assertSuccessDiagnostic(t, fileDownloaded, "", fileDiagnostic)
	if data, err := os.ReadFile(localFile); err != nil || string(data) != body { //nolint:gosec // path is the test-owned single-file download destination
		t.Fatalf("downloaded diagnostic file data=%q err=%v", data, err)
	}
}

func TestCompiledSuccessfulDirectoryFallbackPreservesOrderedDiagnostics(t *testing.T) {
	const (
		alias    = "fallback-diagnostics"
		password = "FALLBACK_DIAGNOSTICS_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
	)
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
	cli.TrustSSHHost(t, server)
	cli.SaveVault(t, &config.Vault{
		Connections: []config.Connection{server.Connection(alias, password)},
	})
	local := filepath.Join(cli.temp, "fallback-source")
	if err := os.Mkdir(local, 0o700); err != nil {
		t.Fatalf("create fallback source: %v", err)
	}
	const body = "fallback walk body\n"
	if err := os.WriteFile(filepath.Join(local, "item.txt"), []byte(body), 0o600); err != nil {
		t.Fatalf("write fallback source: %v", err)
	}
	remote := filepath.Join(t.TempDir(), "fallback-destination")
	result := cli.RunWithEnv(t, "sshctl", nil, map[string]string{
		"PATH":                cli.TarFailureHelperDir(t),
		"SSM_TEST_TAR_HELPER": "1",
	}, "--offline", "put", alias, local, remote)
	wantStderr := "config=\"{\\\"token\\\":\\\"FALLBACK_LOCAL_TAR_DIAGNOSTIC\\\"}\"\n" +
		"compiled fixture tar stream invalid\n"
	if result.ProcessExit != 0 || result.Stdout != "" || result.Stderr != wantStderr {
		t.Fatalf(
			"successful fallback diagnostics changed: exit=%d stdout=%q stderr=%q, want exit=0 stdout empty stderr=%q",
			result.ProcessExit, result.Stdout, result.Stderr, wantStderr,
		)
	}
	if data, err := os.ReadFile(filepath.Join(remote, "item.txt")); err != nil || string(data) != body { //nolint:gosec // path is beneath the test-owned remote temporary directory
		t.Fatalf("fallback walk destination data=%q err=%v", data, err)
	}
}

func TestCompiledHumanRunDefersDiagnosticsUntilOutcome(t *testing.T) {
	t.Run("failure redacts fragmented diagnostics and known script input", func(t *testing.T) {
		const (
			password    = "RUN_FAILURE_PASSWORD_CANARY"
			scriptInput = "RUN_FAILURE_SCRIPT_INPUT_CANARY"
		)
		cli := newCompiledCLIHarness(t)
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
			Password:           password,
			RunCommandContains: "command -v 'sh'",
			RunDrainStdin:      true,
			RunExitStatus:      23,
			RunStdoutFragments: []string{
				"safe stdout before\n",
				`password=\"OUTER_ESCAPED_RUN_PASSWORD_CANARY WITH `,
				`SPACES,AND,COMMAS\"` + "\n",
				"master_pass=RUN_MASTER_PASS_CANARY\n",
				"known short value: abc\n",
				scriptInput + "\n",
			},
			RunStderrFragments: []string{
				"token=RUN_TOKEN_CANARY\ncredential=RUN_CREDENTIAL_CANARY\n",
				"-----BEGIN OPENSSH PRIVATE KEY-----\nRUN_PRIVATE_",
				"KEY_CANARY\n-----END OPENSSH PRIVATE KEY-----\n",
				"config={\n  \"token\": \"RUN_CONFIG_CANARY\"\n}\nrequest_body={\n",
				"  \"argv\": [\"RUN_REQUEST_BODY_CANARY\"]\n}\n",
				`decrypted_inventory=\"RUN_INVENTORY_CANARY WITH SPACES\"` + "\n",
			},
		})
		cli.TrustSSHHost(t, server)
		cli.SaveVault(t, &config.Vault{
			Connections: []config.Connection{server.Connection("run-failure", password)},
		})
		secretPath := filepath.Join(cli.temp, "short-secret")
		if err := os.WriteFile(secretPath, []byte("abc\n"), 0o600); err != nil {
			t.Fatalf("write short run secret: %v", err)
		}

		result := cli.Run(t, "sshctl", []byte(scriptInput+"\n"), "--offline", "run", "run-failure", "-s", "--secret", "SHORT=@"+secretPath)
		if result.ProcessExit != 23 {
			t.Fatalf("failed human run exit=%d, want 23; output=%s", result.ProcessExit, compiledOutputIdentity(result))
		}
		if !strings.Contains(result.Stdout, "safe stdout before\n") {
			t.Fatalf("failed human run lost safe stdout: %q", result.Stdout)
		}
		assertNoCompiledCanaryLeak(t, result, map[string]string{ //nolint:gosec // test-only fake credential canaries
			"outer_escaped_password": "OUTER_ESCAPED_RUN_PASSWORD_CANARY",
			"master_pass":            "RUN_MASTER_PASS_CANARY",
			"known_short":            "abc",
			"script_input":           scriptInput,
			"token":                  "RUN_TOKEN_CANARY",
			"credential":             "RUN_CREDENTIAL_CANARY",
			"private_key":            "RUN_PRIVATE_KEY_CANARY",
			"config":                 "RUN_CONFIG_CANARY",
			"request_body":           "RUN_REQUEST_BODY_CANARY",
			"decrypted_inventory":    "RUN_INVENTORY_CANARY",
		})
	})

	t.Run("success replays both streams byte for byte", func(t *testing.T) {
		const (
			password = "RUN_SUCCESS_PASSWORD_CANARY"
			stdout   = "success stdout byte 1\r\nsuccess stdout byte 2"
			stderr   = "success stderr byte 1\r\nsuccess stderr byte 2"
		)
		cli := newCompiledCLIHarness(t)
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
			Password:           password,
			RunCommandContains: "run-success",
			RunStdoutFragments: []string{stdout[:11], stdout[11:]},
			RunStderrFragments: []string{stderr[:9], stderr[9:]},
		})
		cli.TrustSSHHost(t, server)
		cli.SaveVault(t, &config.Vault{
			Connections: []config.Connection{server.Connection("run-success", password)},
		})

		result := cli.Run(t, "sshctl", nil, "--offline", "run", "run-success", "--raw", "run-success")
		if result.ProcessExit != 0 || result.Stdout != stdout || result.Stderr != stderr {
			t.Fatalf(
				"successful human run changed bytes: exit=%d stdout=%q stderr=%q, want exit=0 stdout=%q stderr=%q",
				result.ProcessExit, result.Stdout, result.Stderr, stdout, stderr,
			)
		}
	})
}

func TestCompiledCLIScriptExit127ClassificationAndPlacement(t *testing.T) {
	for _, test := range []struct {
		name       string
		diagnostic string
		wantError  string
		wantStage  string
		wantHint   string
	}{
		{
			name:       "stable interpreter marker",
			diagnostic: machinecontract.InterpreterNotFoundDiagnostic("sh") + "\n",
			wantError:  "interpreter_not_found",
			wantStage:  "interpreter",
			wantHint:   `remote shell "sh" is unavailable; retry with --shell sh or install it`,
		},
		{
			name:       "ordinary script exit",
			diagnostic: "ordinary exit 127\n",
			wantError:  "remote_script_failed",
			wantStage:  "remote_execution",
			wantHint:   "the script reached the remote interpreter but exited non-zero; inspect stderr",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			const password = "EXIT_127_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
			cli := newCompiledCLIHarness(t)
			server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
				Password:           password,
				RunCommandContains: "command -v 'sh'",
				RunStderrFragments: []string{test.diagnostic},
				RunExitStatus:      127,
				RunDrainStdin:      true,
			})
			cli.TrustSSHHost(t, server)
			cli.SaveVault(t, &config.Vault{
				Connections: []config.Connection{server.Connection("script-127", password)},
			})

			human := cli.Run(t, "sshctl", []byte("printf script-body\n"), "--offline", "run", "script-127", "-s")
			if human.ProcessExit != 127 || human.Stdout != "" {
				t.Fatalf("human placement exit=%d stdout=%q stderr=%q", human.ProcessExit, human.Stdout, human.Stderr)
			}
			wantHumanStderr := test.diagnostic +
				"ssm: error=" + test.wantError + " script=<stdin> exit=127\n" +
				"ssm: hint=" + test.wantHint + "\n"
			if human.Stderr != wantHumanStderr {
				t.Fatalf("human stderr placement = %q, want %q", human.Stderr, wantHumanStderr)
			}

			machine := cli.Run(t, "sshctl", []byte("printf script-body\n"), "--offline", "--json", "run", "script-127", "-s")
			if machine.ProcessExit != 127 || machine.Stderr != "" {
				t.Fatalf("machine placement exit=%d stdout=%q stderr=%q", machine.ProcessExit, machine.Stdout, machine.Stderr)
			}
			var document map[string]any
			if err := json.Unmarshal([]byte(machine.Stdout), &document); err != nil {
				t.Fatalf("machine stdout is not one JSON document: %v; output=%q", err, machine.Stdout)
			}
			if document["error"] != test.wantError || document["stage"] != test.wantStage ||
				document["exit"] != float64(127) || document["stderr"] != test.diagnostic {
				t.Fatalf("machine document = %#v", document)
			}
		})
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

	t.Run("physical sshctl basename dispatches portably", func(t *testing.T) {
		invocation := reviewedCompiledMachineContract(t, "unknown_sshctl")
		result := cli.RunWithPhysicalBasename(t, "sshctl", invocation.Args...)
		assertCompiledMachineContract(t, result, invocation)
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
		syncVaultCanary := "ISSUE17_SYNC_VAULT_OUTPUT_CANARY"
		syncCloudCanary := "ISSUE17_SYNC_CLOUD_OUTPUT_CANARY"
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{
			Name: "cached", Host: "192.0.2.20", Port: 22, User: "runner", Password: syncVaultCanary,
		}}})
		cli.SaveCloud(t, sync.URL(), syncCloudCanary)
		cli.SaveRemoteETag(t, "cached-baseline")

		contract := reviewedCompiledMachineContract(t, "sync_etag_conflict")
		result := cli.RunReviewed(t, contract, nil, nil)
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"vault_value": syncVaultCanary,
			"cloud_value": syncCloudCanary,
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
		hostKeyLeakCanary := "ISSUE17_HOST_KEY_OUTPUT_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: hostKeyLeakCanary})
		hostKeySavedKeyCanary := "ISSUE17_HOST_KEY_SAVED_KEY_OUTPUT_CANARY"
		hostKeyCloudCanary := "ISSUE17_HOST_KEY_CLOUD_OUTPUT_CANARY"
		hostKeyUnrelatedCanary := "ISSUE17_HOST_KEY_UNRELATED_OUTPUT_CANARY"
		configCanary := "ISSUE17_HOST_KEY_CONFIG_CANARY"
		inventoryCanary := "ISSUE17_HOST_KEY_DECRYPTED_INVENTORY_CANARY"
		cli.SaveVault(t, &config.Vault{
			Connections: []config.Connection{
				server.Connection("host-key", hostKeyLeakCanary),
				{Name: inventoryCanary, Host: "192.0.2.55", Port: 22, User: "runner", Password: hostKeyUnrelatedCanary},
			},
			Keys: []config.SSHKey{{Name: "host-key-unrelated", PrivateKey: hostKeySavedKeyCanary}},
		})
		cli.writeConfigFile(t, "cloud.json", []byte(`{"server":"https://`+configCanary+`.invalid","token":"`+hostKeyCloudCanary+`"`))
		canaries := map[string]string{
			"host_auth":            hostKeyLeakCanary,
			"saved_key":            hostKeySavedKeyCanary,
			"cloud_value":          hostKeyCloudCanary,
			"unrelated_vault":      hostKeyUnrelatedCanary,
			"configuration":        configCanary,
			"decrypted_inventory":  inventoryCanary,
			"vault_unlock_fixture": cli.passphrase,
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
		dialLeakCanary := "ISSUE17_DIAL_OUTPUT_CANARY"
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{
			Name: "refused", Host: refused.host, Port: refused.port, User: "runner", Password: dialLeakCanary,
		}}})
		contractName := "dial_refused"
		if runtime.GOOS == "windows" {
			contractName = "dial_refused_windows"
		}
		contract := reviewedCompiledMachineContract(t, contractName)
		result := cli.RunReviewed(t, contract, nil, nil)
		assertNoCompiledCanaryLeak(t, result, map[string]string{"host_auth": dialLeakCanary})
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
		input, writer := io.Pipe()
		go func() {
			time.Sleep(500 * time.Millisecond)
			_, _ = io.WriteString(writer, "[\"true\"]\n[\"true\"]\n")
			_ = writer.Close()
		}()
		result := streamCLI.runWithStdin(
			t,
			contract.Executable,
			input,
			map[string]string{"SSM_MASTER_PASS_FILE": streamCLI.passPath},
			contract.Args...,
		)
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
		alphaLeakCanary := "ISSUE17_ALPHA_VAULT_OUTPUT_CANARY"
		betaLeakCanary := "ISSUE17_BETA_VAULT_OUTPUT_CANARY"
		alphaPassword := filepath.Join(mutationCLI.temp, "alpha.password")
		betaPassword := filepath.Join(mutationCLI.temp, "beta.password")
		if err := os.WriteFile(alphaPassword, []byte(alphaLeakCanary+"\n"), 0o600); err != nil {
			t.Fatalf("write alpha password fixture: %v", err)
		}
		if err := os.WriteFile(betaPassword, []byte(betaLeakCanary+"\n"), 0o600); err != nil {
			t.Fatalf("write beta password fixture: %v", err)
		}
		alpha := mutationCLI.Run(t, "sshctl", nil, "--json", "host", "add", "alpha", "--host", "192.0.2.70", "--user", "runner", "--password-file", alphaPassword, "--offline")
		assertNoCompiledCanaryLeak(t, alpha, map[string]string{
			"vault_value": alphaLeakCanary,
			"passphrase":  mutationCLI.passphrase,
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
			"vault_value": betaLeakCanary,
			"passphrase":  mutationCLI.passphrase,
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
				"alpha_vault":         alphaLeakCanary,
				"beta_vault":          betaLeakCanary,
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
		scopedCloudCanary := "ISSUE17_SCOPED_PUSH_CLOUD_OUTPUT_CANARY"
		mutationCLI.SaveCloud(t, sync.URL(), scopedCloudCanary)
		pushed := mutationCLI.Run(t, "sshctl", nil, "--json", "push", "--only", betaID)
		pushedValue := assertCompiledJSONSuccess(t, pushed)
		assertCompiledStringField(t, pushedValue, "transaction_id", betaID, pushed)
		assertNoCompiledCanaryLeak(t, pushed, map[string]string{
			"alpha_vault":         alphaLeakCanary,
			"beta_vault":          betaLeakCanary,
			"unrelated_password":  statusPassword,
			"private_key":         statusPrivateKey,
			"decrypted_inventory": statusInventory,
			"cloud_value":         scopedCloudCanary,
			"passphrase":          mutationCLI.passphrase,
		})
		alphaConnection := config.Connection{
			Name: "alpha", Host: "192.0.2.70", Port: 22, User: "runner", Password: alphaLeakCanary,
		}
		betaConnection := config.Connection{
			Name: "beta", Host: "192.0.2.71", Port: 22, User: "runner",
			Password: betaLeakCanary, Group: requestCanary,
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

	t.Run("BC-1 malformed and unreadable cloud configuration old behavior characterization and migration", func(t *testing.T) {
		for _, variant := range []string{"malformed", "unreadable"} {
			t.Run(variant, func(t *testing.T) {
				cli := newCompiledCLIHarness(t)
				cli.SaveVault(t, &config.Vault{})
				configLeakCanary := "ISSUE17_CONFIG_CLOUD_OUTPUT_CANARY"
				if variant == "malformed" {
					cli.writeConfigFile(t, "cloud.json", []byte(`{"server":"https://sync.invalid","token":"`+configLeakCanary+`"`))
				} else {
					path := filepath.Join(cli.home, ".config", "ssm", "cloud.json")
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatalf("create unreadable cloud configuration fixture: %v", err)
					}
				}

				generic := cli.Run(t, "sshctl", nil, "--json", "list")
				assertNoCompiledCanaryLeak(t, generic, map[string]string{
					"cloud_value":    configLeakCanary,
					"config_content": "sync.invalid",
				})
				assertCompiledMachineContract(t, generic, compiledMachineContract{
					OK: false, Error: "sync_config_error", Stage: "sync_config", JSONExit: 1, ProcessExit: 1,
					Hint: "repair sync configuration or retry explicitly with --offline",
				})

				host := cli.Run(t, "sshctl", nil, "--json", "host", "list")
				assertNoCompiledCanaryLeak(t, host, map[string]string{
					"cloud_value":    configLeakCanary,
					"config_content": "sync.invalid",
				})
				assertCompiledMachineContract(t, host, compiledMachineContract{
					OK: false, Error: "sync_config_error", Stage: "sync_config", JSONExit: 1, ProcessExit: 1,
					Hint: "repair sync configuration or retry explicitly with --offline",
				})

				offline := cli.Run(t, "sshctl", nil, "--json", "host", "list", "--offline")
				assertCompiledEmptyJSONArraySuccess(t, offline)
			})
		}
	})

	t.Run("BC-2 cross-alias saved-key publication is currently permitted", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		sync.SetRemote(t, nil, "bc2-upload")
		keyCanary := "ISSUE17_CROSS_ALIAS_PRIVATE_KEY_CANARY"
		bc2CloudCanary := "ISSUE17_BC2_CLOUD_OUTPUT_CANARY"
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
		cli.SaveCloud(t, sync.URL(), bc2CloudCanary)

		result := cli.Run(t, "sshctl", nil, "--json", "push", "--only", "tx_beta")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"private_key":         keyCanary,
			"cloud_value":         bc2CloudCanary,
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

	t.Run("BC-3 stream startup failure migrates to compact NDJSON", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		sync.SetStatus(t, "HEAD", 500)
		cli.SaveVault(t, &config.Vault{})
		cli.SaveCloud(t, sync.URL(), "ISSUE17_STREAM_TOKEN_CANARY")
		result := cli.RunWithHeldOpenStdin(t, "sshctl", "--json", "run", "missing", "--stream", "--refresh=30s")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"token":               "ISSUE17_STREAM_TOKEN_CANARY",
			"passphrase":          cli.passphrase,
			"passphrase_fragment": "MASTER_PASSPHRASE",
		})
		if result.ProcessExit != 1 || result.Stdout != compiledBC3NewStartupFailure || result.Stderr != "" {
			t.Fatalf("BC-3 startup migration failed; output=%s", compiledOutputIdentity(result))
		}
	})

	t.Run("BC-4 legacy mutations persist directly with their current publication effects", func(t *testing.T) {
		t.Run("legacy remove auto-pushes without a transaction", func(t *testing.T) {
			cli := newCompiledCLIHarness(t)
			sync := newCompiledSyncFixture(t)
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
			starting := &config.Vault{
				Connections: []config.Connection{removedConnection, preservedConnection, preservedKeyConnection},
				Keys:        []config.SSHKey{preservedKey},
				PendingBase: pendingBase, PendingMutations: pendingMutations,
			}
			cli.SaveVault(t, starting)
			sync.SetRemote(t, cli.VaultBlob(t), "legacy-remove")
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
			if got := sync.MethodCount("HEAD"); got != 2 {
				t.Fatalf("legacy remove HEAD count = %d, want 2", got)
			}
			if got := sync.MethodCount("GET"); got != 1 {
				t.Fatalf("legacy remove GET count = %d, want 1", got)
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
			starting := &config.Vault{
				Connections: []config.Connection{connection},
				Keys: []config.SSHKey{
					{Name: "legacy-key", PrivateKey: removedKey},
					unrelatedKey,
				},
				PendingBase: pendingBase, PendingMutations: pendingMutations,
			}
			cli.SaveVault(t, starting)
			sync.SetRemote(t, cli.VaultBlob(t), "legacy-key-remove")
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
			if got := sync.MethodCount("HEAD"); got != 2 {
				t.Fatalf("legacy key remove HEAD count = %d, want 2", got)
			}
			if got := sync.MethodCount("GET"); got != 1 {
				t.Fatalf("legacy key remove GET count = %d, want 1", got)
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
				sync.SetRemote(t, cli.VaultBlob(t), "legacy-import-"+mode)
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
				if got := sync.MethodCount("HEAD"); got != 1 {
					t.Fatalf("legacy import %s HEAD count = %d, want 1", mode, got)
				}
				if got := sync.MethodCount("GET"); got != 1 {
					t.Fatalf("legacy import %s GET count = %d, want 1", mode, got)
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
				vaultLeakCanary := "ISSUE17_EMPTY_LEDGER_VAULT_OUTPUT_CANARY"
				savedKeyLeakCanary := "ISSUE17_EMPTY_LEDGER_SAVED_KEY_OUTPUT_CANARY"
				cloudLeakCanary := "ISSUE17_EMPTY_LEDGER_CLOUD_OUTPUT_CANARY"
				want := &config.Vault{
					Connections: []config.Connection{
						{
							Name: "empty-ledger-password", Host: "192.0.2.54", Port: 2204, User: "password-user",
							Password: vaultLeakCanary, Group: "password-group",
						},
						{
							Name: "empty-ledger-key-reference", Host: "192.0.2.55", Port: 2205, User: "key-user",
							KeyName: "empty-ledger-key", Group: "key-group",
						},
					},
					Keys: []config.SSHKey{{Name: "empty-ledger-key", PrivateKey: savedKeyLeakCanary}},
				}
				cli.SaveVault(t, want)
				cli.SaveCloud(t, sync.URL(), cloudLeakCanary)
				result := cli.Run(t, "sshctl", nil, args...)
				value := assertCompiledJSONSuccess(t, result)
				assertCompiledStringField(t, value, "scope", "all", result)
				assertNoCompiledCanaryLeak(t, result, map[string]string{
					"vault_value": vaultLeakCanary,
					"saved_key":   savedKeyLeakCanary,
					"cloud_value": cloudLeakCanary,
				})
				if got := sync.MethodCount("PUT"); got != 1 {
					t.Fatalf("%s push PUT count = %d, want 1", name, got)
				}
				assertCompiledEncryptedPublication(t, sync.UploadedBlob(), cli.passphrase, map[string]string{
					"vault_value": vaultLeakCanary,
					"saved_key":   savedKeyLeakCanary,
				}, want)
				assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), want)
			})
		}
	})

	t.Run("BC-6 zero refresh is rejected online before refresh or SSH", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		sshLeakCanary := "ISSUE17_ZERO_REFRESH_SSH_OUTPUT_CANARY"
		cloudLeakCanary := "ISSUE17_ZERO_REFRESH_CLOUD_OUTPUT_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: sshLeakCanary})
		cli.TrustSSHHost(t, server)
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("zero-refresh", sshLeakCanary)}})
		cli.SaveCloud(t, sync.URL(), cloudLeakCanary)
		cli.SaveRemoteETag(t, "startup-current")
		sync.SetRemote(t, []byte("unused-opaque-blob"), "startup-current")
		result := cli.Run(t, "sshctl", []byte("[\"true\"]\n\n[\"true\"]\n"), "--json", "run", "zero-refresh", "--stream", "--refresh=0")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"ssh_auth":    sshLeakCanary,
			"cloud_value": cloudLeakCanary,
		})
		if result.ProcessExit != 2 || result.Stdout != compiledBC6NewZeroOnline || result.Stderr != "" {
			t.Fatalf("BC-6 zero online migration failed; output=%s", compiledOutputIdentity(result))
		}
		if got := sync.MethodCount("HEAD"); got != 0 {
			t.Fatalf("zero-refresh HEAD count = %d, want 0", got)
		}
		if connections, sessions := server.ConnectionCount(), server.SessionCount(); connections != 0 || sessions != 0 {
			t.Fatalf("zero-refresh SSH counts connections=%d sessions=%d, want 0 and 0", connections, sessions)
		}
	})

	t.Run("BC-7 direct and request-v1 transfer fields retain current omissions", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		password := "ISSUE17_TRANSFER_LIVE_PASSWORD_CANARY"
		server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
		cli.TrustSSHHost(t, server)
		privateKey := "ISSUE17_TRANSFER_PRIVATE_KEY_CANARY"
		inventoryCanary := "ISSUE17_DECRYPTED_INVENTORY_CANARY"
		cli.SaveVault(t, &config.Vault{
			Connections: []config.Connection{
				server.Connection("transfer-live", password),
				{Name: inventoryCanary, Host: "192.0.2.54", Port: 22, User: "runner", Password: "ISSUE17_UNRELATED_INVENTORY_PASSWORD_CANARY"},
			},
			Keys: []config.SSHKey{{Name: "unrelated-key", PrivateKey: privateKey}},
		})
		secretCanaries := map[string]string{
			"password":            password,
			"private_key":         privateKey,
			"file_content":        "ISSUE17_TRANSFER_FILE_CONTENT_CANARY",
			"directory_content":   "ISSUE17_TRANSFER_DIRECTORY_CONTENT_CANARY",
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
			"ok": true, "direction": "put", "kind": "file", "stage": "complete", "bytes_sent": len(fileBody),
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
			"ok": true, "direction": "put", "kind": "file", "stage": "complete", "bytes_sent": len(fileBody),
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
			"ok": true, "direction": "put", "kind": "directory", "stage": "complete", "bytes_sent": 0,
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
			"ok": true, "direction": "put", "kind": "directory", "stage": "complete", "bytes_sent": 0,
			"integrity": "not_available", "atomic": false, "resume": "unsupported",
		})
		assertNoCompiledCanaryLeak(t, requestDirectory, mergeCompiledCanaries(secretCanaries, "request", string(requestBody)))

		downloadedFile := filepath.Join(cli.temp, "downloaded-file.bin")
		getFile := cli.Run(t, "sshctl", nil, "--offline", "--json", "get", "transfer-live", remoteFile, downloadedFile)
		assertCompiledTransferSnapshot(t, getFile, map[string]any{
			"ok": true, "action": "get", "alias": "transfer-live", "remote": remoteFile, "local": downloadedFile,
			"direction": "get", "kind": "file", "stage": "complete", "bytes_received": len(fileBody),
			"integrity": "not_checked", "atomic": true, "resume": "unsupported",
		})
		assertNoCompiledCanaryLeak(t, getFile, secretCanaries)

		downloadedDirectory := filepath.Join(cli.temp, "downloaded-directory")
		getDirectory := cli.Run(t, "sshctl", nil, "--offline", "--json", "get", "transfer-live", remoteDirectory, downloadedDirectory)
		assertCompiledTransferSnapshot(t, getDirectory, map[string]any{
			"ok": true, "action": "get", "alias": "transfer-live", "remote": remoteDirectory, "local": downloadedDirectory,
			"direction": "get", "kind": "directory", "stage": "complete",
			"integrity": "not_available", "atomic": false, "resume": "unsupported",
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
			t.Run("request-v1 get "+requestGet.name+" migrates with BC-7", func(t *testing.T) {
				body, err := json.Marshal(map[string]any{
					"version": 1, "op": "get", "alias": "transfer-live",
					"remote_path": requestGet.remotePath, "local_path": requestGet.localPath,
				})
				if err != nil {
					t.Fatalf("marshal request-v1 get fixture: %v", err)
				}
				result := cli.Run(t, "sshctl", body, "request", "-")
				kind := requestGet.name
				want := map[string]any{
					"ok": true, "action": "get", "direction": "get", "kind": kind,
					"alias": "transfer-live", "remote": requestGet.remotePath, "local": requestGet.localPath,
					"stage": "complete", "integrity": "not_available", "atomic": false, "resume": "unsupported",
				}
				if kind == "file" {
					want["bytes_received"] = len(fileBody)
					want["integrity"] = "not_checked"
					want["atomic"] = true
				}
				assertCompiledTransferSnapshot(t, result, want)
				assertNoCompiledCanaryLeak(t, result, mergeCompiledCanaries(secretCanaries, "request", string(body)))
			})
		}

		blocker := filepath.Join(remoteRoot, "blocked-parent")
		if err := os.WriteFile(blocker, []byte("preserve\n"), 0o600); err != nil {
			t.Fatalf("write blocked remote parent fixture: %v", err)
		}
		failedRemote := filepath.Join(blocker, "artifact.bin")
		failedHuman := cli.Run(t, "sshctl", nil, "--offline", "put", "transfer-live", localFile, failedRemote, "--sha256")
		wantHumanFailure := "ssm: error=auth_failed alias=transfer-live address=" + server.Address() + "\n" +
			"Error: SSH authentication failed\n" +
			"ssm: hint=verify user and credential file; password/private-key contents are never shown\n"
		if failedHuman.ProcessExit != machinecontract.ExitConnectionFailed ||
			failedHuman.Stdout != "" || failedHuman.Stderr != wantHumanFailure {
			t.Fatalf(
				"permission-denied human transfer changed: exit=%d stdout=%q stderr=%q, want exit=%d stderr=%q",
				failedHuman.ProcessExit, failedHuman.Stdout, failedHuman.Stderr,
				machinecontract.ExitConnectionFailed, wantHumanFailure,
			)
		}
		failed := cli.Run(t, "sshctl", nil, "--offline", "--json", "put", "transfer-live", localFile, failedRemote, "--sha256")
		assertCompiledMachineContract(t, failed, compiledMachineContract{
			OK: false, Error: "remote_write_failed", Stage: "remote_write",
			JSONExit: machinecontract.ExitConnectionFailed, ProcessExit: machinecontract.ExitConnectionFailed,
			Hint:      "check remote path permissions and available space; the final path was not replaced",
			Alias:     "transfer-live",
			Direction: "put", Kind: "file",
		})
		if data, err := os.ReadFile(blocker); err != nil || string(data) != "preserve\n" { //nolint:gosec // blocker is created directly beneath the test-owned remote t.TempDir
			t.Fatalf("failed transfer did not preserve safe blocker fixture")
		}
		if _, err := os.Stat(failedRemote); err == nil {
			t.Fatal("failed transfer published a final path")
		}

		assertNoCompiledCanaryLeak(t, failed, secretCanaries)
	})

	t.Run("BC-8 automatic replacement remains in the current major", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		cli.SaveVault(t, &config.Vault{})
		replacement := []byte("ISSUE17_CROSS_MAJOR_REPLACEMENT_FIXTURE\n")
		compiledUpdateServer.ConfigureRelease("v2.0.0", replacement)
		before := loadCompiledFileIdentity(t, cli.paths["ssm"])
		result := cli.RunWithEnv(t, "ssm", nil, map[string]string{"SSM_UPDATE_REPO": "fixture/repo"}, "list", "--json")
		assertNoCompiledCanaryLeak(t, result, map[string]string{"replacement": string(replacement)})
		assertCompiledEmptyJSONArraySuccess(t, result)
		assertCompiledFileUnchanged(t, cli.paths["ssm"], before)
		if got := compiledUpdateServer.RequestPaths(); !reflect.DeepEqual(got, []string{"/repos/fixture/repo/releases"}) {
			t.Fatalf("automatic cross-major request paths = %q", got)
		}
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

	t.Run("BC-10 make check is a single non-mutating verification-manifest adapter", func(t *testing.T) {
		makefile, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
		if err != nil {
			t.Fatalf("read Makefile for check membership: %v", err)
		}
		lines, err := compiledMakeTargetCommands(makefile, "check")
		if err != nil {
			t.Fatalf("inspect make check membership: %v", err)
		}
		want := []string{"go run ./cmd/verify ci"}
		recipe := strings.Join(lines, "\n")
		for _, forbidden := range []string{
			"gofmt -w",
			"golangci-lint run",
			"go build",
			"go test",
			"go vet",
			"-race",
			"govulncheck",
		} {
			if strings.Contains(recipe, forbidden) {
				t.Fatalf("make check adapter unexpectedly contains legacy direct/mutating recipe fragment %q", forbidden)
			}
		}
		if !reflect.DeepEqual(lines, want) {
			t.Fatalf("make check commands = %q, want single non-mutating verification-manifest adapter %q", lines, want)
		}
	})
}

func TestCompiledSyncStateMatrix(t *testing.T) {
	t.Run("absent configuration remains unconfigured cached success", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		cli.SaveVault(t, &config.Vault{})

		assertCompiledEmptyJSONArraySuccess(t, cli.Run(t, "sshctl", nil, "--json", "list"))
		status := assertCompiledJSONSuccess(t, cli.Run(t, "sshctl", nil, "--json", "status"))
		doctor := assertCompiledJSONSuccess(t, cli.Run(t, "sshctl", nil, "--json", "doctor"))
		for _, value := range []map[string]any{status, doctor} {
			if value["sync"] != "missing" || value["remote_state"] != "not_configured" || value["offline"] != false {
				t.Fatalf("unconfigured sync vocabulary = %#v", value)
			}
		}
		for _, field := range []string{"sync", "freshness", "remote_state", "offline"} {
			if status[field] != doctor[field] {
				t.Fatalf("unconfigured status/doctor %s mismatch: status=%#v doctor=%#v", field, status[field], doctor[field])
			}
		}
		assertCompiledMachineContract(t, cli.Run(t, "sshctl", nil, "--json", "pull"), compiledMachineContract{
			OK: false, Error: "sync_config_error", JSONExit: 1, ProcessExit: 1,
			Hint: "configure sync or use local inventory",
		})
	})

	t.Run("disabled automatic sync validates configuration and makes no request", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		cli.SaveVault(t, &config.Vault{})
		cli.SaveCloud(t, sync.URL(), "AUTO_SYNC_DISABLED_SECRET")
		settings := config.DefaultSettings()
		settings.AutoSync = false
		settingsData, err := json.Marshal(settings)
		if err != nil {
			t.Fatal(err)
		}
		cli.writeConfigFile(t, "settings.json", settingsData)

		assertCompiledEmptyJSONArraySuccess(t, cli.Run(t, "sshctl", nil, "--json", "list"))
		status := assertCompiledJSONSuccess(t, cli.Run(t, "sshctl", nil, "--json", "status"))
		doctor := assertCompiledJSONSuccess(t, cli.Run(t, "sshctl", nil, "--json", "doctor"))
		for _, value := range []map[string]any{status, doctor} {
			if value["sync"] != "configured" || value["remote_state"] != "auto_sync_disabled" || value["offline"] != false {
				t.Fatalf("disabled automatic sync vocabulary = %#v", value)
			}
		}
		for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
			if got := sync.MethodCount(method); got != 0 {
				t.Fatalf("disabled automatic sync %s requests = %d, want 0", method, got)
			}
		}
	})

	t.Run("changed remote opaque blob replaces the unlocked snapshot before use", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{
			Name: "cached", Host: "192.0.2.40", Port: 22, User: "runner", Password: "CACHED_SNAPSHOT_SECRET",
		}}})
		cachedBlob := cli.VaultBlob(t)
		remoteVault := &config.Vault{Connections: []config.Connection{{
			Name: "remote", Host: "192.0.2.41", Port: 22, User: "runner", Password: "REMOTE_SNAPSHOT_SECRET",
		}}}
		remoteBlob, err := config.EncryptVault(remoteVault, cli.passphrase)
		if err != nil {
			t.Fatal(err)
		}
		cachedIdentity := fmt.Sprintf("%x", sha256.Sum256(cachedBlob))
		remoteIdentity := fmt.Sprintf("%x", sha256.Sum256(remoteBlob))
		cli.SaveRemoteETag(t, cachedIdentity)
		cli.SaveCloud(t, sync.URL(), "REMOTE_REPLACEMENT_TOKEN_SECRET")
		sync.SetRemote(t, remoteBlob, remoteIdentity)

		result := cli.Run(t, "sshctl", nil, "--json", "list")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"cached": "CACHED_SNAPSHOT_SECRET", "remote": "REMOTE_SNAPSHOT_SECRET",
			"token": "REMOTE_REPLACEMENT_TOKEN_SECRET",
		})
		items, ok := decodeExactlyOneJSONValue(t, result.Stdout).([]any)
		if result.ProcessExit != 0 || result.Stderr != "" || !ok || len(items) != 1 {
			t.Fatalf("changed remote list output=%s", compiledOutputIdentity(result))
		}
		item, ok := items[0].(map[string]any)
		if !ok || item["name"] != "remote" {
			t.Fatalf("changed remote list = %#v", items)
		}
		if after := cli.VaultBlob(t); !bytes.Equal(after, remoteBlob) {
			t.Fatal("compiled refresh did not atomically commit the opaque remote blob")
		}
		if sync.MethodCount(http.MethodHead) != 1 || sync.MethodCount(http.MethodGet) != 1 || sync.MethodCount(http.MethodPut) != 0 {
			t.Fatalf(
				"changed remote requests HEAD=%d GET=%d PUT=%d",
				sync.MethodCount(http.MethodHead), sync.MethodCount(http.MethodGet), sync.MethodCount(http.MethodPut),
			)
		}
	})

	t.Run("present invalid configuration is one failure across inventory families", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{
			Name: "alpha", Host: "192.0.2.20", Port: 22, User: "runner", Password: "fixture-only",
		}}})
		cli.writeConfigFile(t, "cloud.json", []byte(`{"server":"https://sync.invalid","token":"MATRIX_SECRET"`))

		commands := []struct {
			name       string
			executable string
			input      []byte
			args       []string
		}{
			{name: "list", executable: "sshctl", args: []string{"--json", "list"}},
			{name: "legacy list", executable: "ssm", args: []string{"--json", "list"}},
			{name: "status", executable: "sshctl", args: []string{"--json", "status"}},
			{name: "doctor", executable: "sshctl", args: []string{"--json", "doctor"}},
			{name: "check", executable: "sshctl", args: []string{"--json", "check", "alpha"}},
			{name: "run plan", executable: "sshctl", args: []string{"--json", "run", "alpha", "--plan", "--argv", "true"}},
			{name: "map plan", executable: "sshctl", args: []string{"--json", "map", "alpha", "--plan", "--argv", "true"}},
			{
				name: "put", executable: "sshctl",
				args: []string{"--json", "put", "alpha", filepath.Join(cli.home, "missing"), "/tmp/target"},
			},
			{
				name: "get", executable: "sshctl",
				args: []string{"--json", "get", "alpha", "/tmp/source", filepath.Join(cli.home, "target")},
			},
			{name: "host list", executable: "sshctl", args: []string{"--json", "host", "list"}},
			{name: "host search", executable: "sshctl", args: []string{"--json", "host", "search", "alpha"}},
			{name: "host show", executable: "sshctl", args: []string{"--json", "host", "show", "alpha"}},
			{
				name: "host mutation", executable: "sshctl",
				args: []string{"--json", "host", "update", "alpha", "--group", "changed"},
			},
			{name: "host key", executable: "sshctl", args: []string{"--json", "host-key", "inspect", "alpha"}},
			{name: "legacy keys", executable: "ssm", args: []string{"--json", "keys"}},
			{name: "explicit pull", executable: "sshctl", args: []string{"--json", "pull"}},
			{name: "explicit sync", executable: "sshctl", args: []string{"--json", "sync"}},
			{name: "pull if changed", executable: "ssm", args: []string{"--json", "pull-if-changed"}},
			{name: "push", executable: "sshctl", args: []string{"--json", "push", "--all"}},
			{name: "remote identity", executable: "ssm", args: []string{"--json", "remote-hash"}},
			{
				name: "request v1", executable: "sshctl",
				input: []byte(`{"version":1,"op":"plan","alias":"alpha","argv":["true"]}`),
				args:  []string{"--json", "request"},
			},
			{
				name: "stream initialization", executable: "sshctl", input: []byte("[\"true\"]\n"),
				args: []string{"--json", "run", "alpha", "--stream", "--refresh=1ms"},
			},
		}
		for _, command := range commands {
			t.Run(command.name, func(t *testing.T) {
				result := cli.Run(t, command.executable, command.input, command.args...)
				assertNoCompiledCanaryLeak(t, result, map[string]string{"cloud_value": "MATRIX_SECRET", "config_content": "sync.invalid"})
				assertCompiledMachineContract(t, result, compiledMachineContract{
					OK: false, Error: "sync_config_error", Stage: "sync_config", JSONExit: 1, ProcessExit: 1,
					Hint: "repair sync configuration or retry explicitly with --offline",
				})
			})
		}
	})

	t.Run("import and legacy removals stop before mutation on configuration and refresh failures", func(t *testing.T) {
		commands := []struct {
			name string
			args func(importPath string) []string
		}{
			{name: "connection removal", args: func(string) []string { return []string{"--json", "remove", "alpha"} }},
			{name: "key removal", args: func(string) []string { return []string{"--json", "keys", "remove", "alpha-key"} }},
			{name: "import", args: func(importPath string) []string {
				return []string{"--json", "import-json", importPath, "--merge"}
			}},
		}
		states := []struct {
			name      string
			contract  compiledMachineContract
			configure func(*testing.T, *compiledCLIHarness) *compiledSyncFixture
		}{
			{
				name: "malformed configuration",
				contract: compiledMachineContract{
					OK: false, Error: "sync_config_error", Stage: "sync_config", JSONExit: 1, ProcessExit: 1,
					Hint: "repair sync configuration or retry explicitly with --offline",
				},
				configure: func(t *testing.T, cli *compiledCLIHarness) *compiledSyncFixture {
					cli.writeConfigFile(t, "cloud.json", []byte(`{"server":"https://sync.invalid","token":"MUTATION_CONFIG_SECRET"`))
					return nil
				},
			},
			{
				name: "unreadable configuration",
				contract: compiledMachineContract{
					OK: false, Error: "sync_config_error", Stage: "sync_config", JSONExit: 1, ProcessExit: 1,
					Hint: "repair sync configuration or retry explicitly with --offline",
				},
				configure: func(t *testing.T, cli *compiledCLIHarness) *compiledSyncFixture {
					path := filepath.Join(cli.home, ".config", "ssm", "cloud.json")
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatalf("create unreadable mutation configuration: %v", err)
					}
					return nil
				},
			},
			{
				name: "refresh failure",
				contract: compiledMachineContract{
					OK: false, Error: "sync_pull_failed", Stage: "sync_pull", JSONExit: 1, ProcessExit: 1,
					Hint: "fix sync connectivity or retry explicitly with --offline",
				},
				configure: func(t *testing.T, cli *compiledCLIHarness) *compiledSyncFixture {
					sync := newCompiledSyncFixture(t)
					sync.SetStatus(t, http.MethodHead, http.StatusInternalServerError)
					cli.SaveCloud(t, sync.URL(), "MUTATION_REFRESH_SECRET")
					return sync
				},
			},
		}

		for _, state := range states {
			t.Run(state.name, func(t *testing.T) {
				for _, command := range commands {
					t.Run(command.name, func(t *testing.T) {
						cli := newCompiledCLIHarness(t)
						starting := &config.Vault{
							Connections: []config.Connection{{
								Name: "alpha", Host: "192.0.2.20", Port: 22, User: "runner", Password: "MUTATION_VAULT_SECRET",
							}},
							Keys: []config.SSHKey{{Name: "alpha-key", PrivateKey: "MUTATION_KEY_SECRET"}},
						}
						cli.SaveVault(t, starting)
						importPath := filepath.Join(cli.temp, "import.json")
						if err := os.WriteFile(importPath, []byte(
							`[{"alias":"imported","host":"192.0.2.21","port":22,"user":"runner","auth_type":"password","password":"MUTATION_IMPORT_SECRET"}]`,
						), 0o600); err != nil {
							t.Fatalf("write import fixture: %v", err)
						}
						sync := state.configure(t, cli)

						result := cli.Run(t, "ssm", nil, command.args(importPath)...)
						assertNoCompiledCanaryLeak(t, result, map[string]string{ //nolint:gosec // test-only fake credential canaries
							"configuration": "sync.invalid",
							"config_token":  "MUTATION_CONFIG_SECRET",
							"refresh_token": "MUTATION_REFRESH_SECRET",
							"vault":         "MUTATION_VAULT_SECRET",
							"key":           "MUTATION_KEY_SECRET",
							"import":        "MUTATION_IMPORT_SECRET",
						})
						assertCompiledMachineContract(t, result, state.contract)
						assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), starting)
						if sync != nil {
							if got := sync.MethodCount(http.MethodHead); got != 1 {
								t.Fatalf("refresh failure HEAD count = %d, want 1", got)
							}
							for _, method := range []string{http.MethodGet, http.MethodPut} {
								if got := sync.MethodCount(method); got != 0 {
									t.Fatalf("refresh failure %s count = %d, want 0", method, got)
								}
							}
						}
					})
				}
			})
		}
	})

	t.Run("explicit pull preserves two-sided conflict without GET or local overwrite", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{ //nolint:gosec // test-only fake credential canary
			Name: "local", Host: "192.0.2.30", Port: 22, User: "runner", Password: "PULL_LOCAL_SECRET",
		}}})
		localBlob := cli.VaultBlob(t)
		sync.SetRemote(t, []byte("different opaque encrypted remote blob"), "pull-remote-current")
		cli.SaveCloud(t, sync.URL(), "PULL_CONFIG_SECRET")
		cli.SaveRemoteETag(t, "pull-remote-previous")

		result := cli.Run(t, "sshctl", nil, "--json", "pull")
		assertNoCompiledCanaryLeak(t, result, map[string]string{ //nolint:gosec // test-only fake credential canaries
			"vault": "PULL_LOCAL_SECRET", "token": "PULL_CONFIG_SECRET",
		})
		assertCompiledMachineContract(t, result, compiledMachineContract{
			OK: false, Error: "sync_conflict", Stage: "sync_compare", JSONExit: 1, ProcessExit: 1,
			Hint: "local and remote blobs were preserved; inspect sshctl --offline --json doctor, then explicitly pull or push after review",
		})
		if got := sync.MethodCount(http.MethodHead); got != 1 {
			t.Fatalf("explicit pull HEAD count = %d, want 1", got)
		}
		for _, method := range []string{http.MethodGet, http.MethodPut} {
			if got := sync.MethodCount(method); got != 0 {
				t.Fatalf("explicit pull %s count = %d, want 0", method, got)
			}
		}
		if after := cli.VaultBlob(t); !bytes.Equal(after, localBlob) {
			t.Fatal("explicit pull overwrote the local encrypted blob during conflict")
		}
		evidenceData, err := os.ReadFile(filepath.Join(cli.home, ".config", "ssm", "sync-conflict.json"))
		if err != nil {
			t.Fatalf("read explicit pull conflict evidence: %v", err)
		}
		var evidence struct {
			Local  string `json:"local_etag"`
			Remote string `json:"remote_etag"`
			Cached string `json:"cached_etag"`
		}
		if err := json.Unmarshal(evidenceData, &evidence); err != nil {
			t.Fatalf("decode explicit pull conflict evidence: %v", err)
		}
		wantLocal := fmt.Sprintf("%x", sha256.Sum256(localBlob))
		if evidence.Local != wantLocal || evidence.Remote != "pull-remote-current" || evidence.Cached != "pull-remote-previous" {
			t.Fatalf("explicit pull conflict identities = %+v", evidence)
		}
	})

	t.Run("explicit push preserves two-sided conflict without PUT or local overwrite", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{ //nolint:gosec // test-only fake credential canary
			Name: "local", Host: "192.0.2.31", Port: 22, User: "runner", Password: "PUSH_LOCAL_SECRET",
		}}})
		localBlob := cli.VaultBlob(t)
		sync.SetRemote(t, []byte("different opaque encrypted remote blob"), "push-remote-current")
		cli.SaveCloud(t, sync.URL(), "PUSH_CONFIG_SECRET")
		cli.SaveRemoteETag(t, "push-remote-previous")

		result := cli.Run(t, "sshctl", nil, "--json", "push", "--all")
		assertNoCompiledCanaryLeak(t, result, map[string]string{ //nolint:gosec // test-only fake credential canaries
			"vault": "PUSH_LOCAL_SECRET", "token": "PUSH_CONFIG_SECRET",
		})
		assertCompiledMachineContract(t, result, compiledMachineContract{
			OK: false, Error: "sync_conflict", Stage: "sync_compare", JSONExit: 1, ProcessExit: 1,
			Hint: "local and remote blobs were preserved; inspect sshctl --offline --json doctor, then explicitly pull or push after review",
		})
		if got := sync.MethodCount(http.MethodHead); got != 1 {
			t.Fatalf("explicit push HEAD count = %d, want 1", got)
		}
		for _, method := range []string{http.MethodGet, http.MethodPut} {
			if got := sync.MethodCount(method); got != 0 {
				t.Fatalf("explicit push %s count = %d, want 0", method, got)
			}
		}
		if after := cli.VaultBlob(t); !bytes.Equal(after, localBlob) {
			t.Fatal("explicit push rewrote the local encrypted blob during conflict")
		}
		evidenceData, err := os.ReadFile(filepath.Join(cli.home, ".config", "ssm", "sync-conflict.json"))
		if err != nil {
			t.Fatalf("read explicit push conflict evidence: %v", err)
		}
		var evidence struct {
			Local  string `json:"local_etag"`
			Remote string `json:"remote_etag"`
			Cached string `json:"cached_etag"`
		}
		if err := json.Unmarshal(evidenceData, &evidence); err != nil {
			t.Fatalf("decode explicit push conflict evidence: %v", err)
		}
		wantLocal := fmt.Sprintf("%x", sha256.Sum256(localBlob))
		if evidence.Local != wantLocal || evidence.Remote != "push-remote-current" || evidence.Cached != "push-remote-previous" {
			t.Fatalf("explicit push conflict identities = %+v", evidence)
		}
	})

	t.Run("explicit offline uses cached state with zero sync requests", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		cli.SaveVault(t, &config.Vault{
			Connections: []config.Connection{{ //nolint:gosec // test-only fake credential canary
				Name: "cached", Host: "192.0.2.42", Port: 22, User: "runner", Password: "OFFLINE_CACHED_SECRET",
			}},
			Keys: []config.SSHKey{{Name: "cached-key", PrivateKey: "OFFLINE_KEY_SECRET"}},
		})
		cachedBlob := cli.VaultBlob(t)
		cachedIdentity := fmt.Sprintf("%x", sha256.Sum256(cachedBlob))
		cli.SaveRemoteETag(t, cachedIdentity)
		conflictData, err := json.Marshal(map[string]string{
			"detected_at": "2026-07-28T12:00:00Z",
			"local_etag":  cachedIdentity, "remote_etag": "offline-remote-changed", "cached_etag": "offline-cached",
		})
		if err != nil {
			t.Fatal(err)
		}
		cli.writeConfigFile(t, "sync-conflict.json", conflictData)
		sync.SetRemote(t, []byte("unused changed opaque remote blob"), "offline-remote-changed")
		cli.writeConfigFile(
			t,
			"cloud.json",
			[]byte(`{"server":"`+sync.URL()+`","token":"OFFLINE_MATRIX_SECRET"`),
		)
		settings := config.DefaultSettings()
		settings.LastPull = "2020-01-02T03:04:05Z"
		settingsData, err := json.Marshal(settings)
		if err != nil {
			t.Fatal(err)
		}
		cli.writeConfigFile(t, "settings.json", settingsData)

		listResult := cli.Run(t, "sshctl", nil, "--offline", "--json", "list")
		list, ok := decodeExactlyOneJSONValue(t, listResult.Stdout).([]any)
		if listResult.ProcessExit != 0 || listResult.Stderr != "" || !ok || len(list) != 1 {
			t.Fatalf("offline cached list output=%s", compiledOutputIdentity(listResult))
		}
		listHost, ok := list[0].(map[string]any)
		if !ok || listHost["name"] != "cached" {
			t.Fatalf("offline cached list = %#v", list)
		}

		hostListResult := cli.Run(t, "sshctl", nil, "--json", "host", "list", "--offline")
		hostList, ok := decodeExactlyOneJSONValue(t, hostListResult.Stdout).([]any)
		if hostListResult.ProcessExit != 0 || hostListResult.Stderr != "" || !ok || len(hostList) != 1 {
			t.Fatalf("offline host list output=%s", compiledOutputIdentity(hostListResult))
		}
		status := assertCompiledJSONSuccess(t, cli.Run(t, "sshctl", nil, "--offline", "--json", "status"))
		if status["offline"] != true ||
			status["freshness"] != "cached" ||
			status["remote_state"] != "not_checked" ||
			status["last_pull"] != settings.LastPull ||
			status["last_sync"] != settings.LastPull {
			t.Fatalf("offline status vocabulary changed: %s", compiledOutputIdentity(cli.Run(t, "sshctl", nil, "--offline", "--json", "status")))
		}
		doctor := assertCompiledJSONSuccess(t, cli.Run(t, "sshctl", nil, "--offline", "--json", "doctor"))
		if doctor["offline"] != true ||
			doctor["freshness"] != "cached" ||
			doctor["remote_state"] != "not_checked" ||
			doctor["last_pull"] != settings.LastPull ||
			doctor["last_sync"] != settings.LastPull {
			t.Fatalf("offline doctor vocabulary = %#v", doctor)
		}
		for _, field := range []string{
			"sync", "freshness", "remote_state", "offline", "last_pull", "last_sync", "sync_conflict",
		} {
			if !reflect.DeepEqual(status[field], doctor[field]) {
				t.Fatalf("status/doctor %s mismatch: status=%#v doctor=%#v", field, status[field], doctor[field])
			}
		}
		statusAge, statusAgeOK := status["cache_age_seconds"].(float64)
		doctorAge, doctorAgeOK := doctor["cache_age_seconds"].(float64)
		if !statusAgeOK || !doctorAgeOK || statusAge <= 0 || doctorAge <= 0 || math.Abs(statusAge-doctorAge) > 1 {
			t.Fatalf("status/doctor cache age mismatch: status=%#v doctor=%#v", status["cache_age_seconds"], doctor["cache_age_seconds"])
		}

		requestInput := []byte(`{"version":1,"op":"plan","alias":"cached","argv":["true"]}`)
		importPath := filepath.Join(cli.temp, "offline-import.json")
		if err := os.WriteFile(
			importPath,
			[]byte(`[{"alias":"imported","host":"192.0.2.43","port":22,"user":"runner","auth_type":"password","password":"OFFLINE_IMPORT_SECRET"}]`),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		offlineCommands := []struct {
			name       string
			executable string
			input      []byte
			args       []string
		}{
			{name: "legacy list", executable: "ssm", args: []string{"--offline", "--json", "list"}},
			{name: "host search", executable: "sshctl", args: []string{"--offline", "--json", "host", "search", "cached"}},
			{name: "host show", executable: "sshctl", args: []string{"--offline", "--json", "host", "show", "cached"}},
			{name: "host mutation", executable: "sshctl", args: []string{"--json", "host", "update", "cached", "--group", "offline", "--offline"}},
			{name: "run plan", executable: "sshctl", args: []string{"--offline", "--json", "run", "cached", "--plan", "--argv", "true"}},
			{name: "map plan", executable: "sshctl", args: []string{"--offline", "--json", "map", "cached", "--plan", "--argv", "true"}},
			{name: "check", executable: "sshctl", args: []string{"--offline", "--json", "check", "missing"}},
			{
				name: "put", executable: "sshctl",
				args: []string{"--offline", "--json", "put", "cached", filepath.Join(cli.home, "missing"), "/tmp/target"},
			},
			{
				name: "get", executable: "sshctl",
				args: []string{"--offline", "--json", "get", "missing", "/tmp/source", filepath.Join(cli.home, "target")},
			},
			{name: "host key", executable: "sshctl", args: []string{"--offline", "--json", "host-key", "inspect", "missing"}},
			{name: "legacy keys", executable: "ssm", args: []string{"--offline", "--json", "keys"}},
			{name: "request v1", executable: "sshctl", input: requestInput, args: []string{"--offline", "--json", "request"}},
			{
				name: "stream initialization", executable: "sshctl", input: []byte("[\"true\"]\n"),
				args: []string{"--offline", "--json", "run", "missing", "--stream", "--refresh=0"},
			},
			{name: "explicit pull", executable: "sshctl", args: []string{"--offline", "--json", "pull"}},
			{name: "explicit sync", executable: "sshctl", args: []string{"--offline", "--json", "sync"}},
			{name: "pull if changed", executable: "ssm", args: []string{"--offline", "--json", "pull-if-changed"}},
			{name: "push", executable: "sshctl", args: []string{"--offline", "--json", "push", "--all"}},
			{name: "remote identity", executable: "ssm", args: []string{"--offline", "--json", "remote-hash"}},
			{name: "legacy remove", executable: "ssm", args: []string{"--offline", "--json", "remove", "cached"}},
			{name: "legacy key remove", executable: "ssm", args: []string{"--offline", "--json", "keys", "remove", "cached-key"}},
			{
				name: "import", executable: "ssm",
				args: []string{"--offline", "--json", "import-json", importPath, "--merge"},
			},
		}
		for _, command := range offlineCommands {
			t.Run(command.name, func(t *testing.T) {
				result := cli.Run(t, command.executable, command.input, command.args...)
				assertNoCompiledCanaryLeak(t, result, map[string]string{
					"cloud": "OFFLINE_MATRIX_SECRET", "cached": "OFFLINE_CACHED_SECRET",
					"key": "OFFLINE_KEY_SECRET", "import": "OFFLINE_IMPORT_SECRET",
				})
			})
		}
		for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
			if got := sync.MethodCount(method); got != 0 {
				t.Fatalf("offline %s requests = %d, want 0", method, got)
			}
		}
		if after := cli.VaultBlob(t); bytes.Equal(after, []byte("unused changed opaque remote blob")) {
			t.Fatal("offline command selected the remote opaque blob")
		}
	})
}

func TestCompiledConfirmedSyncMetadataFailuresRemainSuccessful(t *testing.T) {
	outputModes := []struct {
		name string
		args func(...string) []string
	}{
		{
			name: "json",
			args: func(args ...string) []string {
				return append([]string{"--json"}, args...)
			},
		},
		{name: "human", args: func(args ...string) []string { return args }},
	}

	t.Run("scoped push keeps the selected ledger finalized after confirmed PUT", func(t *testing.T) {
		for _, mode := range outputModes {
			t.Run(mode.name, func(t *testing.T) {
				cli := newCompiledCLIHarness(t)
				sync := newCompiledSyncFixture(t)
				tokenCanary := "ISSUE20_PUBLIC_METADATA_PUSH_TOKEN_CANARY" //nolint:gosec // test-only fake credential canary
				connection := config.Connection{                           //nolint:gosec // test-only fake credential canary
					Name: "metadata-push", Host: "192.0.2.80", Port: 22, User: "runner",
					Password: "ISSUE20_PUBLIC_METADATA_PUSH_VAULT_CANARY",
				}
				starting := &config.Vault{
					Connections: []config.Connection{connection},
					PendingBase: &config.InventorySnapshot{},
					PendingMutations: []config.PendingMutation{{
						ID: "tx_metadata_push", Alias: connection.Name, Operation: "created",
						CreatedAt: "2026-07-28T14:30:00Z", After: &connection,
					}},
				}
				cli.SaveVault(t, starting)
				sync.SetRemote(t, nil, "confirmed-public-put")
				cli.SaveCloud(t, sync.URL(), tokenCanary)
				configDir := filepath.Join(cli.home, ".config", "ssm")
				if err := os.Mkdir(filepath.Join(configDir, "remote.etag"), 0o700); err != nil {
					t.Fatal(err)
				}
				cli.writeConfigFile(t, "sync-conflict.json", []byte(
					`{"detected_at":"2026-07-28T14:29:00Z","local_etag":"opaque-local","remote_etag":"opaque-remote","cached_etag":"opaque-cached"}`,
				))

				result := cli.Run(t, "sshctl", nil, mode.args("push", "--only", "tx_metadata_push")...)
				assertNoCompiledCanaryLeak(t, result, map[string]string{
					"token": tokenCanary, "vault": connection.Password,
					"passphrase": cli.passphrase, "config_path": configDir,
				})
				switch mode.name {
				case "json":
					value := assertCompiledJSONSuccess(t, result)
					if value["action"] != "pushed" ||
						value["scope"] != "only" ||
						value["transaction_id"] != "tx_metadata_push" {
						t.Fatalf("confirmed push JSON = %#v", value)
					}
					if _, found := value["error"]; found {
						t.Fatalf("confirmed push emitted a failure field: %#v", value)
					}
				case "human":
					assertCompiledHumanSuccess(t, result, "Vault pushed to cloud.")
					if strings.Contains(result.Stdout, "sync refresh failed") {
						t.Fatalf("confirmed push emitted a human failure: %s", compiledOutputIdentity(result))
					}
				}
				if got := sync.MethodCount(http.MethodPut); got != 1 {
					t.Fatalf("confirmed push PUT count = %d, want 1", got)
				}
				if got := sync.MethodCount(http.MethodHead); got != 0 {
					t.Fatalf("confirmed push HEAD count = %d, want 0 without cached identity", got)
				}
				finalized := &config.Vault{Connections: []config.Connection{connection}}
				assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), finalized)
				assertCompiledEncryptedPublication(t, sync.UploadedBlob(), cli.passphrase, map[string]string{
					"vault": connection.Password, "token": tokenCanary, "passphrase": cli.passphrase,
				}, finalized)
				if _, err := os.Stat(filepath.Join(configDir, "sync-conflict.json")); !os.IsNotExist(err) {
					t.Fatalf("confirmed push conflict metadata was not cleared: %v", err)
				}
			})
		}
	})

	t.Run("pull and refresh keep the confirmed local replacement after metadata failure", func(t *testing.T) {
		operations := []struct {
			name string
			args []string
		}{
			{name: "pull", args: []string{"pull"}},
			{name: "refresh", args: []string{"list"}},
		}
		for _, operation := range operations {
			t.Run(operation.name, func(t *testing.T) {
				for _, mode := range outputModes {
					t.Run(mode.name, func(t *testing.T) {
						cli := newCompiledCLIHarness(t)
						sync := newCompiledSyncFixture(t)
						tokenCanary := "ISSUE20_PUBLIC_METADATA_PULL_TOKEN_CANARY" //nolint:gosec // test-only fake credential canary
						local := &config.Vault{Connections: []config.Connection{{  //nolint:gosec // test-only fake credential canary
							Name: "metadata-local", Host: "192.0.2.81", Port: 22, User: "runner",
							Password: "ISSUE20_PUBLIC_METADATA_PULL_LOCAL_CANARY",
						}}}
						remote := &config.Vault{Connections: []config.Connection{{ //nolint:gosec // test-only fake credential canary
							Name: "metadata-remote", Host: "192.0.2.82", Port: 22, User: "runner",
							Password: "ISSUE20_PUBLIC_METADATA_PULL_REMOTE_CANARY",
						}}}
						cli.SaveVault(t, local)
						localBlob := cli.VaultBlob(t)
						cachedIdentity := fmt.Sprintf("%x", sha256.Sum256(localBlob))
						cli.SaveRemoteETag(t, cachedIdentity)
						remoteBlob, err := config.EncryptVault(remote, cli.passphrase)
						if err != nil {
							t.Fatal(err)
						}
						sync.SetRemote(t, remoteBlob, "confirmed-public-get")
						cli.SaveCloud(t, sync.URL(), tokenCanary)
						configDir := filepath.Join(cli.home, ".config", "ssm")
						cli.writeConfigFile(t, "sync-conflict.json", []byte(
							`{"detected_at":"2026-07-28T14:39:00Z","local_etag":"opaque-local","remote_etag":"opaque-remote","cached_etag":"opaque-cached"}`,
						))
						if err := os.Mkdir(filepath.Join(configDir, "settings.json"), 0o700); err != nil {
							t.Fatal(err)
						}

						result := cli.Run(t, "sshctl", nil, mode.args(operation.args...)...)
						assertNoCompiledCanaryLeak(t, result, map[string]string{
							"token": tokenCanary,
							"local": local.Connections[0].Password, "remote": remote.Connections[0].Password,
							"passphrase": cli.passphrase, "config_path": configDir,
						})
						switch operation.name {
						case "pull":
							switch mode.name {
							case "json":
								value := assertCompiledJSONSuccess(t, result)
								if value["action"] != "pulled" {
									t.Fatalf("confirmed pull JSON = %#v", value)
								}
								if _, found := value["error"]; found {
									t.Fatalf("confirmed pull emitted a failure field: %#v", value)
								}
							case "human":
								assertCompiledHumanSuccess(t, result, "Vault pulled from cloud.")
							}
						case "refresh":
							switch mode.name {
							case "json":
								value := decodeExactlyOneJSONValue(t, result.Stdout)
								items, ok := value.([]any)
								if result.ProcessExit != 0 || result.Stderr != "" || !ok || len(items) != 1 {
									t.Fatalf("confirmed refresh JSON output=%s", compiledOutputIdentity(result))
								}
								host, ok := items[0].(map[string]any)
								if !ok || host["name"] != "metadata-remote" {
									t.Fatalf("confirmed refresh used stale inventory: %#v", items)
								}
							case "human":
								assertCompiledHumanSuccess(t, result, "metadata-remote")
							}
						}
						if strings.Contains(result.Stdout, "sync refresh failed") {
							t.Fatalf("confirmed %s emitted a human failure: %s", operation.name, compiledOutputIdentity(result))
						}
						if got := sync.MethodCount(http.MethodHead); got != 1 {
							t.Fatalf("confirmed %s HEAD count = %d, want 1", operation.name, got)
						}
						if got := sync.MethodCount(http.MethodGet); got != 1 {
							t.Fatalf("confirmed %s GET count = %d, want 1", operation.name, got)
						}
						if after := cli.VaultBlob(t); !bytes.Equal(after, remoteBlob) {
							t.Fatalf("confirmed %s did not preserve the local opaque replacement", operation.name)
						}
						assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), remote)
						identity, readErr := os.ReadFile(filepath.Join(configDir, "remote.etag")) //nolint:gosec // path is fixed beneath the harness-owned temporary home
						if readErr != nil || strings.TrimSpace(string(identity)) != "confirmed-public-get" {
							t.Fatalf("confirmed %s identity = %q err=%v", operation.name, identity, readErr)
						}
						if _, err := os.Stat(filepath.Join(configDir, "sync-conflict.json")); !os.IsNotExist(err) {
							t.Fatalf("confirmed %s conflict metadata was not cleared: %v", operation.name, err)
						}
					})
				}
			})
		}
	})
}

func TestMajorUpdateReviewIsNonInteractive(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	cli.SaveVault(t, &config.Vault{})
	cli.writeConfigFile(t, "update_repo", []byte("fixture/repo\n"))
	compiledUpdateServer.ConfigureRelease("v2.0.0", []byte("UNAUTHORIZED_REPLACEMENT_MUST_NOT_BE_READ\n"))
	before := loadCompiledFileIdentity(t, cli.paths["ssm"])

	result := cli.RunWithHeldOpenStdinAndEnv(t, "ssm", map[string]string{"SSM_UPDATE_REPO": "fixture/repo"}, "--json", "update", "--major")
	if result.ProcessExit != 0 || result.Stderr != "" {
		t.Fatalf("major review exit=%d stderr=%q requests=%q output=%s", result.ProcessExit, result.Stderr, compiledUpdateServer.RequestPaths(), compiledOutputIdentity(result))
	}
	var review map[string]any
	if err := json.Unmarshal([]byte(result.Stdout), &review); err != nil {
		t.Fatalf("major review is not one JSON document: %v: %q", err, result.Stdout)
	}
	if review["target"] != "v2.0.0" || review["authorized"] != false ||
		review["authorization_state"] != "not_authorized" || review["installed"] != false {
		t.Fatalf("major review authorization fields = %#v", review)
	}
	changes, ok := review["breaking_changes"].([]any)
	if !ok || len(changes) != 10 {
		t.Fatalf("major review breaking changes = %#v", review["breaking_changes"])
	}

	human := cli.RunWithHeldOpenStdinAndEnv(t, "ssm", map[string]string{"SSM_UPDATE_REPO": "fixture/repo"}, "update", "--major")
	if human.ProcessExit != 0 || human.Stderr != "" {
		t.Fatalf("human major review exit=%d stderr=%q output=%s", human.ProcessExit, human.Stderr, compiledOutputIdentity(human))
	}
	authorizationState, ok := review["authorization_state"].(string)
	if !ok || !strings.Contains(human.Stdout, "\nAuthorization: "+authorizationState+"\nRelease notes:\n") || strings.Contains(human.Stdout, "%!(EXTRA") {
		t.Fatalf("human migration authorization output: %q", human.Stdout)
	}
	assertCompiledFileUnchanged(t, cli.paths["ssm"], before)
	if got := compiledUpdateServer.RequestPaths(); !reflect.DeepEqual(got, []string{"/repos/fixture/repo/releases", "/repos/fixture/repo/releases"}) {
		t.Fatalf("non-authorized review downloaded an artifact: %q", got)
	}
}
