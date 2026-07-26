package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	statusPassed                = "passed"
	statusPassedWithUnavailable = "passed_with_unavailable"
	statusUnavailable           = "unavailable"
	statusFailed                = "failed"
)

type prerequisiteState struct {
	available bool
	detail    string
}

type actionContext struct {
	RepoRoot string
	TempDir  string
	Version  string
	Stdout   io.Writer
	Stderr   io.Writer
}

type checkResult struct {
	ID     string `json:"id,omitempty"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type profileResult struct {
	Profile string        `json:"profile"`
	Status  string        `json:"status"`
	Checks  []checkResult `json:"checks"`
}

type actionExecutor interface {
	Execute(context.Context, Action, actionContext) checkResult
}

type actionExecutorFunc func(context.Context, Action, actionContext) checkResult

func (function actionExecutorFunc) Execute(ctx context.Context, action Action, actionCtx actionContext) checkResult {
	return function(ctx, action, actionCtx)
}

type systemActionExecutor struct{}

func (systemActionExecutor) Execute(ctx context.Context, action Action, actionCtx actionContext) checkResult {
	switch action.Kind {
	case actionCommand:
		if action.Command == nil {
			return checkResult{Status: statusFailed, Detail: "command action has no command"}
		}
		return executeCommand(ctx, *action.Command, actionCtx)
	case actionExtension:
		return checkResult{Status: statusUnavailable, Detail: action.Reason}
	case actionBuiltin:
		return executeBuiltin(action.Name, actionCtx)
	default:
		return checkResult{Status: statusFailed, Detail: "unknown action kind: " + action.Kind}
	}
}

type runtimeDependencies struct {
	repoRoot      string
	stdout        io.Writer
	stderr        io.Writer
	prerequisites func(Prerequisite) prerequisiteState
	actions       actionExecutor
}

func executeCommand(ctx context.Context, specification Command, actionCtx actionContext) checkResult {
	args := make([]string, len(specification.Args))
	for index, arg := range specification.Args {
		args[index] = expandActionValue(arg, actionCtx)
	}
	command := exec.CommandContext(ctx, specification.Executable, args...) //nolint:gosec // executable and argv come only from the validated checked-in manifest
	command.Dir = actionCtx.RepoRoot
	command.Env = os.Environ()
	for _, environment := range specification.Env {
		command.Env = append(command.Env, expandActionValue(environment, actionCtx))
	}

	stdoutWriter := actionCtx.Stdout
	if stdoutWriter == nil {
		stdoutWriter = io.Discard
	}
	stderrWriter := actionCtx.Stderr
	if stderrWriter == nil {
		stderrWriter = io.Discard
	}
	var stdout bytes.Buffer
	command.Stdout = io.MultiWriter(stdoutWriter, &stdout)
	command.Stderr = stderrWriter
	if err := command.Run(); err != nil {
		return checkResult{Status: statusFailed, Detail: err.Error()}
	}
	if specification.Expect == "stdout_empty" && strings.TrimSpace(stdout.String()) != "" {
		return checkResult{Status: statusFailed, Detail: "command produced output; repository is not formatted"}
	}
	return checkResult{Status: statusPassed}
}

func expandActionValue(value string, actionCtx actionContext) string {
	value = strings.ReplaceAll(value, "{temp}", actionCtx.TempDir)
	value = strings.ReplaceAll(value, "{exe}", executableSuffix())
	value = strings.ReplaceAll(value, "{version}", actionCtx.Version)
	return value
}

func executeBuiltin(name string, actionCtx actionContext) checkResult {
	switch name {
	case "source-version":
		version, err := readSourceVersion(actionCtx.RepoRoot)
		if err != nil {
			return checkResult{Status: statusFailed, Detail: err.Error()}
		}
		return checkResult{Status: statusPassed, Detail: version}
	case "release-notes":
		version, err := readSourceVersion(actionCtx.RepoRoot)
		if err != nil {
			return checkResult{Status: statusFailed, Detail: err.Error()}
		}
		if err := validateReleaseNotes(actionCtx.RepoRoot, version); err != nil {
			return checkResult{Status: statusFailed, Detail: err.Error()}
		}
		return checkResult{Status: statusPassed, Detail: "v" + version}
	case "release-checksums":
		if err := verifyReleaseChecksums(actionCtx); err != nil {
			return checkResult{Status: statusFailed, Detail: err.Error()}
		}
		return checkResult{Status: statusPassed, Detail: "computed SHA-256 for 7 release files"}
	default:
		return checkResult{Status: statusFailed, Detail: "unknown builtin action: " + name}
	}
}

func verifyReleaseChecksums(actionCtx actionContext) error {
	paths := []string{
		filepath.Join(actionCtx.TempDir, "ssm-linux-amd64"),
		filepath.Join(actionCtx.TempDir, "ssm-linux-arm64"),
		filepath.Join(actionCtx.TempDir, "ssm-darwin-amd64"),
		filepath.Join(actionCtx.TempDir, "ssm-darwin-arm64"),
		filepath.Join(actionCtx.TempDir, "ssm-windows-amd64.exe"),
		filepath.Join(actionCtx.TempDir, "ssm-windows-arm64.exe"),
		filepath.Join(actionCtx.RepoRoot, "install.sh"),
	}
	for _, path := range paths {
		file, err := os.Open(path) //nolint:gosec // paths are fixed manifest assets in profile-owned temporary storage
		if err != nil {
			return fmt.Errorf("open release file %s: %w", filepath.Base(path), err)
		}
		info, statErr := file.Stat()
		if statErr != nil {
			_ = file.Close()
			return fmt.Errorf("stat release file %s: %w", filepath.Base(path), statErr)
		}
		if info.Size() == 0 {
			_ = file.Close()
			return fmt.Errorf("release file %s is empty", filepath.Base(path))
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("hash release file %s: %w", filepath.Base(path), copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close release file %s: %w", filepath.Base(path), closeErr)
		}
		if len(hash.Sum(nil)) != sha256.Size {
			return fmt.Errorf("invalid SHA-256 result for %s", filepath.Base(path))
		}
	}
	return nil
}

func readSourceVersion(repoRoot string) (string, error) {
	path := filepath.Join(repoRoot, "cmd", "ssm", "main.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return "", fmt.Errorf("parse source version: %w", err)
	}
	var version string
	ast.Inspect(file, func(node ast.Node) bool {
		specification, ok := node.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for index, name := range specification.Names {
			if name.Name != "version" || index >= len(specification.Values) {
				continue
			}
			literal, ok := specification.Values[index].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				continue
			}
			value, unquoteErr := strconv.Unquote(literal.Value)
			if unquoteErr == nil {
				version = value
			}
		}
		return version == ""
	})
	if !isReleaseVersion(version) {
		return "", fmt.Errorf("source version %q is not an x.y.z release version", version)
	}
	return version, nil
}

func isReleaseVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	return true
}

func validateReleaseNotes(repoRoot, version string) error {
	data, err := os.ReadFile(filepath.Join(repoRoot, "RELEASE_NOTES.md")) //nolint:gosec // fixed tracked release-note path
	if err != nil {
		return fmt.Errorf("read release notes: %w", err)
	}
	header := "## v" + version
	lines := strings.Split(string(data), "\n")
	found := false
	var body []string
	for _, line := range lines {
		if strings.HasPrefix(line, "## v") {
			if !found {
				if line != header {
					return fmt.Errorf("first release-note version is %q, want %q", line, header)
				}
				found = true
				continue
			}
			break
		}
		if found {
			body = append(body, line)
		}
	}
	if !found {
		return fmt.Errorf("release notes have no %q section", header)
	}
	if strings.TrimSpace(strings.Join(body, "\n")) == "" {
		return fmt.Errorf("release-note section %q is empty", header)
	}
	return nil
}

func validateNonMutating(manifest Manifest) error {
	for _, profile := range manifest.Profiles {
		for _, check := range profile.Checks {
			action := check.Action
			switch action.Kind {
			case actionCommand:
				if action.Command == nil {
					return fmt.Errorf("%s/%s: command action has no command", profile.Name, check.ID)
				}
				if err := validateNonMutatingCommand(*action.Command); err != nil {
					return fmt.Errorf("%s/%s: %w", profile.Name, check.ID, err)
				}
			case actionBuiltin:
				switch action.Name {
				case "source-version", "release-notes", "release-checksums":
				default:
					return fmt.Errorf("%s/%s: unknown builtin %q", profile.Name, check.ID, action.Name)
				}
			case actionExtension:
				if check.Requirement != requirementConditional {
					return fmt.Errorf("%s/%s: unavailable extension must be conditional", profile.Name, check.ID)
				}
			default:
				return fmt.Errorf("%s/%s: unknown action kind %q", profile.Name, check.ID, action.Kind)
			}
		}
	}
	return nil
}

func validateNonMutatingCommand(command Command) error {
	switch command.Executable {
	case "gofmt":
		if !equalStrings(command.Args, []string{"-l", "."}) {
			return fmt.Errorf("unreviewed gofmt action %q", strings.Join(command.Args, " "))
		}
	case "go":
		if len(command.Args) == 0 {
			return errors.New("go action has no subcommand")
		}
		switch command.Args[0] {
		case "build":
			output, ok := argumentAfter(command.Args, "-o")
			if !ok || !strings.HasPrefix(output, "{temp}/") {
				return errors.New("go build output must be inside {temp}")
			}
		case "run":
			if !equalStrings(command.Args, []string{
				"run", "golang.org/x/vuln/cmd/govulncheck@v1.6.0", "./...",
			}) {
				return fmt.Errorf("unreviewed go run action %q", strings.Join(command.Args, " "))
			}
		case "test", "vet":
		default:
			return fmt.Errorf("unreviewed go action %q", command.Args[0])
		}
	case "bash":
		if !reflectsApprovedShellCheck(command.Args) {
			return fmt.Errorf("unreviewed bash action %q", strings.Join(command.Args, " "))
		}
	case "golangci-lint":
		if !equalStrings(command.Args, []string{"run", "--new-from-rev=v1.2.0"}) {
			return fmt.Errorf("unreviewed golangci-lint action %q", strings.Join(command.Args, " "))
		}
	case "jq":
		if len(command.Args) != 2 || command.Args[0] != "empty" ||
			(command.Args[1] != "skills/agent-ssm/test-prompts.json" &&
				command.Args[1] != "skills/agent-ssm/references/request-v1.schema.json") {
			return fmt.Errorf("unreviewed jq action %q", strings.Join(command.Args, " "))
		}
	default:
		return fmt.Errorf("executable %q is not allowed in verification profiles", command.Executable)
	}
	return nil
}

func reflectsApprovedShellCheck(args []string) bool {
	return (len(args) == 2 && args[0] == "-n" && args[1] == "scripts/ssh_matrix_test.sh") ||
		(len(args) == 1 && args[0] == "scripts/ssh_matrix_test.sh")
}

func executeProfile(ctx context.Context, manifest Manifest, profileName string, deps runtimeDependencies) (result profileResult, returnErr error) {
	result = profileResult{Profile: profileName, Status: statusPassed}
	profile, ok := findProfile(manifest, profileName)
	if !ok || profileName == "list" {
		return result, fmt.Errorf("unknown executable profile %q", profileName)
	}
	if err := validateNonMutating(manifest); err != nil {
		return result, err
	}
	if deps.prerequisites == nil {
		return result, errors.New("prerequisite checker is required")
	}
	if deps.actions == nil {
		return result, errors.New("action executor is required")
	}

	for _, prerequisite := range profile.Prerequisites {
		state := deps.prerequisites(prerequisite)
		if !state.available {
			return result, fmt.Errorf("profile %s prerequisite unavailable: %s (%s)", profileName, prerequisite.Name, state.detail)
		}
	}

	before, err := trackedState(deps.repoRoot)
	if err != nil {
		return result, err
	}
	defer func() {
		after, stateErr := trackedState(deps.repoRoot)
		if stateErr != nil {
			result.Status = statusFailed
			returnErr = errors.Join(returnErr, stateErr)
			return
		}
		if !bytes.Equal(before, after) {
			result.Status = statusFailed
			returnErr = errors.Join(returnErr, errors.New("verification changed tracked repository state"))
		}
	}()
	tempDir, err := os.MkdirTemp("", "ssm-verify-"+profileName+"-*")
	if err != nil {
		return result, fmt.Errorf("create profile temporary directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tempDir) //nolint:gosec // tempDir is created immediately above by os.MkdirTemp
	}()

	version := ""
	for _, check := range profile.Checks {
		missing := unavailablePrerequisites(check.Prerequisites, deps.prerequisites)
		if len(missing) > 0 {
			detail := "missing prerequisites: " + strings.Join(missing, ", ")
			if check.Requirement == requirementRequired {
				result.Checks = append(result.Checks, checkResult{ID: check.ID, Status: statusFailed, Detail: detail})
				result.Status = statusFailed
				return result, fmt.Errorf("required check %s is unavailable: %s", check.ID, detail)
			}
			result.Checks = append(result.Checks, checkResult{ID: check.ID, Status: statusUnavailable, Detail: detail})
			result.Status = statusPassedWithUnavailable
			continue
		}

		checkResult := deps.actions.Execute(ctx, check.Action, actionContext{
			RepoRoot: deps.repoRoot,
			TempDir:  tempDir,
			Version:  version,
			Stdout:   deps.stdout,
			Stderr:   deps.stderr,
		})
		checkResult.ID = check.ID
		result.Checks = append(result.Checks, checkResult)
		switch checkResult.Status {
		case statusPassed:
			if check.ID == "source-version" {
				version = checkResult.Detail
				if !isReleaseVersion(version) {
					result.Status = statusFailed
					return result, fmt.Errorf("source-version action returned invalid version %q", version)
				}
			}
		case statusUnavailable:
			if check.Requirement == requirementRequired {
				result.Status = statusFailed
				return result, fmt.Errorf("required check %s was unavailable: %s", check.ID, checkResult.Detail)
			}
			result.Status = statusPassedWithUnavailable
		default:
			result.Status = statusFailed
			return result, fmt.Errorf("check %s failed: %s", check.ID, checkResult.Detail)
		}
	}

	return result, nil
}

func unavailablePrerequisites(prerequisites []Prerequisite, checker func(Prerequisite) prerequisiteState) []string {
	var unavailable []string
	for _, prerequisite := range prerequisites {
		state := checker(prerequisite)
		if !state.available {
			detail := prerequisite.Name
			if state.detail != "" {
				detail += " (" + state.detail + ")"
			}
			unavailable = append(unavailable, detail)
		}
	}
	return unavailable
}

func checkPrerequisite(repoRoot string, prerequisite Prerequisite) prerequisiteState {
	switch prerequisite.Kind {
	case "platform":
		if prerequisite.Name == runtime.GOOS {
			return prerequisiteState{available: true, detail: runtime.GOOS}
		}
		return prerequisiteState{detail: "current platform is " + runtime.GOOS}
	case "file":
		path := joinedPath(repoRoot, prerequisite.Name)
		info, err := os.Stat(path)
		if err != nil {
			return prerequisiteState{detail: err.Error()}
		}
		if !info.Mode().IsRegular() {
			return prerequisiteState{detail: "not a regular file"}
		}
		return prerequisiteState{available: true, detail: prerequisite.Version}
	case "tool":
		path, err := exec.LookPath(prerequisite.Name)
		if err != nil {
			return prerequisiteState{detail: "not found in PATH"}
		}
		if prerequisite.Version == "" || prerequisite.Version == "any" {
			return prerequisiteState{available: true, detail: path}
		}
		version, err := toolVersion(prerequisite.Name)
		if err != nil {
			return prerequisiteState{detail: err.Error()}
		}
		if version != prerequisite.Version {
			return prerequisiteState{detail: fmt.Sprintf("found %s, need %s", version, prerequisite.Version)}
		}
		return prerequisiteState{available: true, detail: version}
	default:
		return prerequisiteState{detail: "unknown prerequisite kind " + prerequisite.Kind}
	}
}

func toolVersion(name string) (string, error) {
	switch name {
	case "go", "gofmt":
		output, err := exec.Command("go", "version").Output()
		if err != nil {
			return "", fmt.Errorf("read Go version: %w", err)
		}
		fields := strings.Fields(string(output))
		for _, field := range fields {
			if strings.HasPrefix(field, "go1.") {
				if name == "gofmt" {
					return field, nil
				}
				return strings.TrimPrefix(field, "go"), nil
			}
		}
		return "", errors.New("go version output was not recognized")
	case "golangci-lint":
		output, err := exec.Command(name, "version").Output()
		if err != nil {
			return "", fmt.Errorf("read golangci-lint version: %w", err)
		}
		fields := strings.Fields(string(output))
		for index, field := range fields {
			if field == "version" && index+1 < len(fields) {
				return strings.TrimPrefix(fields[index+1], "v"), nil
			}
		}
		return "", errors.New("golangci-lint version output was not recognized")
	default:
		return "", fmt.Errorf("no version probe is defined for %s", name)
	}
}

func trackedState(repoRoot string) ([]byte, error) {
	command := exec.Command("git", "status", "--porcelain=v1", "--untracked-files=no")
	command.Dir = repoRoot
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("inspect tracked repository state: %w", err)
	}
	return output, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func argumentAfter(args []string, flag string) (string, bool) {
	for index, arg := range args {
		if arg == flag && index+1 < len(args) {
			return args[index+1], true
		}
	}
	return "", false
}

func executableSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func joinedPath(root, slashPath string) string {
	return filepath.Join(append([]string{root}, strings.Split(slashPath, "/")...)...)
}
