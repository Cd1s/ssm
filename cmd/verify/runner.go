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
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"ssm/internal/releaseasset"
)

const (
	statusPassed               = "passed"
	statusPreflightPassed      = "preflight_passed"
	statusCompletedUnavailable = "completed_with_unavailable"
	statusUnavailable          = "unavailable"
	statusFailed               = "failed"
)

type prerequisiteState struct {
	available bool
	detail    string
}

type actionContext struct {
	RepoRoot string
	TempDir  string
	Version  string
	GoRoot   string
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

func executeAction(ctx context.Context, action Action, actionCtx actionContext) checkResult {
	switch action.Kind {
	case actionCommand:
		if action.Command == nil {
			return checkResult{Status: statusFailed, Detail: "command action has no command"}
		}
		return executeCommand(ctx, *action.Command, actionCtx)
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
	actions       func(context.Context, Action, actionContext) checkResult
	removeAll     func(string) error
}

func executeCommand(ctx context.Context, specification Command, actionCtx actionContext) checkResult {
	if strings.Contains(specification.Executable, "{goroot}") && actionCtx.GoRoot == "" {
		goRoot, err := goToolchainRoot()
		if err != nil {
			return checkResult{Status: statusFailed, Detail: err.Error()}
		}
		actionCtx.GoRoot = goRoot
	}
	args := make([]string, len(specification.Args))
	for index, arg := range specification.Args {
		args[index] = expandActionValue(arg, actionCtx)
	}
	executable := expandActionValue(specification.Executable, actionCtx)
	command := exec.CommandContext(ctx, executable, args...) //nolint:gosec // executable and argv come only from the validated checked-in manifest
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
	return expandActionValueForOS(value, actionCtx, runtime.GOOS)
}

func expandActionValueForOS(value string, actionCtx actionContext, goos string) string {
	value = expandPathPlaceholder(value, "{temp}", actionCtx.TempDir, goos)
	value = expandPathPlaceholder(value, "{goroot}", actionCtx.GoRoot, goos)
	value = strings.ReplaceAll(value, "{exe}", executableSuffixFor(goos))
	value = strings.ReplaceAll(value, "{version}", actionCtx.Version)
	return value
}

func expandPathPlaceholder(value, placeholder, root, goos string) string {
	if value == placeholder {
		return root
	}
	prefix := placeholder + "/"
	if !strings.HasPrefix(value, prefix) {
		return value
	}
	remainder := strings.TrimPrefix(value, prefix)
	separator := "/"
	if goos == "windows" {
		separator = `\`
		remainder = strings.ReplaceAll(remainder, "/", separator)
	}
	return strings.TrimRight(root, `/\`) + separator + remainder
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
		count := len(releaseasset.SupportedTargets()) + 1
		return checkResult{Status: statusPassed, Detail: fmt.Sprintf("computed SHA-256 for %d release files", count)}
	default:
		return checkResult{Status: statusFailed, Detail: "unknown builtin action: " + name}
	}
}

func verifyReleaseChecksums(actionCtx actionContext) error {
	paths := make([]string, 0, len(releaseasset.SupportedTargets())+1)
	for _, target := range releaseasset.SupportedTargets() {
		paths = append(paths, filepath.Join(actionCtx.TempDir, releaseasset.Name(target.GOOS, target.GOARCH)))
	}
	paths = append(paths, filepath.Join(actionCtx.RepoRoot, "install.sh"))
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
	approved := reviewedActionPolicy()
	for _, profile := range manifest.Profiles {
		for _, check := range profile.Checks {
			want, ok := approved[check.ID]
			if !ok {
				return fmt.Errorf("%s/%s: action is not approved", profile.Name, check.ID)
			}
			if !reflect.DeepEqual(check.Action, want) {
				return fmt.Errorf("%s/%s: action differs from its exact approved argv", profile.Name, check.ID)
			}
		}
	}
	return nil
}

func executeProfile(ctx context.Context, manifest Manifest, profileName string, deps runtimeDependencies) (result profileResult, returnErr error) {
	result = profileResult{Profile: profileName, Status: statusFailed}
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

	before, untracked, err := captureRepositorySnapshot(deps.repoRoot)
	if err != nil {
		return result, err
	}
	if len(untracked) != 0 {
		return result, fmt.Errorf(
			"repository clean-tree prerequisite failed: %d non-ignored untracked path(s)",
			len(bytes.Split(bytes.TrimSuffix(untracked, []byte{0}), []byte{0})),
		)
	}
	defer func() {
		after, stateErr := repositorySnapshot(deps.repoRoot)
		if stateErr != nil {
			result.Status = statusFailed
			returnErr = errors.Join(returnErr, stateErr)
			return
		}
		if !bytes.Equal(before, after) {
			result.Status = statusFailed
			returnErr = errors.Join(returnErr, errors.New("verification changed repository state"))
		}
	}()
	tempDir, err := os.MkdirTemp("", "ssm-verify-"+profileName+"-*")
	if err != nil {
		return result, fmt.Errorf("create profile temporary directory: %w", err)
	}
	removeAll := deps.removeAll
	if removeAll == nil {
		removeAll = os.RemoveAll
	}
	defer func() {
		if cleanupErr := removeAll(tempDir); cleanupErr != nil {
			result.Status = statusFailed
			returnErr = errors.Join(
				returnErr,
				fmt.Errorf("remove profile temporary directory: %w", cleanupErr),
			)
		}
	}()
	result.Status = statusPassed
	if profileName == "release" {
		result.Status = statusPreflightPassed
	}

	version := ""
	for _, check := range profile.Checks {
		missing := unavailablePrerequisites(check.Prerequisites, deps.prerequisites)
		if len(missing) > 0 {
			detail := "missing prerequisites: " + strings.Join(missing, ", ")
			if checkIsRequired(check) {
				result.Checks = append(result.Checks, checkResult{ID: check.ID, Status: statusFailed, Detail: detail})
				result.Status = statusFailed
				return result, fmt.Errorf("required check %s is unavailable: %s", check.ID, detail)
			}
			result.Checks = append(result.Checks, checkResult{ID: check.ID, Status: statusUnavailable, Detail: detail})
			result.Status = statusCompletedUnavailable
			continue
		}

		checkResult := deps.actions(ctx, check.Action, actionContext{
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
			if checkIsRequired(check) {
				result.Status = statusFailed
				return result, fmt.Errorf("required check %s was unavailable: %s", check.ID, checkResult.Detail)
			}
			result.Status = statusCompletedUnavailable
		default:
			result.Status = statusFailed
			return result, fmt.Errorf("check %s failed: %s", check.ID, checkResult.Detail)
		}
	}

	return result, nil
}

func checkIsRequired(check Check) bool {
	if check.Requirement == requirementRequired {
		return true
	}
	for _, contextName := range check.RequiredContexts {
		if contextName == "github_actions_linux" &&
			os.Getenv("GITHUB_ACTIONS") == "true" &&
			os.Getenv("RUNNER_OS") == "Linux" {
			return true
		}
	}
	return false
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
		if prerequisite.Version == "tracked" {
			command := exec.Command("git", "-C", repoRoot, "ls-files", "--error-unmatch", "--", prerequisite.Name) //nolint:gosec // fixed read-only Git argv
			if output, err := command.CombinedOutput(); err != nil {
				detail := strings.TrimSpace(string(output))
				if detail == "" {
					detail = err.Error()
				}
				return prerequisiteState{detail: "not tracked by Git: " + detail}
			}
		}
		return prerequisiteState{available: true, detail: prerequisite.Version}
	case "system_path":
		info, err := os.Stat(prerequisite.Name)
		if err != nil {
			return prerequisiteState{detail: err.Error()}
		}
		switch prerequisite.Version {
		case "directory":
			if !info.IsDir() {
				return prerequisiteState{detail: "not a directory"}
			}
		case "executable":
			if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
				return prerequisiteState{detail: "not an executable regular file"}
			}
		case "readable":
			file, openErr := os.Open(prerequisite.Name) //nolint:gosec // fixed manifest-owned non-secret system path
			if openErr != nil {
				return prerequisiteState{detail: openErr.Error()}
			}
			if closeErr := file.Close(); closeErr != nil {
				return prerequisiteState{detail: closeErr.Error()}
			}
		default:
			return prerequisiteState{detail: "unknown system-path requirement " + prerequisite.Version}
		}
		return prerequisiteState{available: true, detail: prerequisite.Version}
	case "capability":
		if prerequisite.Name != "govulncheck-module" ||
			prerequisite.Version != "network-or-module-cache" {
			return prerequisiteState{detail: "unknown capability " + prerequisite.Name}
		}
		return govulncheckModuleCapability()
	case "tool":
		if prerequisite.Name == "gofmt" {
			return pinnedGofmtPrerequisite(prerequisite.Version)
		}
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

func pinnedGofmtPrerequisite(wantVersion string) prerequisiteState {
	goRoot, err := goToolchainRoot()
	if err != nil {
		return prerequisiteState{detail: err.Error()}
	}
	path := filepath.Join(goRoot, "bin", "gofmt"+executableSuffix())
	info, err := os.Stat(path)
	if err != nil {
		return prerequisiteState{detail: err.Error()}
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0) {
		return prerequisiteState{detail: path + " is not executable"}
	}
	version, err := goBinaryVersion(path)
	if err != nil {
		return prerequisiteState{detail: err.Error()}
	}
	if version != wantVersion {
		return prerequisiteState{detail: fmt.Sprintf("%s is %s, need %s", path, version, wantVersion)}
	}
	return prerequisiteState{available: true, detail: path + " (" + version + ")"}
}

func goToolchainRoot() (string, error) {
	output, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return "", fmt.Errorf("resolve pinned Go toolchain root: %w", err)
	}
	root := strings.TrimSpace(string(output))
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("go env GOROOT returned invalid path %q", root)
	}
	return root, nil
}

func goBinaryVersion(path string) (string, error) {
	output, err := exec.Command("go", "version", "-m", path).Output() //nolint:gosec // path is the validated gofmt inside resolved GOROOT
	if err != nil {
		return "", fmt.Errorf("inspect Go binary %s: %w", path, err)
	}
	firstLine, _, _ := strings.Cut(string(output), "\n")
	fields := strings.Fields(firstLine)
	if len(fields) < 2 || !strings.HasPrefix(fields[len(fields)-1], "go1.") {
		return "", fmt.Errorf("go binary version for %s was not recognized", path)
	}
	return fields[len(fields)-1], nil
}

func govulncheckModuleCapability() prerequisiteState {
	output, err := exec.Command("go", "env", "GOMODCACHE", "GOPROXY").Output()
	if err != nil {
		return prerequisiteState{detail: fmt.Sprintf("read Go module settings: %v", err)}
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 2 {
		return prerequisiteState{detail: "go env did not return GOMODCACHE and GOPROXY"}
	}
	moduleCache, proxy := lines[0], lines[1]
	unpacked := filepath.Join(moduleCache, "golang.org", "x", "vuln@v1.6.0")
	if _, err := os.Stat(unpacked); err == nil {
		return prerequisiteState{available: true, detail: "govulncheck v1.6.0 is in the Go module cache"}
	}
	downloaded := filepath.Join(moduleCache, "cache", "download", "golang.org", "x", "vuln", "@v", "v1.6.0")
	if _, zipErr := os.Stat(downloaded + ".zip"); zipErr == nil {
		if _, modErr := os.Stat(downloaded + ".mod"); modErr == nil {
			return prerequisiteState{available: true, detail: "govulncheck v1.6.0 is in the Go download cache"}
		}
	}
	if proxy == "" || proxy == "off" {
		return prerequisiteState{detail: "govulncheck v1.6.0 is not cached and GOPROXY disables network resolution"}
	}
	return prerequisiteState{
		available: true,
		detail:    "govulncheck v1.6.0 is not cached; configured GOPROXY must provide network resolution",
	}
}

func toolVersion(name string) (string, error) {
	switch name {
	case "go":
		output, err := exec.Command("go", "version").Output()
		if err != nil {
			return "", fmt.Errorf("read Go version: %w", err)
		}
		fields := strings.Fields(string(output))
		for _, field := range fields {
			if strings.HasPrefix(field, "go1.") {
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

func repositorySnapshot(repoRoot string) ([]byte, error) {
	snapshot, _, err := captureRepositorySnapshot(repoRoot)
	return snapshot, err
}

func captureRepositorySnapshot(repoRoot string) ([]byte, []byte, error) {
	digest := sha256.New()
	gitParts := []struct {
		name string
		args []string
	}{
		{
			name: "head",
			args: []string{"rev-parse", "--verify", "HEAD"},
		},
		{
			name: "head-name",
			args: []string{"rev-parse", "--symbolic-full-name", "HEAD"},
		},
		{
			name: "refs",
			args: []string{
				"for-each-ref",
				"--sort=refname",
				"--format=%(refname)%00%(objectname)%00%(symref)%00",
				"refs/heads",
				"refs/tags",
				"refs/remotes",
			},
		},
		{
			name: "index",
			args: []string{"ls-files", "--stage", "-z"},
		},
		{
			name: "index-flags",
			args: []string{"ls-files", "-v", "-z"},
		},
		{
			name: "index-diff",
			args: []string{"diff", "--cached", "--no-ext-diff", "--no-textconv", "--binary", "--full-index", "HEAD", "--"},
		},
		{
			name: "worktree-diff",
			args: []string{"diff", "--no-ext-diff", "--no-textconv", "--binary", "--full-index", "--"},
		},
		{
			name: "untracked",
			args: []string{"ls-files", "--others", "--exclude-standard", "-z"},
		},
	}

	var untracked []byte
	for _, part := range gitParts {
		command := exec.Command("git", append([]string{"-C", repoRoot}, part.args...)...) //nolint:gosec // fixed read-only Git argv
		output, err := command.Output()
		if err != nil {
			return nil, nil, fmt.Errorf("snapshot repository %s: %w", part.name, err)
		}
		_, _ = fmt.Fprintf(digest, "%s\x00%d\x00", part.name, len(output))
		_, _ = digest.Write(output)
		if part.name == "untracked" {
			untracked = output
		}
	}
	return digest.Sum(nil), untracked, nil
}

func executableSuffix() string {
	return executableSuffixFor(runtime.GOOS)
}

func executableSuffixFor(goos string) string {
	if goos == "windows" {
		return ".exe"
	}
	return ""
}

func joinedPath(root, slashPath string) string {
	return filepath.Join(append([]string{root}, strings.Split(slashPath, "/")...)...)
}
