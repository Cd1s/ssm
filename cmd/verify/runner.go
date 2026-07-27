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
	"time"

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
	RepoRoot    string
	TempDir     string
	Version     string
	GoRoot      string
	Environment []string
	Stdout      io.Writer
	Stderr      io.Writer
}

type checkResult struct {
	ID     string `json:"id,omitempty"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	Err    error  `json:"-"`
}

type profileResult struct {
	Profile string        `json:"profile"`
	Status  string        `json:"status"`
	Checks  []checkResult `json:"checks"`
}

type executionContext struct {
	GOOS          string
	GOARCH        string
	GitHubActions bool
	RunnerOS      string
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
	cacheRoot     string
	stdout        io.Writer
	stderr        io.Writer
	prerequisites func(context.Context, string, Prerequisite, []string) prerequisiteState
	actions       func(context.Context, Action, actionContext) checkResult
	removeAll     func(string) error
}

func executeCommand(ctx context.Context, specification Command, actionCtx actionContext) checkResult {
	if strings.Contains(specification.Executable, "{goroot}") && actionCtx.GoRoot == "" {
		goRoot, err := goToolchainRoot(ctx, actionCtx.Environment)
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
	if len(actionCtx.Environment) == 0 {
		return checkResult{Status: statusFailed, Detail: "isolated child environment is required"}
	}
	command := exec.Command(executable, args...) //nolint:gosec // executable and argv come only from the validated checked-in manifest
	command.Dir = actionCtx.RepoRoot
	command.Env = append([]string(nil), actionCtx.Environment...)
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
	if err := runOwnedCommand(ctx, command); err != nil {
		return checkResult{Status: statusFailed, Detail: err.Error(), Err: err}
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
	type releaseFile struct {
		root string
		name string
	}
	paths := make([]releaseFile, 0, len(releaseasset.SupportedTargets())+1)
	for _, target := range releaseasset.SupportedTargets() {
		paths = append(paths, releaseFile{
			root: actionCtx.TempDir,
			name: releaseasset.Name(target.GOOS, target.GOARCH),
		})
	}
	paths = append(paths, releaseFile{root: actionCtx.RepoRoot, name: "install.sh"})
	for _, path := range paths {
		file, err := openRegularFileNoFollow(path.root, path.name)
		if err != nil {
			return fmt.Errorf("open release file %s: %w", path.name, err)
		}
		info, statErr := file.Stat()
		if statErr != nil {
			return errors.Join(
				fmt.Errorf("stat release file %s: %w", path.name, statErr),
				wrapCloseError("close release file "+path.name, file.Close()),
			)
		}
		if info.Size() == 0 {
			return errors.Join(
				fmt.Errorf("release file %s is empty", path.name),
				wrapCloseError("close release file "+path.name, file.Close()),
			)
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(
				wrapError("hash release file "+path.name, copyErr),
				wrapCloseError("close release file "+path.name, closeErr),
			)
		}
		if len(hash.Sum(nil)) != sha256.Size {
			return fmt.Errorf("invalid SHA-256 result for %s", path.name)
		}
	}
	return nil
}

func readSourceVersion(repoRoot string) (string, error) {
	const sourcePath = "cmd/ssm/main.go"
	data, err := readRegularFileNoFollow(repoRoot, sourcePath)
	if err != nil {
		return "", fmt.Errorf("read source version: %w", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), sourcePath, data, 0)
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
		for index := 0; index < len(part); index++ {
			if part[index] < '0' || part[index] > '9' {
				return false
			}
		}
	}
	return true
}

func validateReleaseNotes(repoRoot, version string) error {
	data, err := readRegularFileNoFollow(repoRoot, "RELEASE_NOTES.md")
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
	approvedPreparations := reviewedPreparationPolicy()
	for _, profile := range manifest.Profiles {
		for _, check := range profile.Checks {
			for _, preparation := range check.Preparations {
				if err := validateManifestActionEnvironment(preparation.Action); err != nil {
					return fmt.Errorf("%s/%s/%s: %w", profile.Name, check.ID, preparation.ID, err)
				}
				want, ok := approvedPreparations[preparation.ID]
				if !ok {
					return fmt.Errorf("%s/%s/%s: preparation is not approved", profile.Name, check.ID, preparation.ID)
				}
				if !reflect.DeepEqual(preparation, want) {
					return fmt.Errorf(
						"%s/%s/%s: preparation differs from its exact approved action",
						profile.Name,
						check.ID,
						preparation.ID,
					)
				}
			}
			if err := validateManifestActionEnvironment(check.Action); err != nil {
				return fmt.Errorf("%s/%s: %w", profile.Name, check.ID, err)
			}
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

func validateManifestActionEnvironment(action Action) error {
	if action.Command == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(action.Command.Env))
	for _, entry := range action.Command.Env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			return fmt.Errorf("invalid manifest environment entry")
		}
		normalized := strings.ToUpper(key)
		if credentialLikeEnvironmentKey(normalized) {
			return fmt.Errorf("credential-like environment key %q is forbidden", key)
		}
		if _, duplicate := seen[normalized]; duplicate {
			return fmt.Errorf("duplicate manifest environment key %q", key)
		}
		seen[normalized] = struct{}{}
		switch normalized {
		case "GOOS":
			if value != "linux" && value != "darwin" && value != "windows" {
				return fmt.Errorf("unreviewed GOOS value %q", value)
			}
		case "GOARCH":
			if value != "amd64" && value != "arm64" {
				return fmt.Errorf("unreviewed GOARCH value %q", value)
			}
		default:
			return fmt.Errorf("unreviewed manifest environment key %q", key)
		}
	}
	return nil
}

func credentialLikeEnvironmentKey(key string) bool {
	for _, marker := range []string{
		"ACCESS_KEY",
		"API_KEY",
		"AUTH",
		"COOKIE",
		"CREDENTIAL",
		"NETRC",
		"PASSWORD",
		"PASSWD",
		"PRIVATE_KEY",
		"SECRET",
		"SESSION",
		"TOKEN",
	} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
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

	removeAll := deps.removeAll
	if removeAll == nil {
		removeAll = os.RemoveAll
	}
	tempDir, err := createPrivateProfileTempDirectory(
		deps.repoRoot,
		"ssm-verify-"+profileName+"-*",
		removeAll,
	)
	if err != nil {
		return result, err
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
	cache, err := prepareVerifierCache(deps.repoRoot, deps.cacheRoot)
	if err != nil {
		return result, err
	}
	processEnvironment, err := newIsolatedProcessEnvironmentWithCache(tempDir, cache)
	if err != nil {
		return result, err
	}

	prerequisiteResults := make(map[string]prerequisiteState)
	checkPrerequisiteOnce := func(root string, prerequisite Prerequisite) prerequisiteState {
		key := root + "\x00" + fmt.Sprintf("%#v", prerequisite)
		if state, ok := prerequisiteResults[key]; ok {
			return state
		}
		state := deps.prerequisites(ctx, root, prerequisite, processEnvironment)
		prerequisiteResults[key] = state
		return state
	}
	for _, prerequisite := range profile.Prerequisites {
		state := checkPrerequisiteOnce(deps.repoRoot, prerequisite)
		if !state.available {
			return result, fmt.Errorf("profile %s prerequisite unavailable: %s (%s)", profileName, prerequisite.Name, state.detail)
		}
	}

	if err := validateTrackedWorktreePaths(ctx, deps.repoRoot, processEnvironment); err != nil {
		return result, err
	}
	before, untracked, err := captureRepositorySnapshot(ctx, deps.repoRoot, processEnvironment)
	if err != nil {
		return result, err
	}
	if len(untracked) != 0 {
		return result, fmt.Errorf(
			"repository clean-tree prerequisite failed: %d non-ignored untracked path(s)",
			len(bytes.Split(bytes.TrimSuffix(untracked, []byte{0}), []byte{0})),
		)
	}
	workspaceRoot := filepath.Join(tempDir, "action-workspace")
	trackedFiles, err := materializeActionWorkspace(ctx, deps.repoRoot, workspaceRoot, processEnvironment)
	if err != nil {
		return result, fmt.Errorf("materialize private action workspace: %w", err)
	}
	workspaceBefore, err := actionWorkspaceSnapshot(workspaceRoot, trackedFiles)
	if err != nil {
		return result, err
	}
	actionEnvironment := append(
		append([]string(nil), processEnvironment...),
		"GIT_CEILING_DIRECTORIES="+tempDir,
		"GIT_DISCOVERY_ACROSS_FILESYSTEM=0",
	)
	validateGuardedState := func(validationContext context.Context) error {
		if _, err := inspectTrackedWorktreeLayout(validationContext, deps.repoRoot, processEnvironment); err != nil {
			return err
		}
		originalNow, err := repositorySnapshotWithEnvironment(
			validationContext,
			deps.repoRoot,
			processEnvironment,
		)
		if err != nil {
			return err
		}
		if !bytes.Equal(before, originalNow) {
			return errors.New("verification changed repository state")
		}
		workspaceNow, err := actionWorkspaceSnapshot(workspaceRoot, trackedFiles)
		if err != nil {
			return fmt.Errorf("validate action workspace state: %w", err)
		}
		if !bytes.Equal(workspaceBefore, workspaceNow) {
			return errors.New("verification changed action workspace state")
		}
		return nil
	}
	defer func() {
		cleanupContext, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancelCleanup()
		if stateErr := validateGuardedState(cleanupContext); stateErr != nil {
			result.Status = statusFailed
			returnErr = errors.Join(returnErr, stateErr)
		}
	}()
	result.Status = statusPassed
	if profileName == "release" {
		result.Status = statusPreflightPassed
	}

	version := ""
	for _, check := range profile.Checks {
		if err := validateGuardedState(ctx); err != nil {
			result.Status = statusFailed
			return result, err
		}
		missing := unavailablePrerequisites(check.Prerequisites, func(prerequisite Prerequisite) prerequisiteState {
			root := workspaceRoot
			environment := actionEnvironment
			if prerequisite.Kind == "file" || prerequisite.Kind == "git_ref" {
				root = deps.repoRoot
				environment = processEnvironment
			}
			key := root + "\x00" + fmt.Sprintf("%#v", prerequisite)
			if state, ok := prerequisiteResults[key]; ok {
				return state
			}
			state := deps.prerequisites(ctx, root, prerequisite, environment)
			prerequisiteResults[key] = state
			return state
		})
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
		if err := validateGuardedState(ctx); err != nil {
			result.Status = statusFailed
			return result, err
		}
		for _, preparation := range check.Preparations {
			if err := executePreparation(
				ctx,
				preparation,
				deps.repoRoot,
				workspaceRoot,
				tempDir,
				trackedFiles,
				processEnvironment,
				deps.stderr,
			); err != nil {
				result.Status = statusFailed
				return result, fmt.Errorf("prepare check %s with %s: %w", check.ID, preparation.ID, err)
			}
			if err := validateGuardedState(ctx); err != nil {
				result.Status = statusFailed
				return result, err
			}
		}

		checkResult := deps.actions(ctx, check.Action, actionContext{
			RepoRoot:    workspaceRoot,
			TempDir:     tempDir,
			Version:     version,
			Environment: actionEnvironment,
			Stdout:      deps.stdout,
			Stderr:      deps.stderr,
		})
		checkResult.ID = check.ID
		result.Checks = append(result.Checks, checkResult)
		if err := validateGuardedState(ctx); err != nil {
			result.Status = statusFailed
			return result, err
		}
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
			if checkResult.Err != nil {
				return result, fmt.Errorf("check %s failed: %w", check.ID, checkResult.Err)
			}
			return result, fmt.Errorf("check %s failed: %s", check.ID, checkResult.Detail)
		}
	}

	return result, nil
}

func checkIsRequired(check Check) bool {
	return checkIsRequiredFor(check, executionContext{
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		GitHubActions: os.Getenv("GITHUB_ACTIONS") == "true",
		RunnerOS:      os.Getenv("RUNNER_OS"),
	})
}

func checkIsRequiredFor(check Check, execution executionContext) bool {
	if check.Requirement == requirementRequired {
		return true
	}
	for _, contextName := range check.RequiredContexts {
		if contextName == "github_actions_linux" &&
			execution.GitHubActions &&
			execution.RunnerOS == "Linux" &&
			execution.GOOS == "linux" {
			return true
		}
	}
	return false
}

func unavailablePrerequisites(
	prerequisites []Prerequisite,
	checker func(Prerequisite) prerequisiteState,
) []string {
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

func checkPrerequisite(
	ctx context.Context,
	repoRoot string,
	prerequisite Prerequisite,
	environment []string,
) prerequisiteState {
	switch prerequisite.Kind {
	case "repository":
		switch {
		case prerequisite.Name == "fully-populated-regular-tracked-worktree" &&
			prerequisite.Version == "stage-0-modes-100644-or-100755-no-sparse":
			if _, err := inspectTrackedWorktreeLayout(ctx, repoRoot, environment); err != nil {
				return prerequisiteState{detail: err.Error()}
			}
			return prerequisiteState{available: true, detail: prerequisite.Version}
		case prerequisite.Name == "safe-local-git-configuration" &&
			prerequisite.Version == "no-includes-or-executable-command-authority":
			if err := rejectSensitiveLocalGitConfiguration(ctx, repoRoot, environment); err != nil {
				return prerequisiteState{detail: err.Error()}
			}
			return prerequisiteState{available: true, detail: prerequisite.Version}
		case prerequisite.Name == "no-nonignored-untracked-paths" &&
			prerequisite.Version == "git-ls-files-others-exclude-standard-z":
			untracked, err := nonIgnoredUntrackedPaths(ctx, repoRoot, environment)
			if err != nil {
				return prerequisiteState{detail: err.Error()}
			}
			if len(untracked) != 0 {
				count := len(bytes.Split(bytes.TrimSuffix(untracked, []byte{0}), []byte{0}))
				return prerequisiteState{
					detail: fmt.Sprintf("%d non-ignored untracked path(s) are present", count),
				}
			}
			return prerequisiteState{available: true, detail: prerequisite.Version}
		default:
			return prerequisiteState{detail: "unknown repository requirement " + prerequisite.Name}
		}
	case "git_ref":
		if prerequisite.Name != "v1.2.0" || prerequisite.Version != "commit" {
			return prerequisiteState{detail: "unknown Git reference requirement " + prerequisite.Name}
		}
		git, err := newSourceGit(ctx, repoRoot, environment)
		if err != nil {
			return prerequisiteState{detail: err.Error()}
		}
		if err := git.runWithWriters(
			io.Discard,
			io.Discard,
			"rev-parse", "--verify", "--quiet", "--end-of-options", "refs/tags/v1.2.0^{commit}",
		); err != nil {
			return prerequisiteState{
				detail: "lint baseline ref v1.2.0 is unavailable or does not resolve to a commit",
			}
		}
		return prerequisiteState{available: true, detail: "v1.2.0 resolves to a commit"}
	case "platform":
		if prerequisite.Name == runtime.GOOS {
			return prerequisiteState{available: true, detail: runtime.GOOS}
		}
		return prerequisiteState{detail: "current platform is " + runtime.GOOS}
	case "file":
		file, err := openRegularFileNoFollow(repoRoot, prerequisite.Name)
		if err != nil {
			return prerequisiteState{detail: err.Error()}
		}
		if err := file.Close(); err != nil {
			return prerequisiteState{detail: fmt.Sprintf("close prerequisite file: %v", err)}
		}
		if prerequisite.Version == "tracked" {
			git, gitErr := newSourceGit(ctx, repoRoot, environment)
			if gitErr != nil {
				return prerequisiteState{detail: gitErr.Error()}
			}
			if output, gitErr := git.combinedOutput("ls-files", "--error-unmatch", "--", prerequisite.Name); gitErr != nil {
				detail := strings.TrimSpace(string(output))
				if detail == "" {
					detail = gitErr.Error()
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
		switch {
		case prerequisite.Name == "repository-modules" &&
			prerequisite.Version == "go-mod-download":
			return goModuleDownloadCapability(ctx, repoRoot, environment)
		case prerequisite.Name == "govulncheck-module" &&
			prerequisite.Version == "network-or-module-cache":
			return govulncheckModuleCapability(ctx, repoRoot, environment)
		case prerequisite.Name == "native-race" &&
			prerequisite.Version == "supported-host-cgo-c-compiler":
			return raceCapabilityForHost(ctx, runtime.GOOS, runtime.GOARCH, environment)
		default:
			return prerequisiteState{detail: "unknown capability " + prerequisite.Name}
		}
	case "executable_alternatives":
		if prerequisite.Name != "sshd" ||
			prerequisite.Version != "SSHD-then-PATH-then-/usr/sbin/sshd" {
			return prerequisiteState{detail: "unknown executable alternatives " + prerequisite.Name}
		}
		path, source, err := selectSSHDExecutable(environment)
		if err != nil {
			return prerequisiteState{detail: err.Error()}
		}
		return prerequisiteState{available: true, detail: path + " (" + source + ")"}
	case "tool":
		if prerequisite.Name == "gofmt" {
			return pinnedGofmtPrerequisite(ctx, prerequisite.Version, environment)
		}
		path, err := lookPathInEnvironment(prerequisite.Name, environment)
		if err != nil {
			return prerequisiteState{detail: "not found in PATH"}
		}
		if prerequisite.Version == "" || prerequisite.Version == "any" {
			return prerequisiteState{available: true, detail: path}
		}
		version, err := toolVersion(ctx, prerequisite.Name, environment)
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

func selectSSHDExecutable(environment []string) (string, string, error) {
	if override, set := environmentValue(environment, "SSHD"); set {
		if err := validateExecutableRegularFile(override); err != nil {
			return "", "", fmt.Errorf("invalid SSHD override %q: %w", override, err)
		}
		return override, "SSHD override", nil
	}

	if candidate, err := lookPathInEnvironment("sshd", environment); err == nil {
		if validateErr := validateExecutableRegularFile(candidate); validateErr != nil {
			return "", "", fmt.Errorf("invalid PATH sshd %q: %w", candidate, validateErr)
		}
		return candidate, "PATH", nil
	}

	const fallback = "/usr/sbin/sshd"
	if err := validateExecutableRegularFile(fallback); err == nil {
		return fallback, "/usr/sbin fallback", nil
	}
	return "", "", errors.New("no executable sshd: SSHD is unset, PATH has no sshd, and /usr/sbin/sshd is unavailable")
}

func lookPathInEnvironment(name string, environment []string) (string, error) {
	pathValue, ok := environmentValue(environment, "PATH")
	if !ok {
		return "", exec.ErrNotFound
	}
	names := []string{name}
	if runtime.GOOS == "windows" && filepath.Ext(name) == "" {
		pathExtensions, present := environmentValue(environment, "PATHEXT")
		if !present || pathExtensions == "" {
			pathExtensions = ".COM;.EXE;.BAT;.CMD"
		}
		names = names[:0]
		for _, extension := range strings.Split(pathExtensions, ";") {
			names = append(names, name+strings.ToLower(extension), name+strings.ToUpper(extension))
		}
	}
	for _, directory := range filepath.SplitList(pathValue) {
		if directory == "" {
			continue
		}
		for _, candidateName := range names {
			candidate := filepath.Join(directory, candidateName)
			if err := validateExecutableRegularFile(candidate); err == nil {
				return candidate, nil
			}
		}
	}
	return "", exec.ErrNotFound
}

func validateExecutableRegularFile(path string) error {
	if path == "" {
		return errors.New("path is empty")
	}
	info, err := os.Stat(path) //nolint:gosec // path is a selected SSHD prerequisite or executable found in the reviewed PATH
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return errors.New("not executable")
	}
	return nil
}

func pinnedGofmtPrerequisite(
	ctx context.Context,
	wantVersion string,
	environment []string,
) prerequisiteState {
	goRoot, err := goToolchainRoot(ctx, environment)
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
	version, err := goBinaryVersion(ctx, path, environment)
	if err != nil {
		return prerequisiteState{detail: err.Error()}
	}
	if version != wantVersion {
		return prerequisiteState{detail: fmt.Sprintf("%s is %s, need %s", path, version, wantVersion)}
	}
	return prerequisiteState{available: true, detail: path + " (" + version + ")"}
}

func goToolchainRoot(ctx context.Context, environment []string) (string, error) {
	command := exec.Command("go", "env", "GOROOT")
	command.Env = environment
	output, err := ownedCommandOutput(ctx, command)
	if err != nil {
		return "", fmt.Errorf("resolve pinned Go toolchain root: %w", err)
	}
	root := strings.TrimSpace(string(output))
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("go env GOROOT returned invalid path %q", root)
	}
	return root, nil
}

func goBinaryVersion(ctx context.Context, path string, environment []string) (string, error) {
	command := exec.Command("go", "version", "-m", path) //nolint:gosec // path is the validated gofmt inside resolved GOROOT
	command.Env = environment
	output, err := ownedCommandOutput(ctx, command)
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

func goModuleDownloadCapability(
	ctx context.Context,
	repoRoot string,
	environment []string,
) prerequisiteState {
	command := exec.Command("go", "mod", "download") //nolint:gosec // fixed non-mutating module availability preflight
	command.Dir = repoRoot
	command.Env = environment
	output, err := ownedCommandCombinedOutput(ctx, command)
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			detail = err.Error()
		}
		return prerequisiteState{detail: "go mod download failed: " + detail}
	}
	return prerequisiteState{available: true, detail: "repository modules are available in the verifier cache"}
}

func govulncheckModuleCapability(
	ctx context.Context,
	repoRoot string,
	environment []string,
) prerequisiteState {
	command := exec.Command("go", "mod", "download", "golang.org/x/vuln@v1.6.0") //nolint:gosec // fixed reviewed public module and version
	command.Dir = repoRoot
	command.Env = environment
	output, err := ownedCommandCombinedOutput(ctx, command)
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			detail = err.Error()
		}
		return prerequisiteState{detail: "govulncheck module download failed: " + detail}
	}
	return prerequisiteState{available: true, detail: "govulncheck v1.6.0 is available in the verifier cache"}
}

func raceSupportedHost(goos, goarch string) bool {
	switch goos + "/" + goarch {
	case "darwin/amd64",
		"darwin/arm64",
		"freebsd/amd64",
		"linux/amd64",
		"linux/arm64",
		"linux/loong64",
		"linux/ppc64le",
		"linux/s390x",
		"netbsd/amd64",
		"windows/amd64":
		return true
	default:
		return false
	}
}

func raceCapabilityForHost(
	ctx context.Context,
	goos, goarch string,
	environment []string,
) prerequisiteState {
	if !raceSupportedHost(goos, goarch) {
		return prerequisiteState{detail: fmt.Sprintf("race detector is unsupported on native host %s/%s", goos, goarch)}
	}
	command := exec.Command("go", "env", "GOOS", "GOARCH", "CGO_ENABLED", "CC")
	command.Env = environment
	output, err := ownedCommandOutput(ctx, command)
	if err != nil {
		return prerequisiteState{detail: fmt.Sprintf("read native race prerequisites: %v", err)}
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 4 {
		return prerequisiteState{detail: "go env did not return native race prerequisites"}
	}
	if lines[0] != goos || lines[1] != goarch {
		return prerequisiteState{
			detail: fmt.Sprintf(
				"Go toolchain host tuple is %s/%s, need native %s/%s",
				lines[0],
				lines[1],
				goos,
				goarch,
			),
		}
	}
	if lines[2] != "1" {
		return prerequisiteState{detail: "CGO_ENABLED=1 is required for the native race detector"}
	}
	compilerFields := strings.Fields(lines[3])
	if len(compilerFields) == 0 {
		return prerequisiteState{detail: "Go did not report a C compiler for the native race detector"}
	}
	compiler, err := lookPathInEnvironment(compilerFields[0], environment)
	if err != nil {
		return prerequisiteState{detail: fmt.Sprintf("C compiler %q is not available in PATH", compilerFields[0])}
	}
	return prerequisiteState{
		available: true,
		detail:    fmt.Sprintf("native race supported on %s/%s with CGO and %s", goos, goarch, compiler),
	}
}

func rejectSensitiveLocalGitConfiguration(
	ctx context.Context,
	repoRoot string,
	environment []string,
) error {
	_, err := newSourceGit(ctx, repoRoot, environment)
	return err
}

func executePreparation(
	ctx context.Context,
	preparation Preparation,
	repoRoot string,
	workspaceRoot string,
	tempDir string,
	trackedFiles []trackedWorktreeFile,
	environment []string,
	stderr io.Writer,
) error {
	if preparation.WorkingDirectory != "source_repository" {
		return fmt.Errorf("unsupported working directory %q", preparation.WorkingDirectory)
	}
	if preparation.Action.Kind != actionBuiltin || preparation.Action.Name != "lint-patch" {
		return errors.New("preparation must be the reviewed no-filter lint-patch builtin")
	}
	actionCtx := actionContext{
		RepoRoot:    repoRoot,
		TempDir:     tempDir,
		Environment: environment,
	}
	if stderr == nil {
		stderr = io.Discard
	}
	output, err := prepareLintPatch(ctx, repoRoot, workspaceRoot, tempDir, trackedFiles, environment, stderr)
	if err != nil {
		return err
	}
	outputPath := expandActionValue(preparation.Output, actionCtx)
	relative, err := filepath.Rel(tempDir, outputPath)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("preparation output must be a file beneath the profile temporary directory")
	}
	//nolint:gosec // tempDir is created privately by executeProfile and the filename is fixed
	if err := os.WriteFile(outputPath, output, 0o600); err != nil {
		return fmt.Errorf("write preparation output: %w", err)
	}
	return nil
}

func prepareLintPatch(
	ctx context.Context,
	repoRoot string,
	workspaceRoot string,
	tempDir string,
	trackedFiles []trackedWorktreeFile,
	environment []string,
	stderr io.Writer,
) ([]byte, error) {
	source, err := newSourceGit(ctx, repoRoot, environment)
	if err != nil {
		return nil, err
	}
	baselineOutput, err := source.output(
		"rev-parse", "--verify", "--end-of-options", "refs/tags/v1.2.0^{commit}",
	)
	if err != nil {
		return nil, fmt.Errorf("resolve lint baseline commit: %w", err)
	}
	baseline := strings.TrimSpace(string(baselineOutput))
	objectsOutput, err := source.output("rev-parse", "--path-format=absolute", "--git-path", "objects")
	if err != nil {
		return nil, fmt.Errorf("resolve source object directory: %w", err)
	}
	sourceObjects := strings.TrimSpace(string(objectsOutput))
	if sourceObjects == "" || !filepath.IsAbs(sourceObjects) {
		return nil, fmt.Errorf("source object directory is not absolute")
	}
	formatOutput, err := source.output("rev-parse", "--show-object-format")
	if err != nil {
		return nil, fmt.Errorf("resolve source object format: %w", err)
	}
	objectFormat := strings.TrimSpace(string(formatOutput))
	if objectFormat != "sha1" && objectFormat != "sha256" {
		return nil, fmt.Errorf("unsupported source object format %q", objectFormat)
	}

	gitDir := filepath.Join(tempDir, "lint-git")
	initArgs := []string{"init", "--quiet", "--bare", "--object-format=" + objectFormat, gitDir}
	if _, err := runVerifierGit(ctx, tempDir, environment, stderr, nil, initArgs...); err != nil {
		return nil, fmt.Errorf("initialize verifier-controlled lint repository: %w", err)
	}
	lintEnvironment := append(
		isolatedSourceGitEnvironment(environment),
		"GIT_ALTERNATE_OBJECT_DIRECTORIES="+sourceObjects,
		"GIT_DIR="+gitDir,
	)

	baselineIndex := filepath.Join(tempDir, "lint-baseline.index")
	baselineTree, err := buildLintBaselineTree(ctx, baseline, baselineIndex, lintEnvironment, stderr)
	if err != nil {
		return nil, err
	}
	worktreeIndex := filepath.Join(tempDir, "lint-worktree.index")
	worktreeTree, err := buildLintWorktreeTree(
		ctx,
		workspaceRoot,
		trackedFiles,
		worktreeIndex,
		lintEnvironment,
		stderr,
	)
	if err != nil {
		return nil, err
	}
	output, err := runVerifierGit(
		ctx,
		tempDir,
		append(lintEnvironment, "GIT_INDEX_FILE="+worktreeIndex),
		stderr,
		nil,
		"diff", "--no-ext-diff", "--no-textconv", "--binary", "--full-index",
		baselineTree, worktreeTree, "--",
	)
	if err != nil {
		return nil, fmt.Errorf("generate verifier-controlled lint patch: %w", err)
	}
	return output, nil
}

func buildLintBaselineTree(
	ctx context.Context,
	baseline string,
	indexPath string,
	environment []string,
	stderr io.Writer,
) (string, error) {
	indexEnvironment := append([]string(nil), environment...)
	indexEnvironment = append(indexEnvironment, "GIT_INDEX_FILE="+indexPath)
	if _, err := runVerifierGit(ctx, "", indexEnvironment, stderr, nil, "read-tree", baseline); err != nil {
		return "", fmt.Errorf("materialize lint baseline index: %w", err)
	}
	output, err := runVerifierGit(ctx, "", indexEnvironment, stderr, nil, "write-tree")
	if err != nil {
		return "", fmt.Errorf("write lint baseline tree: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func buildLintWorktreeTree(
	ctx context.Context,
	workspaceRoot string,
	trackedFiles []trackedWorktreeFile,
	indexPath string,
	environment []string,
	stderr io.Writer,
) (string, error) {
	indexEnvironment := append([]string(nil), environment...)
	indexEnvironment = append(indexEnvironment, "GIT_INDEX_FILE="+indexPath)
	if _, err := runVerifierGit(ctx, "", indexEnvironment, stderr, nil, "read-tree", "--empty"); err != nil {
		return "", fmt.Errorf("initialize lint worktree index: %w", err)
	}
	for _, tracked := range trackedFiles {
		file, err := openRegularFileNoFollow(workspaceRoot, tracked.Path)
		if err != nil {
			return "", fmt.Errorf("open lint worktree path %q: %w", tracked.Path, err)
		}
		info, statErr := file.Stat()
		if statErr != nil {
			return "", errors.Join(
				fmt.Errorf("inspect lint worktree path %q: %w", tracked.Path, statErr),
				wrapCloseError("close lint worktree path "+tracked.Path, file.Close()),
			)
		}
		hashOutput, hashErr := runVerifierGit(
			ctx,
			"",
			indexEnvironment,
			stderr,
			file,
			"hash-object", "--no-filters", "-w", "--stdin",
		)
		closeErr := file.Close()
		if hashErr != nil || closeErr != nil {
			return "", errors.Join(
				wrapError("hash lint worktree path "+tracked.Path, hashErr),
				wrapCloseError("close lint worktree path "+tracked.Path, closeErr),
			)
		}
		objectID := strings.TrimSpace(string(hashOutput))
		cacheInfo := workspaceGitMode(tracked.Mode, info.Mode()) + "," + objectID + "," + tracked.Path
		if _, err := runVerifierGit(
			ctx,
			"",
			indexEnvironment,
			stderr,
			nil,
			"update-index", "--add", "--cacheinfo", cacheInfo,
		); err != nil {
			return "", fmt.Errorf("index lint worktree path %q: %w", tracked.Path, err)
		}
	}
	output, err := runVerifierGit(ctx, "", indexEnvironment, stderr, nil, "write-tree")
	if err != nil {
		return "", fmt.Errorf("write lint worktree tree: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func runVerifierGit(
	ctx context.Context,
	directory string,
	environment []string,
	stderr io.Writer,
	stdin io.Reader,
	args ...string,
) ([]byte, error) {
	hooksPath, err := disabledGitHooksPath(environment)
	if err != nil {
		return nil, err
	}
	hardened := append(
		[]string{
			"-c", "core.fsmonitor=false",
			"-c", "core.hooksPath=" + hooksPath,
			"-c", "core.untrackedCache=false",
			"-c", "core.preloadIndex=false",
			"-c", "credential.helper=",
		},
		args...,
	)
	command := exec.Command("git", hardened...) //nolint:gosec // args are fixed verifier-controlled temporary-repository operations
	command.Dir = directory
	command.Env = environment
	command.Stdin = stdin
	command.Stderr = stderr
	return ownedCommandOutput(ctx, command)
}

func nonIgnoredUntrackedPaths(
	ctx context.Context,
	repoRoot string,
	environment []string,
) ([]byte, error) {
	git, err := newSourceGit(ctx, repoRoot, environment)
	if err != nil {
		return nil, err
	}
	output, err := git.output("ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, fmt.Errorf("enumerate non-ignored untracked paths: %w", err)
	}
	return output, nil
}

func toolVersion(ctx context.Context, name string, environment []string) (string, error) {
	switch name {
	case "go":
		command := exec.Command("go", "version")
		command.Env = environment
		output, err := ownedCommandOutput(ctx, command)
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
		command := exec.Command(name, "version")
		command.Env = environment
		output, err := ownedCommandOutput(ctx, command)
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

func repositorySnapshot(ctx context.Context, repoRoot string) (snapshot []byte, returnErr error) {
	tempDir, err := os.MkdirTemp("", "ssm-verify-snapshot-*")
	if err != nil {
		return nil, fmt.Errorf("create snapshot environment: %w", err)
	}
	defer func() {
		if cleanupErr := os.RemoveAll(tempDir); cleanupErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("remove snapshot environment: %w", cleanupErr))
		}
	}()
	environment, err := newIsolatedProcessEnvironment(tempDir)
	if err != nil {
		return nil, err
	}
	return repositorySnapshotWithEnvironment(ctx, repoRoot, environment)
}

func repositorySnapshotWithEnvironment(
	ctx context.Context,
	repoRoot string,
	environment []string,
) ([]byte, error) {
	snapshot, _, err := captureRepositorySnapshot(ctx, repoRoot, environment)
	return snapshot, err
}

func captureRepositorySnapshot(
	ctx context.Context,
	repoRoot string,
	environment []string,
) ([]byte, []byte, error) {
	git, err := newSourceGit(ctx, repoRoot, environment)
	if err != nil {
		return nil, nil, err
	}
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
			name: "index-fsmonitor",
			args: []string{"ls-files", "-f", "-z"},
		},
		{
			name: "index-resolve-undo",
			args: []string{"ls-files", "--resolve-undo", "-z"},
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
		output, err := git.output(part.args...)
		if err != nil {
			return nil, nil, fmt.Errorf("snapshot repository %s: %w", part.name, err)
		}
		_, _ = fmt.Fprintf(digest, "%s\x00%d\x00", part.name, len(output))
		_, _ = digest.Write(output)
		if part.name == "untracked" {
			untracked = output
		}
	}
	rawIndex, err := rawIndexState(git)
	if err != nil {
		return nil, nil, err
	}
	_, _ = fmt.Fprintf(digest, "%s\x00%d\x00", "raw-index-state", len(rawIndex))
	_, _ = digest.Write(rawIndex)
	return digest.Sum(nil), untracked, nil
}

func rawIndexState(git *sourceGit) ([]byte, error) {
	var state bytes.Buffer
	for _, query := range []struct {
		name string
		args []string
	}{
		{
			name: "index",
			args: []string{"rev-parse", "--path-format=absolute", "--git-path", "index"},
		},
		{
			name: "shared-index",
			args: []string{"rev-parse", "--path-format=absolute", "--shared-index-path"},
		},
	} {
		output, err := git.output(query.args...)
		if err != nil {
			return nil, fmt.Errorf("resolve repository %s path: %w", query.name, err)
		}
		path := strings.TrimSpace(string(output))
		if path == "" {
			_, _ = fmt.Fprintf(&state, "%s\x00absent\x00", query.name)
			continue
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(git.repoRoot, path)
		}
		data, err := readRegularFileNoFollow(filepath.Dir(path), filepath.ToSlash(filepath.Base(path)))
		if err != nil {
			return nil, fmt.Errorf("read repository %s state: %w", query.name, err)
		}
		hash := sha256.Sum256(data)
		_, _ = fmt.Fprintf(&state, "%s\x00%x\x00", query.name, hash)
	}
	return state.Bytes(), nil
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
