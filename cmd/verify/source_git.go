package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// sourceGit is the only boundary for Git commands that inspect the source
// repository. It first reads local configuration without following includes or
// running repository-configured commands, then applies defense-in-depth
// command overrides to every subsequent probe.
type sourceGit struct {
	ctx         context.Context
	repoRoot    string
	environment []string
}

func newSourceGit(ctx context.Context, repoRoot string, environment []string) (*sourceGit, error) {
	if len(environment) == 0 {
		return nil, errors.New("isolated Git environment is required")
	}
	git := &sourceGit{
		ctx:         ctx,
		repoRoot:    repoRoot,
		environment: isolatedSourceGitEnvironment(environment),
	}
	if _, err := disabledGitHooksPath(git.environment); err != nil {
		return nil, err
	}
	if err := git.inspectLocalConfiguration(); err != nil {
		return nil, err
	}
	return git, nil
}

func (git *sourceGit) output(args ...string) ([]byte, error) {
	command, err := git.command(args...)
	if err != nil {
		return nil, err
	}
	return ownedCommandOutput(git.ctx, command)
}

func (git *sourceGit) combinedOutput(args ...string) ([]byte, error) {
	command, err := git.command(args...)
	if err != nil {
		return nil, err
	}
	return ownedCommandCombinedOutput(git.ctx, command)
}

func (git *sourceGit) runWithWriters(stdout, stderr io.Writer, args ...string) error {
	command, err := git.command(args...)
	if err != nil {
		return err
	}
	command.Stdout = stdout
	command.Stderr = stderr
	return runOwnedCommand(git.ctx, command)
}

func (git *sourceGit) command(args ...string) (*exec.Cmd, error) {
	if err := git.inspectLocalConfiguration(); err != nil {
		return nil, err
	}
	hooksPath, err := disabledGitHooksPath(git.environment)
	if err != nil {
		return nil, err
	}
	hardened := []string{
		"-C", git.repoRoot,
		"-c", "core.fsmonitor=false",
		"-c", "core.hooksPath=" + hooksPath,
		"-c", "core.untrackedCache=false",
		"-c", "core.preloadIndex=false",
		"-c", "credential.helper=",
	}
	command := exec.Command("git", append(hardened, args...)...) //nolint:gosec // callers supply only fixed verifier-owned Git argv
	command.Env = git.environment
	return command, nil
}

func (git *sourceGit) inspectLocalConfiguration() error {
	local, err := git.readConfigurationScope("--local")
	if err != nil {
		return fmt.Errorf("inspect local Git configuration without includes: %w", err)
	}
	if err := rejectUnsafeLocalGitConfiguration(local); err != nil {
		return err
	}
	if !gitWorktreeConfigurationEnabled(local) {
		return nil
	}
	worktree, err := git.readConfigurationScope("--worktree")
	if err != nil {
		return fmt.Errorf("inspect worktree Git configuration without includes: %w", err)
	}
	return rejectUnsafeLocalGitConfiguration(worktree)
}

func (git *sourceGit) readConfigurationScope(scope string) ([]gitConfigEntry, error) {
	command := exec.Command( //nolint:gosec // scope is one of the two fixed callers above
		"git", "-C", git.repoRoot, "config", scope, "--no-includes", "--null", "--list",
	)
	command.Env = git.environment
	output, err := ownedCommandOutput(git.ctx, command)
	if err != nil {
		return nil, err
	}
	return parseNullGitConfiguration(output)
}

type gitConfigEntry struct {
	key   string
	value string
}

func parseNullGitConfiguration(output []byte) ([]gitConfigEntry, error) {
	records := bytes.Split(bytes.TrimSuffix(output, []byte{0}), []byte{0})
	entries := make([]gitConfigEntry, 0, len(records))
	for _, record := range records {
		if len(record) == 0 {
			continue
		}
		key, value, ok := bytes.Cut(record, []byte{'\n'})
		if !ok || len(key) == 0 {
			return nil, errors.New("git returned malformed local configuration")
		}
		entries = append(entries, gitConfigEntry{key: string(key), value: string(value)})
	}
	return entries, nil
}

func rejectUnsafeLocalGitConfiguration(entries []gitConfigEntry) error {
	for _, entry := range entries {
		if unsafeLocalGitConfigurationKey(entry.key) {
			return fmt.Errorf("unsafe/sensitive local Git configuration key %q is present", entry.key)
		}
	}
	return nil
}

func unsafeLocalGitConfigurationKey(key string) bool {
	key = strings.ToLower(key)
	if key == "include.path" || strings.HasPrefix(key, "includeif.") {
		return true
	}
	switch key {
	case "core.askpass",
		"core.attributesfile",
		"core.excludesfile",
		"core.fsmonitor",
		"core.fsmonitorhookversion",
		"core.gitproxy",
		"core.hookspath",
		"core.sshcommand",
		"core.worktree",
		"diff.external",
		"merge.tool",
		"sequence.editor":
		return true
	}
	if strings.HasPrefix(key, "credential.") && (key == "credential.helper" || strings.HasSuffix(key, ".helper")) {
		return true
	}
	if strings.HasPrefix(key, "filter.") &&
		(strings.HasSuffix(key, ".clean") || strings.HasSuffix(key, ".process") || strings.HasSuffix(key, ".smudge")) {
		return true
	}
	if strings.HasPrefix(key, "diff.") &&
		(strings.HasSuffix(key, ".command") || strings.HasSuffix(key, ".textconv")) {
		return true
	}
	if strings.HasPrefix(key, "merge.") && strings.HasSuffix(key, ".driver") {
		return true
	}
	if strings.HasPrefix(key, "mergetool.") && strings.HasSuffix(key, ".cmd") {
		return true
	}
	if strings.HasPrefix(key, "http.") && strings.HasSuffix(key, ".extraheader") {
		return true
	}
	if strings.HasPrefix(key, "url.") &&
		(strings.HasSuffix(key, ".insteadof") || strings.HasSuffix(key, ".pushinsteadof")) {
		return true
	}
	if strings.HasPrefix(key, "remote.") && strings.HasSuffix(key, ".pushurl") {
		return true
	}
	return false
}

func gitWorktreeConfigurationEnabled(entries []gitConfigEntry) bool {
	enabled := false
	for _, entry := range entries {
		if strings.EqualFold(entry.key, "extensions.worktreeConfig") {
			switch strings.ToLower(strings.TrimSpace(entry.value)) {
			case "true", "yes", "on", "1":
				enabled = true
			default:
				enabled = false
			}
		}
	}
	return enabled
}

func isolatedSourceGitEnvironment(environment []string) []string {
	blockedPrefixes := []string{
		"GIT_ALTERNATE_OBJECT_DIRECTORIES=",
		"GIT_COMMON_DIR=",
		"GIT_CONFIG_COUNT=",
		"GIT_CONFIG_KEY_",
		"GIT_CONFIG_PARAMETERS=",
		"GIT_CONFIG_SYSTEM=",
		"GIT_CONFIG_VALUE_",
		"GIT_DIR=",
		"GIT_EXTERNAL_DIFF=",
		"GIT_INDEX_FILE=",
		"GIT_OBJECT_DIRECTORY=",
		"GIT_SSH=",
		"GIT_SSH_COMMAND=",
		"GIT_WORK_TREE=",
	}
	filtered := make([]string, 0, len(environment)+8)
	for _, entry := range environment {
		upper := strings.ToUpper(entry)
		blocked := false
		for _, prefix := range blockedPrefixes {
			if strings.HasPrefix(upper, prefix) {
				blocked = true
				break
			}
		}
		if !blocked &&
			!strings.HasPrefix(upper, "GIT_CONFIG_NOSYSTEM=") &&
			!strings.HasPrefix(upper, "GIT_CONFIG_GLOBAL=") &&
			!strings.HasPrefix(upper, "GIT_OPTIONAL_LOCKS=") &&
			!strings.HasPrefix(upper, "GIT_TERMINAL_PROMPT=") &&
			!strings.HasPrefix(upper, "GIT_ATTR_NOSYSTEM=") {
			filtered = append(filtered, entry)
		}
	}
	return append(filtered,
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_CONFIG_COUNT=0",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_SYSTEM="+os.DevNull,
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_TERMINAL_PROMPT=0",
	)
}

func disabledGitHooksPath(environment []string) (string, error) {
	if home, ok := environmentValue(environment, "HOME"); ok && filepath.IsAbs(home) {
		return filepath.Join(home, "disabled-git-hooks"), nil
	}
	return "", errors.New("isolated absolute HOME is required for disabled Git hooks")
}
