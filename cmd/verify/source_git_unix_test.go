//go:build unix

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileRejectsExecutableLocalGitConfigurationBeforeItCanRun(t *testing.T) {
	helperRoot := t.TempDir()
	marker := filepath.Join(helperRoot, "executed")
	helper := filepath.Join(helperRoot, "git-config-command")
	writeTestFile(t, helper, fmt.Sprintf("#!/bin/sh\nprintf executed > %q\nexit 1\n", marker))
	if err := os.Chmod(helper, 0o700); err != nil { //nolint:gosec // adversarial test helper must be executable
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		key        string
		value      string
		attributes string
		include    bool
	}{
		{name: "fsmonitor", key: "core.fsmonitor", value: helper},
		{name: "clean filter", key: "filter.adversarial.clean", value: helper, attributes: "sentinel.txt filter=adversarial\n"},
		{name: "process filter", key: "filter.adversarial.process", value: helper, attributes: "sentinel.txt filter=adversarial\n"},
		{name: "smudge filter", key: "filter.adversarial.smudge", value: helper},
		{name: "external diff", key: "diff.external", value: helper},
		{name: "diff driver command", key: "diff.adversarial.command", value: helper},
		{name: "diff textconv", key: "diff.adversarial.textconv", value: helper},
		{name: "merge driver", key: "merge.adversarial.driver", value: helper},
		{name: "merge tool command", key: "mergetool.adversarial.cmd", value: helper},
		{name: "hooks path", key: "core.hooksPath", value: helperRoot},
		{name: "credential helper", key: "credential.helper", value: helper},
		{name: "askpass", key: "core.askPass", value: helper},
		{name: "ssh command", key: "core.sshCommand", value: helper},
		{name: "git proxy", key: "core.gitProxy", value: helper},
		{name: "include with fsmonitor", key: "core.fsmonitor", value: helper, include: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			repo := newCleanTestRepository(t)
			if test.attributes != "" {
				writeTestFile(t, filepath.Join(repo, ".gitattributes"), test.attributes)
				gitOutput(t, repo, "add", ".gitattributes")
				gitOutput(t, repo, "commit", "--quiet", "-m", "add adversarial attributes")
			}
			if test.include {
				included := filepath.Join(t.TempDir(), "included.gitconfig")
				writeTestFile(t, included, fmt.Sprintf("[%s]\n\t%s = %s\n", configSectionAndName(test.key), configVariableName(test.key), test.value))
				gitOutput(t, repo, "config", "--local", "include.path", included)
			} else {
				gitOutput(t, repo, "config", "--local", test.key, test.value)
			}

			actionCalled := false
			deps := passingTestDependencies(t, repo)
			deps.prerequisites = func(
				ctx context.Context,
				root string,
				prerequisite Prerequisite,
				environment []string,
			) prerequisiteState {
				if prerequisite.Kind == "repository" {
					return checkPrerequisite(ctx, root, prerequisite, environment)
				}
				return prerequisiteState{available: true}
			}
			deps.actions = func(context.Context, Action, actionContext) checkResult {
				actionCalled = true
				return checkResult{Status: statusPassed}
			}
			deps.stdout = io.Discard
			deps.stderr = io.Discard

			_, err := executeProfile(context.Background(), verificationManifest(), "fast", deps)
			if err == nil || !strings.Contains(err.Error(), "local Git configuration") {
				t.Errorf("error = %v, want unsafe local Git configuration failure", err)
			}
			if actionCalled {
				t.Error("profile action ran with executable local Git configuration")
			}
			if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
				t.Errorf("local Git configuration command executed before rejection: %v", statErr)
			}
		})
	}
}

func TestSourceGitIgnoresExecutableGlobalAndSystemConfiguration(t *testing.T) {
	helperRoot := t.TempDir()
	marker := filepath.Join(helperRoot, "executed")
	helper := filepath.Join(helperRoot, "git-config-command")
	writeTestFile(t, helper, fmt.Sprintf("#!/bin/sh\nprintf executed > %q\nexit 1\n", marker))
	if err := os.Chmod(helper, 0o700); err != nil { //nolint:gosec // adversarial test helper must be executable
		t.Fatal(err)
	}
	global := filepath.Join(helperRoot, "global.gitconfig")
	system := filepath.Join(helperRoot, "system.gitconfig")
	for _, path := range []string{global, system} {
		writeTestFile(t, path, fmt.Sprintf("[core]\n\tfsmonitor = %s\n", helper))
	}

	repo := newCleanTestRepository(t)
	environment := newTestProcessEnvironment(t)
	environment = replaceEnvironmentValue(environment, "GIT_CONFIG_GLOBAL", global)
	environment = replaceEnvironmentValue(environment, "GIT_CONFIG_SYSTEM", system)
	git, err := newSourceGit(context.Background(), repo, environment)
	if err != nil {
		t.Fatalf("create hardened source Git boundary: %v", err)
	}
	if _, err := git.output("ls-files", "--stage", "-z", "--"); err != nil {
		t.Fatalf("inspect source repository: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("global or system Git command executed: %v", err)
	}
}

func TestSourceGitSupportsLinkedWorktreeAndRejectsUnsafeWorktreeConfiguration(t *testing.T) {
	mainWorktree := newCleanTestRepository(t)
	linkedWorktree := filepath.Join(t.TempDir(), "linked")
	gitOutput(t, mainWorktree, "worktree", "add", "--quiet", "--detach", linkedWorktree, "HEAD")
	writeTestFile(t, filepath.Join(linkedWorktree, "sentinel.txt"), "linked dirty worktree\n")

	environment := newTestProcessEnvironment(t)
	before, err := repositorySnapshotWithEnvironment(context.Background(), linkedWorktree, environment)
	if err != nil {
		t.Fatalf("snapshot linked worktree: %v", err)
	}
	if len(before) == 0 {
		t.Fatal("linked worktree snapshot is empty")
	}
	workspace := filepath.Join(t.TempDir(), "workspace")
	tracked, err := materializeActionWorkspace(
		context.Background(),
		linkedWorktree,
		workspace,
		environment,
	)
	if err != nil {
		t.Fatalf("materialize linked worktree: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(workspace, "sentinel.txt")) //nolint:gosec // test-owned workspace
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "linked dirty worktree\n" || len(tracked) == 0 {
		t.Fatalf("linked dirty state was not preserved: data=%q tracked=%d", data, len(tracked))
	}

	gitOutput(t, mainWorktree, "config", "--local", "extensions.worktreeConfig", "true")
	gitOutput(t, linkedWorktree, "config", "--worktree", "core.hooksPath", t.TempDir())
	if _, err := newSourceGit(context.Background(), linkedWorktree, environment); err == nil ||
		!strings.Contains(err.Error(), "core.hookspath") {
		t.Fatalf("unsafe linked-worktree config error = %v", err)
	}
}

func configSectionAndName(key string) string {
	section, rest, _ := strings.Cut(key, ".")
	if subsection, _, ok := strings.Cut(rest, "."); ok {
		return section + " \"" + subsection + "\""
	}
	return section
}

func configVariableName(key string) string {
	_, rest, _ := strings.Cut(key, ".")
	if _, name, ok := strings.Cut(rest, "."); ok {
		return name
	}
	return rest
}
