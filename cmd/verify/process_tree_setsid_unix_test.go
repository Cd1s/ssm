//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProfileCancellationTerminatesSetsidDescendantBeforeWorkspaceCleanup(t *testing.T) {
	testProfileTerminatesSetsidDescendantBeforeWorkspaceCleanup(t, true)
}

func TestProfileCompletionTerminatesSetsidDescendantBeforeWorkspaceCleanup(t *testing.T) {
	testProfileTerminatesSetsidDescendantBeforeWorkspaceCleanup(t, false)
}

func TestOwnedCommandCompletionCleansSetsidDescendantWithInheritedPipes(t *testing.T) {
	role := os.Getenv("SSM_VERIFY_INHERITED_PIPE_ROLE")
	started := os.Getenv("SSM_VERIFY_INHERITED_PIPE_STARTED")
	delayedMutation := os.Getenv("SSM_VERIFY_INHERITED_PIPE_MUTATION")
	release := os.Getenv("SSM_VERIFY_INHERITED_PIPE_RELEASE")
	switch role {
	case "descendant":
		if err := os.WriteFile(started, []byte("started"), 0o600); err != nil { //nolint:gosec // path is supplied by the parent test from its private t.TempDir
			t.Fatal(err)
		}
		waitForProcessTreeTestFile(t, release)
		_ = os.WriteFile(delayedMutation, []byte("descendant retained inherited pipes"), 0o600) //nolint:gosec // path is supplied by the parent test from its private t.TempDir
		time.Sleep(30 * time.Second)
		return
	case "root":
		command := exec.Command( //nolint:gosec // os.Args[0] is the current controlled Go test binary
			os.Args[0],
			"-test.run=^TestOwnedCommandCompletionCleansSetsidDescendantWithInheritedPipes$",
		)
		command.Env = append(os.Environ(), "SSM_VERIFY_INHERITED_PIPE_ROLE=descendant")
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		waitForProcessTreeTestFile(t, started)
		return
	}

	observationRoot := t.TempDir()
	started = filepath.Join(observationRoot, "inherited-pipe-descendant-started")
	delayedMutation = filepath.Join(observationRoot, "inherited-pipe-delayed-mutation")
	release = filepath.Join(observationRoot, "inherited-pipe-release")
	command := exec.Command( //nolint:gosec // os.Args[0] is the current controlled Go test binary
		os.Args[0],
		"-test.run=^TestOwnedCommandCompletionCleansSetsidDescendantWithInheritedPipes$",
	)
	command.Env = append(
		os.Environ(),
		"SSM_VERIFY_INHERITED_PIPE_ROLE=root",
		"SSM_VERIFY_INHERITED_PIPE_STARTED="+started,
		"SSM_VERIFY_INHERITED_PIPE_MUTATION="+delayedMutation,
		"SSM_VERIFY_INHERITED_PIPE_RELEASE="+release,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := ownedCommandCombinedOutput(ctx, command); err != nil {
		t.Fatalf("owned command with inherited descendant pipes failed: %v", err)
	}
	if err := os.WriteFile(release, []byte("command cleanup returned"), 0o600); err != nil {
		t.Fatalf("release inherited-pipe descendant: %v", err)
	}

	time.Sleep(600 * time.Millisecond)
	if data, err := os.ReadFile(delayedMutation); err == nil { //nolint:gosec // path is beneath this test's private temporary directory
		t.Fatalf("setsid descendant mutated after inherited-pipe cleanup: %s", strings.TrimSpace(string(data)))
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func testProfileTerminatesSetsidDescendantBeforeWorkspaceCleanup(t *testing.T, cancelProfile bool) {
	t.Helper()
	repo := newGoTestRepository(t)
	observationRoot := t.TempDir()
	started := filepath.Join(observationRoot, "setsid-descendant-started")
	delayedMutation := filepath.Join(observationRoot, "post-cleanup-setsid-mutation")
	fixture := fmt.Sprintf(`package verifyfixture

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestSetsidDescendant(t *testing.T) {
	if os.Getenv("SSM_VERIFY_SETSID_DESCENDANT") != "1" {
		return
	}
	if err := os.WriteFile(%q, []byte("started in new session"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(800 * time.Millisecond)
	_ = os.WriteFile(%q, []byte("setsid descendant survived command cleanup"), 0o600)
}

func TestSetsidParent(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestSetsidDescendant$")
	command.Env = append(os.Environ(), "SSM_VERIFY_SETSID_DESCENDANT=1")
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(%q); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for setsid descendant")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if %t {
		select {}
	}
}
`, started, delayedMutation, started, cancelProfile)
	writeTestFile(t, filepath.Join(repo, "setsid_lifecycle_test.go"), fixture)
	gitOutput(t, repo, "add", "setsid_lifecycle_test.go")
	gitOutput(t, repo, "commit", "--quiet", "-m", "add setsid lifecycle fixture")

	manifest := verificationManifest()
	setProfileChecks(t, &manifest, "fast", []Check{unitCheck()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var workspace string
	deps := passingTestDependencies(t, repo)
	deps.actions = func(ctx context.Context, action Action, actionCtx actionContext) checkResult {
		workspace = actionCtx.RepoRoot
		return executeAction(ctx, action, actionCtx)
	}
	type outcome struct {
		result profileResult
		err    error
	}
	finished := make(chan outcome, 1)
	go func() {
		result, err := executeProfile(ctx, manifest, "fast", deps)
		finished <- outcome{result: result, err: err}
	}()

	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for setsid cancellation descendant")
		}
		select {
		case got := <-finished:
			t.Fatalf("profile exited before lifecycle observation: err=%v result=%+v", got.err, got.result)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if cancelProfile {
		cancel()
	}

	var got outcome
	select {
	case got = <-finished:
	case <-time.After(15 * time.Second):
		t.Fatal("profile did not finish after command lifecycle transition")
	}
	if cancelProfile {
		if !errors.Is(got.err, context.Canceled) {
			t.Errorf("cancellation error = %v, want context.Canceled (result=%+v)", got.err, got.result)
		}
	} else if got.err != nil {
		t.Errorf("completion error = %v, want nil (result=%+v)", got.err, got.result)
	}
	if workspace == "" {
		t.Fatal("action workspace was not observed")
	}
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Errorf("workspace still exists after command cleanup: %v", err)
	}

	time.Sleep(time.Second)
	if data, err := os.ReadFile(delayedMutation); err == nil { //nolint:gosec // path is created beneath this test's private temporary directory
		t.Errorf("setsid descendant mutated after workspace cleanup: %s", strings.TrimSpace(string(data)))
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
