package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProfileCancellationTerminatesGrandchildBeforeWorkspaceCleanup(t *testing.T) {
	repo := newGoTestRepository(t)
	observationRoot := t.TempDir()
	started := filepath.Join(observationRoot, "grandchild-started")
	delayedMutation := filepath.Join(observationRoot, "post-cancel-mutation")
	fixture := fmt.Sprintf(`package verifyfixture

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestCancellationGrandchild(t *testing.T) {
	if os.Getenv("SSM_VERIFY_GRANDCHILD") != "1" {
		return
	}
	time.Sleep(800 * time.Millisecond)
	_ = os.WriteFile(%q, []byte("descendant survived cancellation"), 0o600)
}

func TestCancellationParent(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestCancellationGrandchild$")
	command.Env = append(os.Environ(), "SSM_VERIFY_GRANDCHILD=1")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(%q, []byte("started"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {}
}
`, delayedMutation, started)
	writeTestFile(t, filepath.Join(repo, "cancellation_test.go"), fixture)
	gitOutput(t, repo, "add", "cancellation_test.go")
	gitOutput(t, repo, "commit", "--quiet", "-m", "add cancellation fixture")

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
			t.Fatal("timed out waiting for cancellation grandchild")
		}
		select {
		case got := <-finished:
			t.Fatalf("profile exited before cancellation: err=%v result=%+v", got.err, got.result)
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()

	var got outcome
	select {
	case got = <-finished:
	case <-time.After(15 * time.Second):
		t.Fatal("profile did not finish after cancellation")
	}
	if !errors.Is(got.err, context.Canceled) {
		t.Errorf("cancellation error = %v, want context.Canceled (result=%+v)", got.err, got.result)
	}
	if workspace == "" {
		t.Fatal("action workspace was not observed")
	}
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Errorf("workspace still exists after cancellation cleanup: %v", err)
	}

	time.Sleep(time.Second)
	if data, err := os.ReadFile(delayedMutation); err == nil { //nolint:gosec // path is created beneath this test's private temporary directory
		t.Errorf("descendant mutated after cancellation: %s", strings.TrimSpace(string(data)))
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestOwnedCommandPreservesDirectExitError(t *testing.T) {
	if os.Getenv("SSM_VERIFY_DIRECT_FAILURE_HELPER") == "1" {
		os.Exit(23)
	}
	environment := append(os.Environ(), "SSM_VERIFY_DIRECT_FAILURE_HELPER=1")
	result := executeCommand(
		context.Background(),
		Command{
			Executable: os.Args[0],
			Args:       []string{"-test.run=^TestOwnedCommandPreservesDirectExitError$"},
		},
		actionContext{
			RepoRoot:    t.TempDir(),
			Environment: environment,
		},
	)
	if result.Status != statusFailed {
		t.Fatalf("status = %q, want %q", result.Status, statusFailed)
	}
	var exitError *exec.ExitError
	if !errors.As(result.Err, &exitError) {
		t.Fatalf("error = %v, want exec.ExitError", result.Err)
	}
	if exitError.ExitCode() != 23 {
		t.Fatalf("exit code = %d, want 23", exitError.ExitCode())
	}
}
