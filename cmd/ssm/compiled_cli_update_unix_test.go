//go:build !windows

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func assertCompiledFileUnchanged(t *testing.T, path string, before compiledFileIdentity) {
	t.Helper()
	if got := loadCompiledFileIdentity(t, path); got != before {
		t.Fatal("compiled CLI executable changed unexpectedly")
	}
}

func TestCompiledCLICommandsSurviveMovedOrUnlinkedExecutable(t *testing.T) {
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skipf("procfs file-descriptor execution is unavailable: %v", err)
	}
	harness := newCompiledCLIHarness(t)
	harness.SaveVault(t, nil)

	tests := []struct {
		name string
		args []string
	}{
		{name: "help", args: []string{"--help"}},
		{name: "version", args: []string{"--version"}},
		{name: "unrelated offline command", args: []string{"list", "--offline", "--json"}},
	}
	baselines := make(map[string]compiledCLIResult, len(tests))
	for _, test := range tests {
		baselines[test.name] = harness.Run(t, "ssm", nil, test.args...)
	}

	executable, err := os.Open(harness.paths["ssm"]) //nolint:gosec // test-owned compiled executable
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := executable.Close(); err != nil {
			t.Errorf("close moved/unlinked compiled executable: %v", err)
		}
	}()
	movedExecutable := harness.paths["ssm"] + ".moved"
	if err := os.Rename(harness.paths["ssm"], movedExecutable); err != nil {
		t.Fatal(err)
	}

	assertBehavior := func(t *testing.T, executableState string) {
		t.Helper()
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), compiledCLISubprocessTimeout)
				defer cancel()
				command := exec.CommandContext(ctx, "/proc/self/fd/3", test.args...) //nolint:gosec // fd 3 is the test-owned compiled executable
				command.ExtraFiles = []*os.File{executable}
				command.Env = isolatedCompiledCLIEnvironmentWith(
					harness.home,
					harness.temp,
					map[string]string{"SSM_MASTER_PASS_FILE": harness.passPath},
				)
				var stdout, stderr bytes.Buffer
				command.Stdout = &stdout
				command.Stderr = &stderr
				processExit := 0
				if err := command.Run(); err != nil {
					if errors.Is(ctx.Err(), context.DeadlineExceeded) {
						t.Fatalf("%s compiled CLI exceeded %s", executableState, compiledCLISubprocessTimeout)
					}
					var exitErr *exec.ExitError
					if !errors.As(err, &exitErr) {
						t.Fatalf("execute %s compiled CLI: %v", executableState, err)
					}
					processExit = exitErr.ExitCode()
				}
				got := compiledCLIResult{
					ProcessExit: processExit,
					Stdout:      stdout.String(),
					Stderr:      stderr.String(),
				}
				if want := baselines[test.name]; !reflect.DeepEqual(got, want) {
					t.Fatalf(
						"%s executable result = %s, want baseline %s",
						executableState,
						compiledOutputIdentity(got),
						compiledOutputIdentity(want),
					)
				}
			})
		}
	}

	t.Run("moved", func(t *testing.T) {
		assertBehavior(t, "moved")
	})
	if err := os.Remove(movedExecutable); err != nil {
		t.Fatal(err)
	}
	t.Run("unlinked", func(t *testing.T) {
		assertBehavior(t, "unlinked")
	})
}
