//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestOwnedCommandCompletionClosesInheritedWindowsPipes(t *testing.T) {
	role := os.Getenv("SSM_VERIFY_WINDOWS_PIPE_ROLE")
	started := os.Getenv("SSM_VERIFY_WINDOWS_PIPE_STARTED")
	delayedMutation := os.Getenv("SSM_VERIFY_WINDOWS_PIPE_MUTATION")
	release := os.Getenv("SSM_VERIFY_WINDOWS_PIPE_RELEASE")
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
			"-test.run=^TestOwnedCommandCompletionClosesInheritedWindowsPipes$",
		)
		command.Env = append(os.Environ(), "SSM_VERIFY_WINDOWS_PIPE_ROLE=descendant")
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
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
		"-test.run=^TestOwnedCommandCompletionClosesInheritedWindowsPipes$",
	)
	command.Env = append(
		os.Environ(),
		"SSM_VERIFY_WINDOWS_PIPE_ROLE=root",
		"SSM_VERIFY_WINDOWS_PIPE_STARTED="+started,
		"SSM_VERIFY_WINDOWS_PIPE_MUTATION="+delayedMutation,
		"SSM_VERIFY_WINDOWS_PIPE_RELEASE="+release,
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
		t.Fatalf("descendant mutated after inherited-pipe cleanup: %s", strings.TrimSpace(string(data)))
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestOwnedCommandCancellationReleasesWindowsJobHandles(t *testing.T) {
	if os.Getenv("SSM_VERIFY_WINDOWS_JOB_HELPER") == "1" {
		time.Sleep(30 * time.Second)
		return
	}
	runtime.GC()
	before := currentProcessHandleCount(t)
	for range 5 {
		ctx, cancel := context.WithCancel(context.Background())
		command := exec.Command(os.Args[0], "-test.run=^TestOwnedCommandCancellationReleasesWindowsJobHandles$")
		command.Env = append(os.Environ(), "SSM_VERIFY_WINDOWS_JOB_HELPER=1")
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
		err := runOwnedCommand(ctx, command)
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("owned command error = %v, want context.Canceled", err)
		}
	}
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	after := currentProcessHandleCount(t)
	if after > before+2 {
		t.Fatalf("process handle count grew from %d to %d; verifier Job handles were not released", before, after)
	}
}

func currentProcessHandleCount(t *testing.T) uint32 {
	t.Helper()
	procedure := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount")
	var count uint32
	result, _, callErr := procedure.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&count)),
	)
	if result == 0 {
		t.Fatalf("GetProcessHandleCount: %v", callErr)
	}
	return count
}
