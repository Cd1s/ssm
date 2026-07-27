//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if current := os.Getenv("GORACE"); current == "" {
		_ = os.Setenv("GORACE", "atexit_sleep_ms=0")
	} else {
		_ = os.Setenv("GORACE", current+" atexit_sleep_ms=0")
	}
	os.Exit(m.Run())
}

func TestOwnedCommandDoesNotMakeVerifierAChildSubreaper(t *testing.T) {
	if os.Getenv("SSM_VERIFY_SUBREAPER_TARGET") == "1" {
		return
	}
	before := linuxChildSubreaperSetting(t)
	command := exec.Command( //nolint:gosec // os.Args[0] is the current controlled Go test binary
		os.Args[0],
		"-test.run=^TestOwnedCommandDoesNotMakeVerifierAChildSubreaper$",
	)
	command.Env = append(os.Environ(), "SSM_VERIFY_SUBREAPER_TARGET=1")
	if err := runOwnedCommand(context.Background(), command); err != nil {
		t.Fatalf("ordinary owned command failed: %v", err)
	}
	after := linuxChildSubreaperSetting(t)
	if after != before {
		t.Fatalf("verifier child-subreaper setting changed from %d to %d", before, after)
	}
}

func linuxChildSubreaperSetting(t *testing.T) int32 {
	t.Helper()
	var setting int32
	if err := unix.Prctl(
		unix.PR_GET_CHILD_SUBREAPER,
		uintptr(unsafe.Pointer(&setting)), //nolint:gosec // PR_GET_CHILD_SUBREAPER requires a pointer-sized output argument
		0,
		0,
		0,
	); err != nil {
		t.Fatalf("read verifier child-subreaper setting: %v", err)
	}
	return setting
}

func TestLinuxSupervisorRaceDelayDoesNotChangeTargetEnvironment(t *testing.T) {
	t.Setenv("GORACE", "history_size=7")
	t.Setenv("SSM_VERIFY_ENVIRONMENT_PROBE", "preserved")

	helperEnvironment := linuxSupervisorEnvironment()
	if got, ok := environmentValue(helperEnvironment, "GORACE"); !ok || got != "history_size=7 atexit_sleep_ms=0" {
		t.Fatalf("supervisor GORACE = %q, %v", got, ok)
	}
	targetEnvironment := effectiveProcessTreeEnvironment(nil)
	if got, ok := environmentValue(targetEnvironment, "GORACE"); !ok || got != "history_size=7" {
		t.Fatalf("target GORACE = %q, %v", got, ok)
	}
	if got, ok := environmentValue(targetEnvironment, "SSM_VERIFY_ENVIRONMENT_PROBE"); !ok || got != "preserved" {
		t.Fatalf("target environment probe = %q, %v", got, ok)
	}
	if explicit := effectiveProcessTreeEnvironment([]string{}); len(explicit) != 0 {
		t.Fatalf("explicit empty target environment = %q", explicit)
	}
}

func TestOwnedCommandCleansTransientSetsidForkBursts(t *testing.T) {
	const attempts = 64

	role := os.Getenv("SSM_VERIFY_TRANSIENT_FORK_ROLE")
	mutation := os.Getenv("SSM_VERIFY_TRANSIENT_FORK_MUTATION")
	release := os.Getenv("SSM_VERIFY_TRANSIENT_FORK_RELEASE")
	switch role {
	case "escaped":
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(release); err == nil { //nolint:gosec // release is a parent-test-owned path beneath t.TempDir
				break
			} else if !os.IsNotExist(err) {
				return
			}
			if time.Now().After(deadline) {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
		_ = os.WriteFile(mutation, []byte("escaped transient descendant mutated"), 0o600) //nolint:gosec // path is supplied by the parent test from its private t.TempDir
		return
	case "transient":
		command := exec.Command( //nolint:gosec // os.Args[0] is the current controlled Go test binary
			os.Args[0],
			"-test.run=^TestOwnedCommandCleansTransientSetsidForkBursts$",
		)
		command.Env = append(os.Environ(), "SSM_VERIFY_TRANSIENT_FORK_ROLE=escaped")
		command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		return
	case "root":
		command := exec.Command( //nolint:gosec // os.Args[0] is the current controlled Go test binary
			os.Args[0],
			"-test.run=^TestOwnedCommandCleansTransientSetsidForkBursts$",
		)
		command.Env = append(os.Environ(), "SSM_VERIFY_TRANSIENT_FORK_ROLE=transient")
		if err := command.Run(); err != nil {
			t.Fatal(err)
		}
		return
	}

	observationRoot := t.TempDir()
	releaseRoot := t.TempDir()
	for attempt := range attempts {
		mutation = filepath.Join(observationRoot, "mutation-"+strconv.Itoa(attempt))
		release = filepath.Join(releaseRoot, "release-"+strconv.Itoa(attempt))
		command := exec.Command( //nolint:gosec // os.Args[0] is the current controlled Go test binary
			os.Args[0],
			"-test.run=^TestOwnedCommandCleansTransientSetsidForkBursts$",
		)
		command.Env = append(
			os.Environ(),
			"SSM_VERIFY_TRANSIENT_FORK_ROLE=root",
			"SSM_VERIFY_TRANSIENT_FORK_MUTATION="+mutation,
			"SSM_VERIFY_TRANSIENT_FORK_RELEASE="+release,
		)
		if err := runOwnedCommand(context.Background(), command); err != nil {
			t.Fatalf("transient fork attempt %d failed: %v", attempt, err)
		}
		if err := os.WriteFile(release, []byte("command cleanup returned"), 0o600); err != nil {
			t.Fatalf("release transient fork attempt %d: %v", attempt, err)
		}
	}

	time.Sleep(600 * time.Millisecond)
	entries, err := os.ReadDir(observationRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%d of %d transient setsid descendants mutated after command cleanup", len(entries), attempts)
	}
}
