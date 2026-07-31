//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const windowsCompiledContractStageLinkEnv = "SSM_TEST_COMPILED_WINDOWS_STAGE_LINK"

func assertCompiledFileUnchanged(t *testing.T, path string, before compiledFileIdentity) {
	t.Helper()
	if got := loadCompiledFileIdentity(t, path); got != before {
		t.Fatal("compiled CLI executable changed after the characterized replacement failure")
	}
}

func TestCompiledWindowsBlockedPreparedRecoveryStopsStartupDispatch(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	replacement, err := os.ReadFile(cli.paths["ssm"]) //nolint:gosec // test-owned compiled CLI fixture
	if err != nil {
		t.Fatal(err)
	}
	compiledUpdateServer.ConfigureRelease("v1.5.0", replacement)
	stageAlias := filepath.Join(filepath.Dir(cli.paths["ssm"]), "late-stage-alias.exe")
	result := cli.RunWithEnv(t, "ssm", nil, map[string]string{
		"SSM_UPDATE_REPO":                   "fixture/repo",
		windowsCompiledContractStageLinkEnv: stageAlias,
	}, "update")
	if result.ProcessExit != 1 ||
		!strings.Contains(result.Stderr, "rollback failed") {
		t.Fatalf(
			"compiled prepared-recovery setup did not fail closed; output=%s",
			compiledOutputIdentity(result),
		)
	}

	target := cli.paths["ssm"]
	backup := filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".old")
	record := filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".old.state")
	for _, path := range []string{target, stageAlias, backup, record} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("compiled prepared-recovery fixture is missing %s: %v", filepath.Base(path), err)
		}
	}
	if err := os.Remove(stageAlias); err != nil {
		t.Fatalf("release compiled prepared-state hard link: %v", err)
	}
	targetPointer, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	hostileHandle, err := windows.CreateFile(
		targetPointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		t.Fatalf("open compiled hostile no-delete-share handle: %v", err)
	}
	hostileHandleOpen := true
	defer func() {
		if hostileHandleOpen {
			_ = windows.CloseHandle(hostileHandle)
		}
	}()

	blocked := cli.RunWithEnv(t, "ssm", nil, map[string]string{
		"SSM_UPDATE_REPO": "off",
	}, "--version")
	if blocked.ProcessExit != 1 ||
		blocked.Stdout != "" ||
		!strings.Contains(blocked.Stderr, "startup executable recovery failed") ||
		!strings.Contains(blocked.Stderr, "restore Windows rollback image") {
		t.Fatalf(
			"blocked compiled startup dispatched a successful command; output=%s",
			compiledOutputIdentity(blocked),
		)
	}
	for _, path := range []string{backup, record} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("blocked compiled startup lost recovery evidence %s: %v", filepath.Base(path), err)
		}
	}
	machineBlocked := cli.RunWithEnv(t, "ssm", nil, map[string]string{
		"SSM_UPDATE_REPO": "off",
	}, "--json", "--version")
	assertCompiledMachineContract(t, machineBlocked, compiledMachineContract{
		OK:          false,
		Error:       "update_failed",
		Stage:       "update",
		JSONExit:    1,
		ProcessExit: 1,
		Hint:        "the prior executable was preserved; retry after resolving the reported update failure",
	})
	for _, path := range []string{backup, record} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("blocked machine startup lost recovery evidence %s: %v", filepath.Base(path), err)
		}
	}

	if err := windows.CloseHandle(hostileHandle); err != nil {
		t.Fatalf("release compiled startup sharing handle: %v", err)
	}
	hostileHandleOpen = false
	recovered := cli.RunWithEnv(t, "ssm", nil, map[string]string{
		"SSM_UPDATE_REPO": "off",
	}, "--version")
	if recovered.ProcessExit != 0 ||
		recovered.Stdout != "ssm 1.4.3\n" ||
		recovered.Stderr != "" {
		t.Fatalf(
			"compiled startup did not recover after hostile link release; output=%s",
			compiledOutputIdentity(recovered),
		)
	}
	for _, path := range []string{backup, record} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("successful compiled startup retained %s: %v", filepath.Base(path), err)
		}
	}
}
