//go:build windows

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const (
	windowsCompiledContractStageLinkEnv = "SSM_TEST_COMPILED_WINDOWS_STAGE_LINK"
	compiledContractProvenanceRootEnv   = "SSM_TEST_COMPILED_PROVENANCE_ROOT"
)

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
	trustedRoot, err := compiledUpdateServer.ConfigureAuthenticatedRelease("v1.5.0", replacement)
	if err != nil {
		t.Fatalf("configure authenticated compiled update: %v", err)
	}
	stageAlias := filepath.Join(filepath.Dir(cli.paths["ssm"]), "late-stage-alias.exe")
	result := cli.RunWithEnv(t, "ssm", nil, map[string]string{
		"SSM_UPDATE_REPO":                   "fixture/repo",
		windowsCompiledContractStageLinkEnv: stageAlias,
		compiledContractProvenanceRootEnv:   base64.StdEncoding.EncodeToString(trustedRoot),
	}, "update")
	if result.ProcessExit != 1 ||
		!strings.Contains(result.Stderr, "ssm: error=update_recovery_required stage=update_recovery") ||
		!strings.Contains(result.Stderr, "rollback failed") ||
		!strings.Contains(result.Stderr, "authenticated original evidence was preserved; canonical restoration remains required before retrying") {
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
		!strings.Contains(blocked.Stderr, "ssm: error=update_recovery_required stage=update_recovery") ||
		!strings.Contains(blocked.Stderr, "startup executable recovery failed") ||
		!strings.Contains(blocked.Stderr, "restore Windows rollback image") ||
		!strings.Contains(blocked.Stderr, "authenticated original evidence was preserved; canonical restoration remains required before retrying") {
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
		Error:       "update_recovery_required",
		Stage:       "update_recovery",
		JSONExit:    1,
		ProcessExit: 1,
		Hint:        "authenticated original evidence was preserved; canonical restoration remains required before retrying",
	})
	for _, path := range []string{backup, record} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("blocked machine startup lost recovery evidence %s: %v", filepath.Base(path), err)
		}
	}
	for _, test := range []struct {
		name string
		args []string
	}{
		{
			name: "documented form without JSON option",
			args: []string{"run", "prod", "--stream"},
		},
		{
			name: "ordered global and command options",
			args: []string{
				"--offline",
				"--master-pass-file",
				cli.passPath,
				"--json",
				"run",
				"--json",
				"prod",
				"--stream",
				"--refresh=0",
			},
		},
		{
			name: "missing alias initialization",
			args: []string{"run", "--stream"},
		},
	} {
		t.Run("stream "+test.name, func(t *testing.T) {
			streamBlocked := cli.runWithStdinAndArgv0(
				t,
				"ssm",
				"sshctl",
				bytes.NewReader(nil),
				map[string]string{"SSM_UPDATE_REPO": "off"},
				test.args...,
			)
			if streamBlocked.ProcessExit != 1 || streamBlocked.Stderr != "" {
				t.Fatalf(
					"blocked compiled stream startup broke process framing; output=%s",
					compiledOutputIdentity(streamBlocked),
				)
			}
			lines := nonEmptyCompiledLines(streamBlocked.Stdout)
			if len(lines) != 1 || streamBlocked.Stdout != lines[0]+"\n" {
				t.Fatalf(
					"blocked compiled stream startup emitted %d terminal records; output=%s",
					len(lines),
					compiledOutputIdentity(streamBlocked),
				)
			}
			var compact bytes.Buffer
			if err := json.Compact(&compact, []byte(lines[0])); err != nil ||
				compact.String() != lines[0] {
				t.Fatalf(
					"blocked compiled stream startup was not compact NDJSON: %v; output=%s",
					err,
					compiledOutputIdentity(streamBlocked),
				)
			}
			var failure map[string]any
			if err := json.Unmarshal([]byte(lines[0]), &failure); err != nil {
				t.Fatalf("decode blocked stream startup failure: %v", err)
			}
			if failure["ok"] != false ||
				failure["error"] != "update_recovery_required" ||
				failure["stage"] != "update_recovery" ||
				failure["hint"] != "authenticated original evidence was preserved; canonical restoration remains required before retrying" ||
				!compiledJSONExitEquals(failure["exit"], 1) {
				t.Fatalf(
					"blocked compiled stream startup contract = %v; output=%s",
					failure,
					compiledOutputIdentity(streamBlocked),
				)
			}
			for _, path := range []string{backup, record} {
				if _, err := os.Stat(path); err != nil {
					t.Fatalf(
						"blocked stream startup lost recovery evidence %s: %v",
						filepath.Base(path),
						err,
					)
				}
			}
		})
	}

	if err := windows.CloseHandle(hostileHandle); err != nil {
		t.Fatalf("release compiled startup sharing handle: %v", err)
	}
	hostileHandleOpen = false
	deferred := cli.RunWithEnv(t, "ssm", nil, map[string]string{
		"SSM_UPDATE_REPO": "off",
	}, "--version")
	if deferred.ProcessExit != 1 ||
		deferred.Stdout != "" ||
		!strings.Contains(deferred.Stderr, "ssm: error=update_recovery_required stage=update_recovery") ||
		!strings.Contains(deferred.Stderr, "startup executable recovery failed") {
		t.Fatalf(
			"compiled startup dispatched while mapped prepared recovery remained; output=%s",
			compiledOutputIdentity(deferred),
		)
	}
	mapped := filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".mapped")
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("deferred compiled recovery retained rollback image: %v", err)
	}
	for _, path := range []string{record, mapped} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("blocked mapped compiled recovery lost deferred evidence %s: %v", filepath.Base(path), err)
		}
	}

	cleaned := cli.RunWithEnv(t, "ssm", nil, map[string]string{
		"SSM_UPDATE_REPO": "off",
	}, "--version")
	if cleaned.ProcessExit != 0 ||
		cleaned.Stdout != "ssm 1.4.3\n" ||
		cleaned.Stderr != "" {
		t.Fatalf(
			"compiled next startup did not clean displaced mapped image; output=%s",
			compiledOutputIdentity(cleaned),
		)
	}
	for _, path := range []string{backup, record, mapped} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("successful compiled startup retained %s: %v", filepath.Base(path), err)
		}
	}
}

func TestCompiledWindowsOrdinaryStartupNeedsNoExecutableDirectoryWrite(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	restore := makeCompiledDirectoryReadOnly(t, filepath.Dir(cli.paths["ssm"]))
	defer restore()
	writeProbe := filepath.Join(filepath.Dir(cli.paths["ssm"]), ".directory-write-probe")
	if err := os.WriteFile(writeProbe, []byte("write must be denied"), 0o600); err == nil { //nolint:gosec // test-owned denial probe
		_ = os.Remove(writeProbe)
		t.Fatal("compiled executable directory still permits file creation")
	}

	versionResult := cli.RunWithEnv(t, "ssm", nil, map[string]string{
		"SSM_UPDATE_REPO": "off",
	}, "--version")
	if versionResult.ProcessExit != 0 ||
		versionResult.Stdout != "ssm 1.4.3\n" ||
		versionResult.Stderr != "" {
		t.Fatalf(
			"read-only compiled --version startup failed; output=%s",
			compiledOutputIdentity(versionResult),
		)
	}
	helpResult := cli.RunWithEnv(t, "ssm", nil, map[string]string{
		"SSM_UPDATE_REPO": "off",
	}, "--help")
	if helpResult.ProcessExit != 0 ||
		!strings.Contains(helpResult.Stdout, "Usage:") ||
		helpResult.Stderr != "" {
		t.Fatalf(
			"read-only compiled --help startup failed; output=%s",
			compiledOutputIdentity(helpResult),
		)
	}
	listResult := cli.RunWithEnv(t, "sshctl", nil, map[string]string{
		"SSM_UPDATE_REPO": "off",
	}, "--offline", "--json", "list")
	if listResult.ProcessExit != 0 || listResult.Stderr != "" {
		t.Fatalf(
			"read-only compiled unrelated SSH operation failed; output=%s",
			compiledOutputIdentity(listResult),
		)
	}

	for _, executable := range []string{"ssm", "sshctl"} {
		path := cli.paths[executable]
		for _, sibling := range []string{
			filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".update.lock"),
			filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".old.state"),
			filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".old"),
			filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".mapped"),
		} {
			if _, err := os.Stat(sibling); !os.IsNotExist(err) {
				t.Fatalf(
					"ordinary read-only startup mutated sibling %s: %v",
					filepath.Base(sibling),
					err,
				)
			}
		}
	}
}

func makeCompiledDirectoryReadOnly(t *testing.T, directory string) func() {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		t.Fatalf("open compiled executable directory security: %v", err)
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		_ = windows.CloseHandle(handle)
		t.Fatalf("read compiled executable directory DACL: %v", err)
	}
	originalDACL, _, err := descriptor.DACL()
	if err != nil {
		_ = windows.CloseHandle(handle)
		t.Fatalf("extract compiled executable directory DACL: %v", err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		_ = windows.CloseHandle(handle)
		t.Fatalf("read compiled executable directory DACL control: %v", err)
	}
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil {
		_ = windows.CloseHandle(handle)
		t.Fatalf("read compiled test identity: %v", err)
	}
	readOnlyDACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			// For a directory these rights mean add file and add subdirectory.
			AccessPermissions: windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA,
			AccessMode:        windows.DENY_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
			},
		},
	}, originalDACL)
	if err != nil {
		_ = windows.CloseHandle(handle)
		t.Fatalf("build read-only compiled directory DACL: %v", err)
	}
	information := windows.SECURITY_INFORMATION(
		windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
	)
	if control&windows.SE_DACL_PROTECTED != 0 {
		information = windows.DACL_SECURITY_INFORMATION |
			windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		information,
		nil,
		nil,
		readOnlyDACL,
		nil,
	); err != nil {
		_ = windows.CloseHandle(handle)
		t.Fatalf("make compiled executable directory read-only: %v", err)
	}

	return func() {
		information := windows.SECURITY_INFORMATION(
			windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		)
		if control&windows.SE_DACL_PROTECTED != 0 {
			information = windows.DACL_SECURITY_INFORMATION |
				windows.PROTECTED_DACL_SECURITY_INFORMATION
		}
		restoreErr := windows.SetSecurityInfo(
			handle,
			windows.SE_FILE_OBJECT,
			information,
			nil,
			nil,
			originalDACL,
			nil,
		)
		closeErr := windows.CloseHandle(handle)
		runtime.KeepAlive(descriptor)
		if restoreErr != nil {
			t.Fatalf("restore compiled executable directory DACL: %v", restoreErr)
		}
		if closeErr != nil {
			t.Fatalf("close compiled executable directory security: %v", closeErr)
		}
	}
}
