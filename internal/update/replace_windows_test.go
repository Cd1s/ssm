//go:build windows

package update

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const (
	windowsReplacementChildEnv = "SSM_TEST_WINDOWS_REPLACEMENT_CHILD"
	windowsReplacementStageEnv = "SSM_TEST_WINDOWS_REPLACEMENT_STAGE"
	windowsReplacementFailEnv  = "SSM_TEST_WINDOWS_REPLACEMENT_FAIL"
	windowsCleanupChildEnv     = "SSM_TEST_WINDOWS_CLEANUP_CHILD"
)

func TestWindowsMappedExecutableReplacementSucceedsAndCleansOnNextLaunch(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.test-stage.exe")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	marker := []byte("\nSSM_WINDOWS_REPLACEMENT_MARKER\n")
	copyWindowsTestExecutable(t, testExecutable, stage, marker)
	want, err := os.ReadFile(stage) //nolint:gosec // test-owned replacement fixture
	if err != nil {
		t.Fatal(err)
	}

	command := exec.Command(target, "-test.run=^TestWindowsReplacementChildProcess$", "-test.count=1") //nolint:gosec // fixed test-owned executable and arguments
	command.Env = append(os.Environ(),
		windowsReplacementChildEnv+"=1",
		windowsReplacementStageEnv+"="+stage,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("mapped executable replacement failed: %v; output=%q", err, output)
	}
	assertWindowsFileBytes(t, target, want)

	backup := filepath.Join(directory, ".ssm.exe.old")
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("running executable rollback file was not retained until process exit: %v", err)
	}

	cleanup := exec.Command(target, "-test.run=^TestWindowsCleanupPreviousExecutableChildProcess$", "-test.count=1") //nolint:gosec // fixed test-owned executable and arguments
	cleanup.Env = append(os.Environ(), windowsCleanupChildEnv+"=1")
	if output, err := cleanup.CombinedOutput(); err != nil {
		t.Fatalf("next-launch cleanup failed: %v; output=%q", err, output)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("next launch retained old executable rollback file: %v", err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("successful replacement retained staging file: %v", err)
	}
}

func TestWindowsMappedExecutableReplacementFailureRollsBack(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.test-stage.exe")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nSSM_WINDOWS_LOCKED_STAGE\n"))
	original, err := os.ReadFile(target) //nolint:gosec // test-owned executable fixture
	if err != nil {
		t.Fatal(err)
	}

	command := exec.Command(target, "-test.run=^TestWindowsReplacementChildProcess$", "-test.count=1") //nolint:gosec // fixed test-owned executable and arguments
	command.Env = append(os.Environ(),
		windowsReplacementChildEnv+"=1",
		windowsReplacementStageEnv+"="+stage,
		windowsReplacementFailEnv+"=1",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("rollback fixture failed: %v; output=%q", err, output)
	}
	assertWindowsFileBytes(t, target, original)
	if _, err := os.Stat(filepath.Join(directory, ".ssm.exe.old")); !os.IsNotExist(err) {
		t.Fatalf("failed replacement retained rollback file: %v", err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("failed replacement retained staging file: %v", err)
	}
}

func TestWindowsReplacementChildProcess(t *testing.T) {
	if os.Getenv(windowsReplacementChildEnv) != "1" {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stage := os.Getenv(windowsReplacementStageEnv)
	if os.Getenv(windowsReplacementFailEnv) == "1" {
		stagePath, pathErr := windows.UTF16PtrFromString(stage)
		if pathErr != nil {
			t.Fatal(pathErr)
		}
		stageHandle, openErr := windows.CreateFile(
			stagePath,
			windows.GENERIC_READ,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		if openErr != nil {
			t.Fatal(openErr)
		}
		err = replaceExecutable(stage, executable)
		if closeErr := windows.CloseHandle(stageHandle); closeErr != nil {
			t.Fatal(closeErr)
		}
		if err == nil {
			t.Fatal("locked staged executable was installed")
		}
		if !strings.Contains(err.Error(), "install verified Windows executable") {
			t.Fatalf("replacement failed before exercising rollback: %v", err)
		}
		if removeErr := os.Remove(stage); removeErr != nil {
			t.Fatalf("clean failed replacement staging file: %v", removeErr)
		}
		return
	}
	err = replaceExecutable(stage, executable)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWindowsCleanupPreviousExecutableChildProcess(t *testing.T) {
	if os.Getenv(windowsCleanupChildEnv) != "1" {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanupPreviousExecutable(executable); err != nil {
		t.Fatal(err)
	}
}

func copyWindowsTestExecutable(t *testing.T, source, target string, suffix []byte) {
	t.Helper()
	data, err := os.ReadFile(source) //nolint:gosec // source is the running test executable
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, suffix...)
	if err := os.WriteFile(target, data, 0o700); err != nil { //nolint:gosec // test-owned executable fixture
		t.Fatal(err)
	}
}

func assertWindowsFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path) //nolint:gosec // test-owned executable fixture
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s bytes changed unexpectedly", path)
	}
}
