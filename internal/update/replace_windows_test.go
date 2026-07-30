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
	windowsDescriptorFailEnv   = "SSM_TEST_WINDOWS_DESCRIPTOR_FAIL"
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

func TestWindowsMappedExecutableReplacementPreservesSecurityDescriptor(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.test-stage.exe")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	setRestrictiveWindowsTestDACL(t, target)
	wantDescriptor := readWindowsTestSecurityDescriptor(t, target)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nSSM_WINDOWS_DESCRIPTOR_MARKER\n"))

	command := exec.Command(target, "-test.run=^TestWindowsReplacementChildProcess$", "-test.count=1") //nolint:gosec // fixed test-owned executable and arguments
	command.Env = append(os.Environ(),
		windowsReplacementChildEnv+"=1",
		windowsReplacementStageEnv+"="+stage,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("mapped executable replacement failed: %v; output=%q", err, output)
	}

	gotDescriptor := readWindowsTestSecurityDescriptor(t, target)
	if gotDescriptor != wantDescriptor {
		t.Fatalf("replacement security descriptor = %#v, want %#v", gotDescriptor, wantDescriptor)
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

func TestWindowsSecurityDescriptorApplyFailureRollsBack(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.test-stage.exe")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	setRestrictiveWindowsTestDACL(t, target)
	original, err := os.ReadFile(target) //nolint:gosec // test-owned executable fixture
	if err != nil {
		t.Fatal(err)
	}
	wantDescriptor := readWindowsTestSecurityDescriptor(t, target)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nSSM_WINDOWS_DESCRIPTOR_FAILURE\n"))

	command := exec.Command(target, "-test.run=^TestWindowsReplacementChildProcess$", "-test.count=1") //nolint:gosec // fixed test-owned executable and arguments
	command.Env = append(os.Environ(),
		windowsReplacementChildEnv+"=1",
		windowsReplacementStageEnv+"="+stage,
		windowsDescriptorFailEnv+"=1",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("descriptor rollback fixture failed: %v; output=%q", err, output)
	}

	assertWindowsFileBytes(t, target, original)
	gotDescriptor := readWindowsTestSecurityDescriptor(t, target)
	if gotDescriptor != wantDescriptor {
		t.Fatalf("rolled back security descriptor = %#v, want %#v", gotDescriptor, wantDescriptor)
	}
	if _, err := os.Stat(filepath.Join(directory, ".ssm.exe.old")); !os.IsNotExist(err) {
		t.Fatalf("descriptor failure retained rollback file: %v", err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("descriptor failure retained staging file: %v", err)
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
	if os.Getenv(windowsDescriptorFailEnv) == "1" {
		originalSetSecurityInfo := setWindowsSecurityInfo
		applyCalls := 0
		setWindowsSecurityInfo = func(
			handle windows.Handle,
			objectType windows.SE_OBJECT_TYPE,
			securityInformation windows.SECURITY_INFORMATION,
			owner *windows.SID,
			group *windows.SID,
			dacl *windows.ACL,
			sacl *windows.ACL,
		) error {
			applyCalls++
			if applyCalls == 2 {
				return windows.ERROR_ACCESS_DENIED
			}
			return originalSetSecurityInfo(
				handle,
				objectType,
				securityInformation,
				owner,
				group,
				dacl,
				sacl,
			)
		}
		defer func() { setWindowsSecurityInfo = originalSetSecurityInfo }()

		err = replaceExecutable(stage, executable)
		if err == nil {
			t.Fatal("descriptor application failure reported replacement success")
		}
		if applyCalls != 2 {
			t.Fatalf("security descriptor apply calls = %d, want 2", applyCalls)
		}
		if !strings.Contains(err.Error(), "apply preserved Windows security descriptor") {
			t.Fatalf("replacement did not fail at canonical descriptor application: %v", err)
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

type windowsTestSecurityDescriptor struct {
	sddl    string
	control windows.SECURITY_DESCRIPTOR_CONTROL
}

func setRestrictiveWindowsTestDACL(t *testing.T, path string) {
	t.Helper()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatalf("open current process token: %v", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("read current token user: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.ACCESS_MASK(
				windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff,
			),
			AccessMode:  windows.SET_ACCESS,
			Inheritance: windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("build restrictive DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatalf("set restrictive DACL: %v", err)
	}
}

func readWindowsTestSecurityDescriptor(t *testing.T, path string) windowsTestSecurityDescriptor {
	t.Helper()
	scope, err := beginWindowsReplacementPrivileges()
	if err != nil {
		t.Fatalf("enable test descriptor privileges: %v", err)
	}
	handle, err := openWindowsReplacementFile(
		path,
		windows.READ_CONTROL|windows.ACCESS_SYSTEM_SECURITY,
	)
	if err != nil {
		_ = scope.close()
		t.Fatalf("open test descriptor: %v", err)
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.BACKUP_SECURITY_INFORMATION,
	)
	if err != nil {
		_ = windows.CloseHandle(handle)
		_ = scope.close()
		t.Fatalf("read security descriptor: %v", err)
	}
	if err := windows.CloseHandle(handle); err != nil {
		_ = scope.close()
		t.Fatalf("close test descriptor: %v", err)
	}
	if err := scope.close(); err != nil {
		t.Fatalf("release test descriptor privileges: %v", err)
	}
	if descriptor == nil || !descriptor.IsValid() {
		t.Fatal("security descriptor is absent or invalid")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf("read security descriptor control: %v", err)
	}
	sddl := descriptor.String()
	if sddl == "" {
		t.Fatal("convert security descriptor to SDDL")
	}
	return windowsTestSecurityDescriptor{sddl: sddl, control: control}
}
