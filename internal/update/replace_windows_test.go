//go:build windows

package update

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsReplacementChildEnv = "SSM_TEST_WINDOWS_REPLACEMENT_CHILD"
	windowsReplacementStageEnv = "SSM_TEST_WINDOWS_REPLACEMENT_STAGE"
	windowsReplacementFailEnv  = "SSM_TEST_WINDOWS_REPLACEMENT_FAIL"
	windowsDescriptorFailEnv   = "SSM_TEST_WINDOWS_DESCRIPTOR_FAIL"
	windowsCleanupChildEnv     = "SSM_TEST_WINDOWS_CLEANUP_CHILD"
	windowsCleanupTargetEnv    = "SSM_TEST_WINDOWS_CLEANUP_TARGET"
	windowsExpectedFailureEnv  = "SSM_TEST_WINDOWS_EXPECTED_FAILURE"
	windowsOrdinaryUserEnv     = "SSM_TEST_WINDOWS_ORDINARY_USER"
	windowsFullTierDeniedEnv   = "SSM_TEST_WINDOWS_FULL_TIER_DENIED"
	windowsReplacementPauseEnv = "SSM_TEST_WINDOWS_REPLACEMENT_PAUSE"
	windowsReplacementReadyEnv = "SSM_TEST_WINDOWS_REPLACEMENT_READY"
	windowsReplacementGoEnv    = "SSM_TEST_WINDOWS_REPLACEMENT_GO"
	windowsSubstituteStageEnv  = "SSM_TEST_WINDOWS_SUBSTITUTE_STAGE"
	windowsRollbackFailEnv     = "SSM_TEST_WINDOWS_ROLLBACK_FAIL"
)

func TestWindowsNativeReplacementSecurity(t *testing.T) {
	t.Run("ordinary user preserves owner group DACL and inheritance", testWindowsOrdinaryUserReplacement)
	t.Run("effective token privilege detection cannot escape to the process token", testWindowsRestrictedImpersonationToken)
	t.Run("no thread token falls back to one process token and closes its handles", testWindowsNoThreadTokenProcessFallback)
	t.Run("process token fallback requires ERROR_NO_TOKEN", testWindowsProcessTokenFallbackRequiresNoThreadToken)
	t.Run("ordinary inherited descriptor capture apply and verification are semantic", testWindowsInheritedOrdinaryDescriptorPreparation)
	t.Run("ordinary descriptor differences identify the changed security component", testWindowsOrdinaryDescriptorDiagnostics)
	t.Run("optional complete descriptor denial falls back to ordinary preservation", testWindowsOptionalFullTierFallback)
	t.Run("complete descriptor is preserved when supported with ordinary fallback", testWindowsPrivilegedReplacement)
	t.Run("privileges and thread identity are restored", testWindowsReplacementPrivilegeRestoration)
	t.Run("native descriptor buffers are freed exactly once", testWindowsSecurityDescriptorOwnership)
	t.Run("mapped executable is replaced and completed rollback is cleaned", testWindowsMappedExecutableReplacementSucceedsAndCleansOnNextLaunch)
	t.Run("install failure rolls back", testWindowsMappedExecutableReplacementFailureRollsBack)
	t.Run("descriptor failure rolls back", testWindowsSecurityDescriptorApplyFailureRollsBack)
	t.Run("concurrent updaters are excluded", testWindowsConcurrentUpdaters)
	t.Run("cleanup cannot delete a live updater rollback", testWindowsConcurrentCleanup)
	t.Run("unexplained stale rollback is preserved", testWindowsUnexplainedRollbackIsPreserved)
	t.Run("stage substitution fails closed", testWindowsStageSubstitutionFailsClosed)
	t.Run("source substitution at the rename gap is blocked", testWindowsSourceSubstitutionAtRenameGap)
	t.Run("canonical substitution at the rename gap cannot be installed", testWindowsCanonicalSubstitutionAtRenameGap)
	t.Run("rollback replaces an unexpected canonical substitute", testWindowsRollbackReplacesCanonicalSubstitute)
	t.Run("rollback rejects a late hard link to its image", testWindowsRollbackRejectsLateHardLink)
	t.Run("late hard links cannot compromise the canonical target", testWindowsLateHardLinksCannotCompromiseTarget)
	t.Run("hard-linked targets and stages fail closed", testWindowsHardLinksFailClosed)
	t.Run("rollback failure preserves recovery evidence", testWindowsRollbackFailurePreservesEvidence)
	t.Run("forged rollback control state is rejected", testWindowsForgedRollbackControlStateIsRejected)
	t.Run("writable inherited rollback state is rejected before parsing", testWindowsWritableInheritedRollbackStateIsRejected)
	t.Run("wrong rollback state owner is rejected", testWindowsWrongOwnerRollbackStateIsRejected)
	t.Run("inherited update lock control state is rejected", testWindowsInheritedUpdateLockIsRejected)
}

func testWindowsMappedExecutableReplacementSucceedsAndCleansOnNextLaunch(t *testing.T) {
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
	assertWindowsControlFileSecurity(t, windowsReplacementLock(target))
	assertWindowsControlFileSecurity(t, windowsReplacementRecord(target))

	cleanup := exec.Command(target, "-test.run=^TestWindowsCleanupPreviousExecutableChildProcess$", "-test.count=1") //nolint:gosec // fixed test-owned executable and arguments
	cleanup.Env = append(os.Environ(), windowsCleanupChildEnv+"=1")
	if output, err := cleanup.CombinedOutput(); err != nil {
		t.Fatalf("next-launch cleanup failed: %v; output=%q", err, output)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("next launch retained old executable rollback file: %v", err)
	}
	if _, err := os.Stat(windowsReplacementRecord(target)); !os.IsNotExist(err) {
		t.Fatalf("next launch retained completed rollback ownership record: %v", err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("successful replacement retained staging file: %v", err)
	}
}

func testWindowsPrivilegedReplacement(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.test-stage.exe")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	setRestrictiveWindowsTestDACL(t, target)
	fullConfigured, fullUnavailableReason := trySetWindowsTestSACL(t, target)
	var wantFullDescriptor windowsTestSecurityDescriptor
	if fullConfigured {
		var fullReadable bool
		wantFullDescriptor, fullReadable, fullUnavailableReason =
			tryReadWindowsTestCompleteSecurityDescriptor(t, target)
		fullConfigured = fullReadable
	}
	wantOrdinaryDescriptor := readWindowsTestSecurityDescriptor(t, target)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nSSM_WINDOWS_DESCRIPTOR_MARKER\n"))

	command := exec.Command(target, "-test.run=^TestWindowsReplacementChildProcess$", "-test.count=1") //nolint:gosec // fixed test-owned executable and arguments
	command.Env = append(os.Environ(),
		windowsReplacementChildEnv+"=1",
		windowsReplacementStageEnv+"="+stage,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("mapped executable replacement failed: %v; output=%q", err, output)
	}

	gotOrdinaryDescriptor := readWindowsTestSecurityDescriptor(t, target)
	if gotOrdinaryDescriptor != wantOrdinaryDescriptor {
		t.Fatalf(
			"replacement ordinary security descriptor = %#v, want %#v",
			gotOrdinaryDescriptor,
			wantOrdinaryDescriptor,
		)
	}
	t.Run("complete descriptor", func(t *testing.T) {
		if !fullConfigured {
			t.Skipf("host cannot exercise complete descriptor tier: %s", fullUnavailableReason)
		}
		gotFullDescriptor, available, reason :=
			tryReadWindowsTestCompleteSecurityDescriptor(t, target)
		if !available {
			t.Fatalf("complete descriptor capability became unavailable: %s", reason)
		}
		if gotFullDescriptor != wantFullDescriptor {
			t.Fatalf(
				"replacement complete security descriptor = %#v, want %#v",
				gotFullDescriptor,
				wantFullDescriptor,
			)
		}
	})
}

func testWindowsMappedExecutableReplacementFailureRollsBack(t *testing.T) {
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
	if _, err := os.Stat(windowsReplacementRecord(target)); !os.IsNotExist(err) {
		t.Fatalf("failed replacement retained rollback ownership record: %v", err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("failed replacement retained staging file: %v", err)
	}
}

func testWindowsSecurityDescriptorApplyFailureRollsBack(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.test-stage.exe")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
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
		windowsOrdinaryUserEnv+"=1",
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
	if _, err := os.Stat(windowsReplacementRecord(target)); !os.IsNotExist(err) {
		t.Fatalf("descriptor failure retained rollback ownership record: %v", err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("descriptor failure retained staging file: %v", err)
	}
}

func testWindowsOrdinaryUserReplacement(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.ordinary-stage.exe")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	setRestrictiveWindowsTestDACL(t, target)
	wantDescriptor := readWindowsTestSecurityDescriptor(t, target)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nSSM_WINDOWS_ORDINARY_MARKER\n"))

	command := windowsReplacementTestCommand(target, stage)
	command.Env = append(command.Env, windowsOrdinaryUserEnv+"=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ordinary non-privileged replacement failed: %v; output=%q", err, output)
	}

	gotDescriptor := readWindowsTestSecurityDescriptor(t, target)
	if gotDescriptor != wantDescriptor {
		t.Fatalf("ordinary replacement security descriptor = %#v, want %#v", gotDescriptor, wantDescriptor)
	}
}

func testWindowsRestrictedImpersonationToken(t *testing.T) {
	restore, err := impersonateWindowsTestTokenWithoutPrivileges()
	if err != nil {
		t.Fatalf("create ordinary non-privileged token: %v", err)
	}
	defer func() {
		if restore != nil {
			if err := restore(); err != nil {
				t.Fatalf("restore ordinary non-privileged token: %v", err)
			}
		}
	}()

	token := windows.GetCurrentThreadEffectiveToken()
	tokenType, err := windowsTestTokenUint32Information(token, windows.TokenType)
	if err != nil {
		t.Fatalf("read restricted token type: %v", err)
	}
	if tokenType != windows.TokenImpersonation {
		t.Fatalf("restricted token type = %d, want TokenImpersonation", tokenType)
	}
	level, err := windowsTestTokenUint32Information(token, windows.TokenImpersonationLevel)
	if err != nil {
		t.Fatalf("read restricted token impersonation level: %v", err)
	}
	if level != windows.SecurityImpersonation {
		t.Fatalf("restricted token impersonation level = %d, want SecurityImpersonation", level)
	}
	for _, privilege := range []string{
		"SeBackupPrivilege",
		"SeRestorePrivilege",
		"SeSecurityPrivilege",
	} {
		present, err := windowsTestTokenHasPrivilege(token, privilege)
		if err != nil {
			t.Fatalf("inspect restricted token privilege %s: %v", privilege, err)
		}
		if present {
			t.Fatalf("restricted token unexpectedly retains %s", privilege)
		}
	}
	before := windowsTestTokenDescription(t, token)
	var openAsSelfValues []bool
	var threadOpenErr error
	processOpenCalls := 0
	scope, available, err := beginWindowsReplacementPrivilegesWithTokenOpen(
		func(
			thread windows.Handle,
			access uint32,
			openAsSelf bool,
			token *windows.Token,
		) error {
			openAsSelfValues = append(openAsSelfValues, openAsSelf)
			threadOpenErr = windows.OpenThreadToken(thread, access, openAsSelf, token)
			return threadOpenErr
		},
		func(process windows.Handle, access uint32, token *windows.Token) error {
			processOpenCalls++
			return windows.OpenProcessToken(process, access, token)
		},
	)
	if err != nil {
		t.Fatalf("probe restricted optional privileges: %v", err)
	}
	if len(openAsSelfValues) != 1 {
		t.Fatalf("OpenThreadToken calls = %d, want 1", len(openAsSelfValues))
	}
	if openAsSelfValues[0] {
		t.Fatal("OpenThreadToken openAsSelf = true, want false for the effective thread token")
	}
	if threadOpenErr != nil {
		t.Fatalf("open existing restricted thread token: %v", threadOpenErr)
	}
	if processOpenCalls != 0 {
		t.Fatalf("OpenProcessToken calls with an existing thread token = %d, want 0", processOpenCalls)
	}
	if scope != nil {
		if closeErr := scope.close(); closeErr != nil {
			t.Fatalf("close unexpected restricted privilege scope: %v", closeErr)
		}
	}
	if available {
		t.Fatal("restricted token unexpectedly supports complete descriptor privileges")
	}
	after := windowsTestTokenDescription(t, windows.GetCurrentThreadEffectiveToken())
	if after != before {
		t.Fatalf(
			"optional privilege probe escaped or changed the effective restricted identity: before=%q after=%q",
			before,
			after,
		)
	}
	if err := restore(); err != nil {
		t.Fatalf("restore ordinary non-privileged token: %v", err)
	}
	restore = nil
}

func testWindowsNoThreadTokenProcessFallback(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.RevertToSelf(); err != nil {
		t.Fatalf("remove ambient thread token: %v", err)
	}
	assertWindowsTestThreadHasNoToken(t)

	threadOpenCalls := 0
	var openAsSelfValues []bool
	processOpenCalls := 0
	var processToken windows.Token
	var closedTokens []windows.Token
	scope, _, err := beginWindowsReplacementPrivilegesWithTokenOpenAndClose(
		func(
			_ windows.Handle,
			_ uint32,
			openAsSelf bool,
			_ *windows.Token,
		) error {
			threadOpenCalls++
			openAsSelfValues = append(openAsSelfValues, openAsSelf)
			return windows.ERROR_NO_TOKEN
		},
		func(process windows.Handle, access uint32, token *windows.Token) error {
			processOpenCalls++
			err := windows.OpenProcessToken(process, access, token)
			if err == nil {
				processToken = *token
			}
			return err
		},
		func(token windows.Token) error {
			closedTokens = append(closedTokens, token)
			return token.Close()
		},
	)
	if err != nil {
		t.Fatalf("begin optional replacement privileges without a thread token: %v", err)
	}
	if scope != nil {
		if err := scope.close(); err != nil {
			t.Fatalf("close optional replacement privileges without a prior thread token: %v", err)
		}
	}
	if threadOpenCalls != 1 {
		t.Fatalf("OpenThreadToken calls = %d, want 1", threadOpenCalls)
	}
	if len(openAsSelfValues) != 1 {
		t.Fatalf("OpenThreadToken openAsSelf observations = %d, want 1", len(openAsSelfValues))
	}
	if openAsSelfValues[0] {
		t.Fatal("OpenThreadToken openAsSelf = true, want false for the effective thread token")
	}
	if processOpenCalls != 1 {
		t.Fatalf("OpenProcessToken calls after ERROR_NO_TOKEN = %d, want 1", processOpenCalls)
	}
	if processToken == 0 {
		t.Fatal("OpenProcessToken returned a zero token")
	}
	if len(closedTokens) != 2 {
		t.Fatalf("closed token handles = %d, want process and duplicated tokens", len(closedTokens))
	}
	if !slices.Contains(closedTokens, processToken) {
		t.Fatal("opened process token was not closed")
	}
	if closedTokens[0] == closedTokens[1] {
		t.Fatalf("closed token handle %v twice, want distinct process and duplicated tokens", closedTokens[0])
	}
	for _, token := range closedTokens {
		var size uint32
		err := windows.GetTokenInformation(token, windows.TokenType, nil, 0, &size)
		if !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
			t.Fatalf("GetTokenInformation on closed token %v error = %v, want ERROR_INVALID_HANDLE", token, err)
		}
	}
	assertWindowsTestThreadHasNoToken(t)
}

func testWindowsProcessTokenFallbackRequiresNoThreadToken(t *testing.T) {
	processOpenCalls := 0
	scope, available, err := beginWindowsReplacementPrivilegesWithTokenOpen(
		func(
			windows.Handle,
			uint32,
			bool,
			*windows.Token,
		) error {
			return windows.ERROR_ACCESS_DENIED
		},
		func(windows.Handle, uint32, *windows.Token) error {
			processOpenCalls++
			return windows.ERROR_GEN_FAILURE
		},
	)
	if err != nil {
		t.Fatalf("probe denied thread token: %v", err)
	}
	if scope != nil {
		if closeErr := scope.close(); closeErr != nil {
			t.Fatalf("close unexpected denied privilege scope: %v", closeErr)
		}
	}
	if available {
		t.Fatal("denied thread token unexpectedly supports complete descriptor privileges")
	}
	if processOpenCalls != 0 {
		t.Fatalf("OpenProcessToken calls after ERROR_ACCESS_DENIED = %d, want 0", processOpenCalls)
	}
}

func testWindowsInheritedOrdinaryDescriptorPreparation(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "current.exe")
	stage := filepath.Join(directory, ".current.stage.exe")
	if err := os.WriteFile(target, []byte("current"), 0o700); err != nil { //nolint:gosec // test-owned descriptor fixture
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, []byte("stage"), 0o700); err != nil { //nolint:gosec // test-owned descriptor fixture
		t.Fatal(err)
	}
	want := readWindowsTestOrdinarySecurityContract(t, target)
	if want.protected {
		t.Skip("test temp directory produced a protected file DACL instead of the standard inherited fixture")
	}
	if !want.hasInheritedACE {
		t.Skip("test temp directory did not produce inherited file ACEs")
	}

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

	state, err := prepareWindowsReplacementOrdinarySecurity(stage, target)
	if err != nil {
		t.Fatalf("capture, apply, and verify standard inherited descriptor: %v", err)
	}
	if applyCalls != 1 {
		t.Fatalf("ordinary inherited descriptor apply calls = %d, want 1", applyCalls)
	}
	if err := state.close(); err != nil {
		t.Fatalf("close ordinary inherited descriptor state: %v", err)
	}

	got := readWindowsTestOrdinarySecurityContract(t, stage)
	assertWindowsTestOrdinarySecurityContract(t, got, want)
}

func testWindowsOrdinaryDescriptorDiagnostics(t *testing.T) {
	const baseline = "O:SYG:BAD:AI(A;ID;FR;;;BU)"
	for _, test := range []struct {
		name       string
		want       string
		got        string
		difference string
	}{
		{
			name:       "owner",
			want:       baseline,
			got:        "O:BAG:BAD:AI(A;ID;FR;;;BU)",
			difference: "owner SID changed",
		},
		{
			name:       "primary group",
			want:       baseline,
			got:        "O:SYG:SYD:AI(A;ID;FR;;;BU)",
			difference: "primary group SID changed",
		},
		{
			name:       "access broadening",
			want:       baseline,
			got:        "O:SYG:BAD:AI(A;ID;FA;;;BU)",
			difference: "DACL ACE 0 changed",
		},
		{
			name:       "inherited ACE state",
			want:       baseline,
			got:        "O:SYG:BAD:AI(A;;FR;;;BU)",
			difference: "DACL ACE 0 changed",
		},
		{
			name:       "ACE ordering",
			want:       "O:SYG:BAD:(D;;FW;;;BU)(A;;FR;;;BU)",
			got:        "O:SYG:BAD:(A;;FR;;;BU)(D;;FW;;;BU)",
			difference: "DACL ACE 0 changed",
		},
		{
			name:       "protection",
			want:       baseline,
			got:        "O:SYG:BAD:PAI(A;ID;FR;;;BU)",
			difference: "DACL protection changed",
		},
		{
			name:       "auto inheritance regression",
			want:       baseline,
			got:        "O:SYG:BAD:(A;ID;FR;;;BU)",
			difference: "DACL auto-inherited state changed",
		},
		{
			name:       "null versus empty DACL",
			want:       "O:SYG:BAD:",
			got:        "O:SYG:BAD:NO_ACCESS_CONTROL",
			difference: "DACL state changed",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			want, err := windows.SecurityDescriptorFromString(test.want)
			if err != nil {
				t.Fatalf("build wanted descriptor: %v", err)
			}
			got, err := windows.SecurityDescriptorFromString(test.got)
			if err != nil {
				t.Fatalf("build changed descriptor: %v", err)
			}
			err = compareWindowsSecurityDescriptors(want, got, false)
			if err == nil || !strings.Contains(err.Error(), test.difference) {
				t.Fatalf(
					"ordinary descriptor difference = %v, want diagnostic containing %q",
					err,
					test.difference,
				)
			}
		})
	}

	t.Run("Windows auto-inheritance normalization", func(t *testing.T) {
		want, err := windows.SecurityDescriptorFromString("O:SYG:BAD:(A;ID;FR;;;BU)")
		if err != nil {
			t.Fatal(err)
		}
		got, err := windows.SecurityDescriptorFromString(baseline)
		if err != nil {
			t.Fatal(err)
		}
		if err := compareWindowsSecurityDescriptors(want, got, false); err != nil {
			t.Fatalf("Windows-normalized auto-inherited metadata changed the security contract: %v", err)
		}
	})
}

func testWindowsOptionalFullTierFallback(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.optional-full-tier-stage.exe")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	setRestrictiveWindowsTestDACL(t, target)
	wantDescriptor := readWindowsTestSecurityDescriptor(t, target)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nSSM_WINDOWS_OPTIONAL_FULL_TIER\n"))
	want, err := os.ReadFile(stage) //nolint:gosec // test-owned replacement fixture
	if err != nil {
		t.Fatal(err)
	}

	command := windowsReplacementTestCommand(target, stage)
	command.Env = append(command.Env, windowsFullTierDeniedEnv+"=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("optional full-tier fallback failed: %v; output=%q", err, output)
	}
	assertWindowsFileBytes(t, target, want)
	gotDescriptor := readWindowsTestSecurityDescriptor(t, target)
	if gotDescriptor != wantDescriptor {
		t.Fatalf("ordinary fallback security descriptor = %#v, want %#v", gotDescriptor, wantDescriptor)
	}
}

func testWindowsReplacementPrivilegeRestoration(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	beforeThread, beforeEffective := windowsTestTokenState(t)
	var threadOpenErr error
	processOpenCalls := 0
	scope, _, err := beginWindowsReplacementPrivilegesWithTokenOpen(
		func(
			thread windows.Handle,
			access uint32,
			openAsSelf bool,
			token *windows.Token,
		) error {
			threadOpenErr = windows.OpenThreadToken(thread, access, openAsSelf, token)
			return threadOpenErr
		},
		func(process windows.Handle, access uint32, token *windows.Token) error {
			processOpenCalls++
			return windows.OpenProcessToken(process, access, token)
		},
	)
	if err != nil {
		t.Fatalf("begin optional replacement privileges: %v", err)
	}
	if scope != nil {
		if err := scope.close(); err != nil {
			t.Fatalf("close optional replacement privileges: %v", err)
		}
	}
	if errors.Is(threadOpenErr, windows.ERROR_NO_TOKEN) {
		if processOpenCalls != 1 {
			t.Fatalf("OpenProcessToken calls after ERROR_NO_TOKEN = %d, want 1", processOpenCalls)
		}
	} else if processOpenCalls != 0 {
		t.Fatalf("OpenProcessToken calls after OpenThreadToken error %v = %d, want 0", threadOpenErr, processOpenCalls)
	}
	afterThread, afterEffective := windowsTestTokenState(t)
	if afterThread != beforeThread || afterEffective != beforeEffective {
		t.Fatalf(
			"replacement privilege scope changed token state: thread_before=%q thread_after=%q effective_before=%q effective_after=%q",
			beforeThread,
			afterThread,
			beforeEffective,
			afterEffective,
		)
	}
}

func testWindowsSecurityDescriptorOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "descriptor-owner.exe")
	if err := os.WriteFile(path, []byte("test-owned descriptor"), 0o600); err != nil { //nolint:gosec // test-owned fixture
		t.Fatal(err)
	}
	handle, err := openWindowsReplacementFile(path, windows.READ_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)

	originalLocalFree := localFreeWindowsSecurityDescriptor
	freeCalls := 0
	localFreeWindowsSecurityDescriptor = func(memory windows.Handle) (windows.Handle, error) {
		freeCalls++
		return originalLocalFree(memory)
	}
	defer func() { localFreeWindowsSecurityDescriptor = originalLocalFree }()

	descriptor, err := captureWindowsSecurityDescriptor(handle, windowsOrdinarySecurityInformation)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsSecurityDescriptor(descriptor.descriptor); err != nil {
		t.Fatal(err)
	}
	if err := descriptor.close(); err != nil {
		t.Fatal(err)
	}
	if err := descriptor.close(); err != nil {
		t.Fatalf("second descriptor close was not idempotent: %v", err)
	}
	if freeCalls != 1 {
		t.Fatalf("native descriptor LocalFree calls = %d, want exactly 1", freeCalls)
	}
}

func testWindowsConcurrentUpdaters(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	firstStage := filepath.Join(directory, ".ssm.first-stage.exe")
	secondStage := filepath.Join(directory, ".ssm.second-stage.exe")
	ready := filepath.Join(directory, "first.ready")
	proceed := filepath.Join(directory, "first.proceed")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	copyWindowsTestExecutable(t, testExecutable, firstStage, []byte("\nSSM_WINDOWS_FIRST_UPDATER\n"))
	copyWindowsTestExecutable(t, testExecutable, secondStage, []byte("\nSSM_WINDOWS_SECOND_UPDATER\n"))
	want, err := os.ReadFile(firstStage) //nolint:gosec // test-owned replacement fixture
	if err != nil {
		t.Fatal(err)
	}

	first := windowsReplacementTestCommand(target, firstStage)
	first.Env = append(first.Env,
		windowsReplacementPauseEnv+"="+windowsReplacementPhaseAfterLock,
		windowsReplacementReadyEnv+"="+ready,
		windowsReplacementGoEnv+"="+proceed,
	)
	var firstOutput bytes.Buffer
	first.Stdout = &firstOutput
	first.Stderr = &firstOutput
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	waitForWindowsTestPath(t, ready)

	second := windowsReplacementTestCommand(target, secondStage)
	second.Env = append(second.Env, windowsExpectedFailureEnv+"=another Windows executable update is active")
	if output, err := second.CombinedOutput(); err != nil {
		t.Fatalf("concurrent updater fixture failed: %v; output=%q", err, output)
	}
	if err := os.WriteFile(proceed, []byte("continue"), 0o600); err != nil { //nolint:gosec // test-owned synchronization fixture
		t.Fatal(err)
	}
	if err := first.Wait(); err != nil {
		t.Fatalf("first updater failed: %v; output=%q", err, firstOutput.String())
	}
	assertWindowsFileBytes(t, target, want)
	if _, err := os.Stat(secondStage); err != nil {
		t.Fatalf("excluded updater lost its verified stage: %v", err)
	}
}

func testWindowsConcurrentCleanup(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.live-stage.exe")
	ready := filepath.Join(directory, "backup.ready")
	proceed := filepath.Join(directory, "backup.proceed")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nSSM_WINDOWS_LIVE_ROLLBACK\n"))

	updater := windowsReplacementTestCommand(target, stage)
	updater.Env = append(updater.Env,
		windowsReplacementPauseEnv+"="+windowsReplacementPhaseAfterBackup,
		windowsReplacementReadyEnv+"="+ready,
		windowsReplacementGoEnv+"="+proceed,
	)
	var updaterOutput bytes.Buffer
	updater.Stdout = &updaterOutput
	updater.Stderr = &updaterOutput
	if err := updater.Start(); err != nil {
		t.Fatal(err)
	}
	waitForWindowsTestPath(t, ready)

	backup := windowsReplacementBackup(target)
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("active updater has no rollback image: %v", err)
	}
	cleanup := exec.Command(testExecutable, "-test.run=^TestWindowsCleanupPreviousExecutableChildProcess$", "-test.count=1") //nolint:gosec // fixed test binary and arguments
	cleanup.Env = append(os.Environ(),
		windowsCleanupChildEnv+"=1",
		windowsCleanupTargetEnv+"="+target,
		windowsExpectedFailureEnv+"=another Windows executable update is active",
	)
	if output, err := cleanup.CombinedOutput(); err != nil {
		t.Fatalf("concurrent cleanup fixture failed: %v; output=%q", err, output)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("concurrent cleanup deleted the live rollback image: %v", err)
	}

	if err := os.WriteFile(proceed, []byte("continue"), 0o600); err != nil { //nolint:gosec // test-owned synchronization fixture
		t.Fatal(err)
	}
	if err := updater.Wait(); err != nil {
		t.Fatalf("updater failed after cleanup exclusion: %v; output=%q", err, updaterOutput.String())
	}
}

func testWindowsUnexplainedRollbackIsPreserved(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	backup := windowsReplacementBackup(target)
	stage := filepath.Join(directory, ".ssm.new-stage.exe")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	copyWindowsTestExecutable(t, testExecutable, backup, []byte("\nUNEXPLAINED_ROLLBACK\n"))
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nBLOCKED_NEW_UPDATE\n"))
	original, err := os.ReadFile(target) //nolint:gosec // test-owned executable fixture
	if err != nil {
		t.Fatal(err)
	}

	cleanup := exec.Command(testExecutable, "-test.run=^TestWindowsCleanupPreviousExecutableChildProcess$", "-test.count=1") //nolint:gosec // fixed test binary and arguments
	cleanup.Env = append(os.Environ(),
		windowsCleanupChildEnv+"=1",
		windowsCleanupTargetEnv+"="+target,
		windowsExpectedFailureEnv+"=rollback evidence has no ownership record",
	)
	if output, err := cleanup.CombinedOutput(); err != nil {
		t.Fatalf("stale rollback fixture failed: %v; output=%q", err, output)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("unexplained rollback evidence was deleted: %v", err)
	}

	update := windowsReplacementTestCommand(target, stage)
	update.Env = append(update.Env, windowsExpectedFailureEnv+"=rollback evidence has no ownership record")
	if output, err := update.CombinedOutput(); err != nil {
		t.Fatalf("new-update stale rollback fixture failed: %v; output=%q", err, output)
	}
	assertWindowsFileBytes(t, target, original)
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("new update deleted unexplained rollback evidence: %v", err)
	}
}

func testWindowsStageSubstitutionFailsClosed(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{
		windowsReplacementPhaseBeforeTargetMove,
		windowsReplacementPhaseBeforeStageMove,
	} {
		t.Run(phase, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "ssm.exe")
			stage := filepath.Join(directory, ".ssm.substituted-stage.exe")
			copyWindowsTestExecutable(t, testExecutable, target, nil)
			copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nINSPECTED_STAGE\n"))
			original, err := os.ReadFile(target) //nolint:gosec // test-owned executable fixture
			if err != nil {
				t.Fatal(err)
			}

			command := windowsReplacementTestCommand(target, stage)
			command.Env = append(command.Env,
				windowsSubstituteStageEnv+"="+phase,
				windowsExpectedFailureEnv+"=rename inspected stage",
			)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("stage substitution fixture failed: %v; output=%q", err, output)
			}
			assertWindowsFileBytes(t, target, original)
			if _, err := os.Stat(windowsReplacementBackup(target)); !os.IsNotExist(err) {
				t.Fatalf("stage substitution created rollback state: %v", err)
			}
			if _, err := os.Stat(windowsReplacementRecord(target)); !os.IsNotExist(err) {
				t.Fatalf("stage substitution retained rollback ownership state: %v", err)
			}
		})
	}
}

func testWindowsSourceSubstitutionAtRenameGap(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		phase  string
		source func(target, stage string) string
	}{
		{
			name:  "target",
			phase: windowsReplacementPhaseTargetRenameGap,
			source: func(target, _ string) string {
				return target
			},
		},
		{
			name:  "stage",
			phase: windowsReplacementPhaseStageRenameGap,
			source: func(_, stage string) string {
				return stage
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "ssm.exe")
			stage := filepath.Join(directory, ".ssm.rename-gap-stage.exe")
			ready := filepath.Join(directory, test.name+".ready")
			proceed := filepath.Join(directory, test.name+".proceed")
			copyWindowsTestExecutable(t, testExecutable, target, nil)
			copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nVERIFIED_RENAME_GAP_STAGE\n"))
			want, err := os.ReadFile(stage) //nolint:gosec // test-owned verified stage
			if err != nil {
				t.Fatal(err)
			}

			updater := windowsReplacementTestCommand(target, stage)
			updater.Env = append(updater.Env,
				windowsReplacementPauseEnv+"="+test.phase,
				windowsReplacementReadyEnv+"="+ready,
				windowsReplacementGoEnv+"="+proceed,
			)
			var updaterOutput bytes.Buffer
			updater.Stdout = &updaterOutput
			updater.Stderr = &updaterOutput
			if err := updater.Start(); err != nil {
				t.Fatal(err)
			}
			waitForWindowsTestPath(t, ready)

			source := test.source(target, stage)
			inspected := source + ".inspected"
			substitutionErr := os.Rename(source, inspected)
			if substitutionErr == nil {
				copyWindowsTestExecutable(t, testExecutable, source, []byte("\nATTACKER_SUBSTITUTE\n"))
			}
			if err := os.WriteFile(proceed, []byte("continue"), 0o600); err != nil { //nolint:gosec // test-owned synchronization fixture
				t.Fatal(err)
			}
			waitErr := updater.Wait()
			if substitutionErr == nil {
				t.Fatalf(
					"%s substitution succeeded at the validation/rename gap; updater_error=%v output=%q",
					test.name,
					waitErr,
					updaterOutput.String(),
				)
			}
			if waitErr != nil {
				t.Fatalf("updater failed after blocked %s substitution: %v; output=%q", test.name, waitErr, updaterOutput.String())
			}
			assertWindowsFileBytes(t, target, want)
		})
	}
}

func testWindowsCanonicalSubstitutionAtRenameGap(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.canonical-gap-stage.exe")
	ready := filepath.Join(directory, "canonical.ready")
	proceed := filepath.Join(directory, "canonical.proceed")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nVERIFIED_CANONICAL_GAP_STAGE\n"))
	want, err := os.ReadFile(stage) //nolint:gosec // test-owned verified stage
	if err != nil {
		t.Fatal(err)
	}

	updater := windowsReplacementTestCommand(target, stage)
	updater.Env = append(updater.Env,
		windowsReplacementPauseEnv+"="+windowsReplacementPhaseStageRenameGap,
		windowsReplacementReadyEnv+"="+ready,
		windowsReplacementGoEnv+"="+proceed,
	)
	var updaterOutput bytes.Buffer
	updater.Stdout = &updaterOutput
	updater.Stderr = &updaterOutput
	if err := updater.Start(); err != nil {
		t.Fatal(err)
	}
	waitForWindowsTestPath(t, ready)

	copyWindowsTestExecutable(t, testExecutable, target, []byte("\nATTACKER_CANONICAL_SUBSTITUTE\n"))
	targetPointer, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	attackerHandle, err := windows.CreateFile(
		targetPointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proceed, []byte("continue"), 0o600); err != nil { //nolint:gosec // test-owned synchronization fixture
		_ = windows.CloseHandle(attackerHandle)
		t.Fatal(err)
	}
	waitErr := updater.Wait()
	closeErr := windows.CloseHandle(attackerHandle)
	if waitErr != nil {
		t.Fatalf("updater failed to replace a canonical substitute: %v; output=%q", waitErr, updaterOutput.String())
	}
	if closeErr != nil {
		t.Fatalf("close attacker substitute handle: %v", closeErr)
	}
	assertWindowsFileBytes(t, target, want)
}

func testWindowsRollbackReplacesCanonicalSubstitute(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.rollback-substitute-stage.exe")
	ready := filepath.Join(directory, "rollback.ready")
	proceed := filepath.Join(directory, "rollback.proceed")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	original, err := os.ReadFile(target) //nolint:gosec // test-owned mapped executable
	if err != nil {
		t.Fatal(err)
	}
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nROLLBACK_SUBSTITUTE_STAGE\n"))

	updater := windowsReplacementTestCommand(target, stage)
	updater.Env = append(updater.Env,
		windowsReplacementFailEnv+"=1",
		windowsReplacementPauseEnv+"="+windowsReplacementPhaseStageRenameGap,
		windowsReplacementReadyEnv+"="+ready,
		windowsReplacementGoEnv+"="+proceed,
	)
	var updaterOutput bytes.Buffer
	updater.Stdout = &updaterOutput
	updater.Stderr = &updaterOutput
	if err := updater.Start(); err != nil {
		t.Fatal(err)
	}
	waitForWindowsTestPath(t, ready)

	copyWindowsTestExecutable(t, testExecutable, target, []byte("\nATTACKER_ROLLBACK_SUBSTITUTE\n"))
	targetPointer, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	attackerHandle, err := windows.CreateFile(
		targetPointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proceed, []byte("continue"), 0o600); err != nil { //nolint:gosec // test-owned synchronization fixture
		_ = windows.CloseHandle(attackerHandle)
		t.Fatal(err)
	}
	waitErr := updater.Wait()
	closeErr := windows.CloseHandle(attackerHandle)
	if waitErr != nil {
		t.Fatalf("rollback substitute fixture failed: %v; output=%q", waitErr, updaterOutput.String())
	}
	if closeErr != nil {
		t.Fatalf("close rollback substitute handle: %v", closeErr)
	}
	assertWindowsFileBytes(t, target, original)
	if _, err := os.Stat(windowsReplacementBackup(target)); !os.IsNotExist(err) {
		t.Fatalf("successful object-bound rollback retained rollback image: %v", err)
	}
	if _, err := os.Stat(windowsReplacementRecord(target)); !os.IsNotExist(err) {
		t.Fatalf("successful object-bound rollback retained control state: %v", err)
	}
}

func testWindowsRollbackRejectsLateHardLink(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.rollback-hard-link-stage.exe")
	ready := filepath.Join(directory, "rollback-hard-link.ready")
	proceed := filepath.Join(directory, "rollback-hard-link.proceed")
	alias := filepath.Join(directory, "rollback-hard-link-alias.exe")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nROLLBACK_HARD_LINK_STAGE\n"))
	original, err := os.ReadFile(target) //nolint:gosec // test-owned mapped executable
	if err != nil {
		t.Fatal(err)
	}

	updater := windowsReplacementTestCommand(target, stage)
	updater.Env = append(updater.Env,
		windowsReplacementFailEnv+"=1",
		windowsReplacementPauseEnv+"="+windowsReplacementPhaseAfterBackup,
		windowsReplacementReadyEnv+"="+ready,
		windowsReplacementGoEnv+"="+proceed,
		windowsExpectedFailureEnv+"=rollback failed: Windows rollback image has 2 hard links",
	)
	var updaterOutput bytes.Buffer
	updater.Stdout = &updaterOutput
	updater.Stderr = &updaterOutput
	if err := updater.Start(); err != nil {
		t.Fatal(err)
	}
	waitForWindowsTestPath(t, ready)

	backup := windowsReplacementBackup(target)
	if err := os.Link(backup, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proceed, []byte("continue"), 0o600); err != nil { //nolint:gosec // test-owned synchronization fixture
		t.Fatal(err)
	}
	if waitErr := updater.Wait(); waitErr != nil {
		t.Fatalf("late rollback hard-link fixture failed: %v; output=%q", waitErr, updaterOutput.String())
	}

	assertWindowsFileBytes(t, backup, original)
	assertWindowsFileBytes(t, alias, original)
	if _, err := os.Stat(windowsReplacementRecord(target)); err != nil {
		t.Fatalf("late rollback hard link did not retain ownership state: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("late rollback hard link left an unexpected canonical target: %v", err)
	}
}

func testWindowsLateHardLinksCannotCompromiseTarget(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		phase  string
		source func(target, stage string) string
	}{
		{
			name:  "target",
			phase: windowsReplacementPhaseTargetRenameGap,
			source: func(target, _ string) string {
				return target
			},
		},
		{
			name:  "stage",
			phase: windowsReplacementPhaseStageRenameGap,
			source: func(_, stage string) string {
				return stage
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "ssm.exe")
			stage := filepath.Join(directory, ".ssm.late-link-stage.exe")
			ready := filepath.Join(directory, test.name+".link-ready")
			proceed := filepath.Join(directory, test.name+".link-proceed")
			alias := filepath.Join(directory, test.name+".late-link.exe")
			copyWindowsTestExecutable(t, testExecutable, target, nil)
			original, err := os.ReadFile(target) //nolint:gosec // test-owned mapped executable
			if err != nil {
				t.Fatal(err)
			}
			copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nLATE_LINK_STAGE\n"))
			verified, err := os.ReadFile(stage) //nolint:gosec // test-owned verified stage
			if err != nil {
				t.Fatal(err)
			}

			updater := windowsReplacementTestCommand(target, stage)
			updater.Env = append(updater.Env,
				windowsReplacementPauseEnv+"="+test.phase,
				windowsReplacementReadyEnv+"="+ready,
				windowsReplacementGoEnv+"="+proceed,
			)
			var updaterOutput bytes.Buffer
			updater.Stdout = &updaterOutput
			updater.Stderr = &updaterOutput
			if err := updater.Start(); err != nil {
				t.Fatal(err)
			}
			waitForWindowsTestPath(t, ready)
			linkErr := os.Link(test.source(target, stage), alias)
			if err := os.WriteFile(proceed, []byte("continue"), 0o600); err != nil { //nolint:gosec // test-owned synchronization fixture
				t.Fatal(err)
			}
			waitErr := updater.Wait()
			if linkErr != nil {
				if waitErr != nil {
					t.Fatalf("updater failed after blocked late hard link: %v; output=%q", waitErr, updaterOutput.String())
				}
				assertWindowsFileBytes(t, target, verified)
				return
			}
			if waitErr == nil || !strings.Contains(updaterOutput.String(), "hard links") {
				t.Fatalf("late hard link was not rejected: updater_error=%v output=%q", waitErr, updaterOutput.String())
			}
			assertWindowsFileBytes(t, target, original)
			if _, err := os.Stat(windowsReplacementRecord(target)); !os.IsNotExist(err) {
				t.Fatalf("successful late-link rollback retained control state: %v", err)
			}
		})
	}
}

func testWindowsForgedRollbackControlStateIsRejected(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	backup := windowsReplacementBackup(target)
	recordPath := windowsReplacementRecord(target)
	copyWindowsTestExecutable(t, testExecutable, target, []byte("\nINSTALLED_FORGED_STATE_TARGET\n"))
	copyWindowsTestExecutable(t, testExecutable, backup, []byte("\nFORGED_STATE_ROLLBACK\n"))
	targetIdentity, err := inspectWindowsReplacementPath(target, "forged-state installed executable")
	if err != nil {
		t.Fatal(err)
	}
	backupIdentity, err := inspectWindowsReplacementPath(backup, "forged-state rollback image")
	if err != nil {
		t.Fatal(err)
	}
	forged := encodeWindowsReplacementRecord(windowsReplacementRecordData{
		state:     windowsReplacementRecordCompleted,
		original:  backupIdentity,
		installed: targetIdentity,
	})
	if err := os.WriteFile(recordPath, forged, 0o666); err != nil { //nolint:gosec // intentionally inherited attacker-forgeable test state
		t.Fatal(err)
	}
	setWritableWindowsTestDACL(t, recordPath, true)

	err = cleanupPreviousExecutable(target)
	if err == nil || !strings.Contains(err.Error(), "security policy") {
		t.Fatalf("forged valid-checksum rollback record error = %v, want security-policy rejection", err)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("forged rollback record caused rollback evidence loss: %v", err)
	}
	if _, err := os.Stat(recordPath); err != nil {
		t.Fatalf("forged rollback record was not preserved: %v", err)
	}
}

func testWindowsWritableInheritedRollbackStateIsRejected(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	backup := windowsReplacementBackup(target)
	recordPath := windowsReplacementRecord(target)
	copyWindowsTestExecutable(t, testExecutable, target, []byte("\nINHERITED_STATE_TARGET\n"))
	copyWindowsTestExecutable(t, testExecutable, backup, []byte("\nINHERITED_STATE_ROLLBACK\n"))
	if err := os.WriteFile(recordPath, []byte("parse must not be reached"), 0o666); err != nil { //nolint:gosec // intentionally inherited attacker-writable test state
		t.Fatal(err)
	}
	setWritableWindowsTestDACL(t, recordPath, false)

	err = cleanupPreviousExecutable(target)
	if err == nil || !strings.Contains(err.Error(), "security policy") {
		t.Fatalf("writable inherited rollback state error = %v, want security-policy rejection", err)
	}
	if strings.Contains(err.Error(), "record size") {
		t.Fatalf("writable inherited rollback state was parsed before authorization: %v", err)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("writable inherited state caused rollback evidence loss: %v", err)
	}
	if _, err := os.Stat(recordPath); err != nil {
		t.Fatalf("writable inherited state was not preserved: %v", err)
	}
}

func testWindowsWrongOwnerRollbackStateIsRejected(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	backup := windowsReplacementBackup(target)
	recordPath := windowsReplacementRecord(target)
	copyWindowsTestExecutable(t, testExecutable, target, []byte("\nWRONG_OWNER_STATE_TARGET\n"))
	copyWindowsTestExecutable(t, testExecutable, backup, []byte("\nWRONG_OWNER_STATE_ROLLBACK\n"))
	targetIdentity, err := inspectWindowsReplacementPath(target, "wrong-owner installed executable")
	if err != nil {
		t.Fatal(err)
	}
	backupIdentity, err := inspectWindowsReplacementPath(backup, "wrong-owner rollback image")
	if err != nil {
		t.Fatal(err)
	}
	record := encodeWindowsReplacementRecord(windowsReplacementRecordData{
		state:     windowsReplacementRecordCompleted,
		original:  backupIdentity,
		installed: targetIdentity,
	})
	if err := os.WriteFile(recordPath, record, 0o600); err != nil { //nolint:gosec // test-owned control-state fixture
		t.Fatal(err)
	}
	setRestrictiveWindowsTestDACL(t, recordPath)
	setWrongWindowsTestOwner(t, recordPath)

	err = cleanupPreviousExecutable(target)
	if err == nil || !strings.Contains(err.Error(), "security policy owner") {
		t.Fatalf("wrong-owner rollback state error = %v, want owner rejection", err)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("wrong-owner state caused rollback evidence loss: %v", err)
	}
	if _, err := os.Stat(recordPath); err != nil {
		t.Fatalf("wrong-owner state was not preserved: %v", err)
	}
}

func testWindowsInheritedUpdateLockIsRejected(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	lockPath := windowsReplacementLock(target)
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	if err := os.WriteFile(lockPath, []byte("attacker-controlled lock"), 0o666); err != nil { //nolint:gosec // intentionally inherited attacker-forgeable test lock
		t.Fatal(err)
	}
	setWritableWindowsTestDACL(t, lockPath, false)

	err = cleanupPreviousExecutable(target)
	if err == nil || !strings.Contains(err.Error(), "security policy") {
		t.Fatalf("inherited update lock error = %v, want security-policy rejection", err)
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("untrusted update lock was not preserved: %v", err)
	}
}

func testWindowsHardLinksFailClosed(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("target", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "ssm.exe")
		targetAlias := filepath.Join(directory, "ssm-alias.exe")
		stage := filepath.Join(directory, ".ssm.stage.exe")
		copyWindowsTestExecutable(t, testExecutable, target, nil)
		if err := os.Link(target, targetAlias); err != nil {
			t.Fatal(err)
		}
		copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nTARGET_HARDLINK\n"))

		command := windowsReplacementTestCommand(target, stage)
		command.Env = append(command.Env, windowsExpectedFailureEnv+"=current Windows executable has 2 hard links")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("target hard-link fixture failed: %v; output=%q", err, output)
		}
	})
	t.Run("stage", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "ssm.exe")
		stage := filepath.Join(directory, ".ssm.stage.exe")
		stageAlias := filepath.Join(directory, ".ssm.stage-alias.exe")
		copyWindowsTestExecutable(t, testExecutable, target, nil)
		copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nSTAGE_HARDLINK\n"))
		if err := os.Link(stage, stageAlias); err != nil {
			t.Fatal(err)
		}

		command := windowsReplacementTestCommand(target, stage)
		command.Env = append(command.Env, windowsExpectedFailureEnv+"=verified Windows replacement has 2 hard links")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("stage hard-link fixture failed: %v; output=%q", err, output)
		}
	})
	t.Run("reparse points", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "ssm.exe")
		targetLink := filepath.Join(directory, "ssm-link.exe")
		stage := filepath.Join(directory, ".ssm.stage.exe")
		stageTarget := filepath.Join(directory, ".ssm.stage-target.exe")
		copyWindowsTestExecutable(t, testExecutable, target, nil)
		copyWindowsTestExecutable(t, testExecutable, stageTarget, []byte("\nSTAGE_REPARSE\n"))
		if err := os.Symlink(target, targetLink); err != nil {
			t.Skipf("file symlinks are unavailable: %v", err)
		}
		if err := os.Symlink(stageTarget, stage); err != nil {
			t.Skipf("file symlinks are unavailable: %v", err)
		}
		if err := replaceExecutable(stageTarget, targetLink); err == nil ||
			!strings.Contains(err.Error(), "reparse point") && !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("target reparse point error = %v", err)
		}
		if err := replaceExecutable(stage, target); err == nil ||
			!strings.Contains(err.Error(), "reparse point") && !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("stage reparse point error = %v", err)
		}
	})
}

func testWindowsRollbackFailurePreservesEvidence(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.rollback-failure-stage.exe")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nROLLBACK_FAILURE_STAGE\n"))
	original, err := os.ReadFile(target) //nolint:gosec // test-owned executable fixture
	if err != nil {
		t.Fatal(err)
	}

	command := windowsReplacementTestCommand(target, stage)
	command.Env = append(command.Env,
		windowsReplacementFailEnv+"=1",
		windowsRollbackFailEnv+"=1",
		windowsExpectedFailureEnv+"=rollback failed",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("rollback-failure fixture failed: %v; output=%q", err, output)
	}

	backup := windowsReplacementBackup(target)
	assertWindowsFileBytes(t, backup, original)
	if _, err := os.Stat(windowsReplacementRecord(target)); err != nil {
		t.Fatalf("rollback failure did not retain its ownership record: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("rollback failure reported an unexpected canonical target: %v", err)
	}

	cleanup := exec.Command(testExecutable, "-test.run=^TestWindowsCleanupPreviousExecutableChildProcess$", "-test.count=1") //nolint:gosec // fixed test binary and arguments
	cleanup.Env = append(os.Environ(),
		windowsCleanupChildEnv+"=1",
		windowsCleanupTargetEnv+"="+target,
		windowsExpectedFailureEnv+"=incomplete Windows executable replacement requires recovery",
	)
	if output, err := cleanup.CombinedOutput(); err != nil {
		t.Fatalf("rollback-failure cleanup fixture failed: %v; output=%q", err, output)
	}
	assertWindowsFileBytes(t, backup, original)
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
	if os.Getenv(windowsOrdinaryUserEnv) == "1" {
		restore, err := impersonateWindowsTestTokenWithoutPrivileges()
		if err != nil {
			t.Fatalf("create ordinary non-privileged token: %v", err)
		}
		defer func() {
			if err := restore(); err != nil {
				t.Fatalf("restore ordinary non-privileged token: %v", err)
			}
		}()
	}
	if os.Getenv(windowsFullTierDeniedEnv) == "1" {
		originalBegin := beginWindowsReplacementSecurityPrivileges
		originalCapture := captureWindowsReplacementDescriptor
		fullSelections := 0
		fullCaptures := 0
		ordinaryCaptures := 0
		beginWindowsReplacementSecurityPrivileges = func() (*windowsReplacementPrivilegeScope, bool, error) {
			fullSelections++
			return nil, true, nil
		}
		captureWindowsReplacementDescriptor = func(
			handle windows.Handle,
			information windows.SECURITY_INFORMATION,
		) (*ownedWindowsSecurityDescriptor, error) {
			if information == windowsFullSecurityInformation {
				fullCaptures++
				return nil, windows.ERROR_ACCESS_DENIED
			}
			ordinaryCaptures++
			return originalCapture(handle, information)
		}
		defer func() {
			beginWindowsReplacementSecurityPrivileges = originalBegin
			captureWindowsReplacementDescriptor = originalCapture
		}()

		err = replaceExecutable(stage, executable)
		if err != nil {
			t.Fatalf("replacement did not fall back from optional complete descriptor capture: %v", err)
		}
		if fullSelections != 1 {
			t.Fatalf("complete descriptor tier selections = %d, want 1", fullSelections)
		}
		if fullCaptures > 1 {
			t.Fatalf("complete descriptor capture calls = %d, want at most 1 denied probe", fullCaptures)
		}
		if ordinaryCaptures == 0 {
			t.Fatal("ordinary descriptor capture was not reached after denied complete capture")
		}
		return
	}
	if pause := os.Getenv(windowsReplacementPauseEnv); pause != "" ||
		os.Getenv(windowsSubstituteStageEnv) != "" {
		originalHook := windowsReplacementTestHook
		windowsReplacementTestHook = func(phase string) error {
			if phase == os.Getenv(windowsSubstituteStageEnv) {
				inspected := stage + ".inspected"
				if err := os.Rename(stage, inspected); err != nil {
					return fmt.Errorf("rename inspected stage: %w", err)
				}
				data, err := os.ReadFile(inspected) //nolint:gosec // test-owned race fixture
				if err != nil {
					return fmt.Errorf("read inspected stage: %w", err)
				}
				data = append(data, []byte("\nSUBSTITUTED_STAGE\n")...)
				if err := os.WriteFile(stage, data, 0o700); err != nil { //nolint:gosec // test-owned race fixture
					return fmt.Errorf("write substituted stage: %w", err)
				}
			}
			if phase == pause {
				ready := os.Getenv(windowsReplacementReadyEnv)
				if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil { //nolint:gosec // test-owned synchronization fixture
					return err
				}
				if err := waitForWindowsChildPath(os.Getenv(windowsReplacementGoEnv)); err != nil {
					return err
				}
			}
			return nil
		}
		defer func() { windowsReplacementTestHook = originalHook }()
	}
	if os.Getenv(windowsReplacementFailEnv) == "1" ||
		os.Getenv(windowsRollbackFailEnv) == "1" {
		originalRename := renameWindowsReplacementHandle
		targetRenames := 0
		renameWindowsReplacementHandle = func(handle windows.Handle, destination string, replace bool) error {
			if strings.EqualFold(destination, executable) {
				targetRenames++
				if targetRenames == 1 ||
					os.Getenv(windowsRollbackFailEnv) == "1" {
					return windows.ERROR_ACCESS_DENIED
				}
			}
			return originalRename(handle, destination, replace)
		}
		defer func() { renameWindowsReplacementHandle = originalRename }()
	}
	if os.Getenv(windowsReplacementFailEnv) == "1" {
		err = replaceExecutable(stage, executable)
		if assertExpectedWindowsReplacementFailure(t, err) {
			return
		}
		if err == nil {
			t.Fatal("injected staged executable rename failure reported success")
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
		if assertExpectedWindowsReplacementFailure(t, err) {
			return
		}
		if err == nil {
			t.Fatal("descriptor application failure reported replacement success")
		}
		if applyCalls != 2 {
			t.Fatalf("security descriptor apply calls = %d, want 2", applyCalls)
		}
		if !strings.Contains(err.Error(), "apply preserved Windows security descriptor") {
			t.Fatalf("replacement did not fail at canonical descriptor application: %v", err)
		}
		if strings.Contains(err.Error(), "rollback failed") {
			t.Fatalf("descriptor application failure did not restore the original object: %v", err)
		}
		return
	}
	err = replaceExecutable(stage, executable)
	if assertExpectedWindowsReplacementFailure(t, err) {
		return
	}
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
	if target := os.Getenv(windowsCleanupTargetEnv); target != "" {
		executable = target
	}
	err = cleanupPreviousExecutable(executable)
	if assertExpectedWindowsReplacementFailure(t, err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
}

func assertExpectedWindowsReplacementFailure(t *testing.T, err error) bool {
	t.Helper()
	expected := os.Getenv(windowsExpectedFailureEnv)
	if expected == "" {
		return false
	}
	if err == nil {
		t.Fatalf("operation succeeded, want failure containing %q", expected)
	}
	if !strings.Contains(err.Error(), expected) {
		t.Fatalf("operation error = %v, want failure containing %q", err, expected)
	}
	return true
}

func windowsReplacementTestCommand(target, stage string) *exec.Cmd {
	command := exec.Command(target, "-test.run=^TestWindowsReplacementChildProcess$", "-test.count=1") //nolint:gosec // fixed test-owned executable and arguments
	command.Env = append(os.Environ(),
		windowsReplacementChildEnv+"=1",
		windowsReplacementStageEnv+"="+stage,
	)
	return command
}

func waitForWindowsTestPath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForWindowsChildPath(path string) error {
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for test synchronization path")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func impersonateWindowsTestTokenWithoutPrivileges() (func() error, error) {
	runtime.LockOSThread()
	var processToken windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE,
		&processToken,
	); err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	defer processToken.Close()

	var restrictedPrimaryToken windows.Token
	createRestrictedToken := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	result, _, callErr := createRestrictedToken.Call(
		uintptr(processToken),
		0x1, // DISABLE_MAX_PRIVILEGE removes every privilege except SeChangeNotifyPrivilege.
		0,
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&restrictedPrimaryToken)),
	)
	if result == 0 {
		runtime.UnlockOSThread()
		if callErr == nil || errors.Is(callErr, windows.ERROR_SUCCESS) {
			callErr = windows.ERROR_GEN_FAILURE
		}
		return nil, callErr
	}
	tokenType, err := windowsTestTokenUint32Information(
		restrictedPrimaryToken,
		windows.TokenType,
	)
	if err != nil {
		_ = restrictedPrimaryToken.Close()
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("read restricted primary token type: %w", err)
	}
	if tokenType != windows.TokenPrimary {
		_ = restrictedPrimaryToken.Close()
		runtime.UnlockOSThread()
		return nil, fmt.Errorf(
			"CreateRestrictedToken returned token type %d, want TokenPrimary",
			tokenType,
		)
	}

	var restrictedToken windows.Token
	if err := windows.DuplicateTokenEx(
		restrictedPrimaryToken,
		windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&restrictedToken,
	); err != nil {
		_ = restrictedPrimaryToken.Close()
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("duplicate restricted impersonation token: %w", err)
	}
	if err := restrictedPrimaryToken.Close(); err != nil {
		_ = restrictedToken.Close()
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("close restricted primary token: %w", err)
	}
	if err := windows.SetThreadToken(nil, restrictedToken); err != nil {
		_ = restrictedToken.Close()
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("install restricted impersonation token: %w", err)
	}
	return func() error {
		var errs []error
		errs = append(errs, windows.RevertToSelf())
		errs = append(errs, restrictedToken.Close())
		runtime.UnlockOSThread()
		return errors.Join(errs...)
	}, nil
}

func windowsTestTokenState(t *testing.T) (thread, effective string) {
	t.Helper()
	var threadToken windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &threadToken)
	switch {
	case errors.Is(err, windows.ERROR_NO_TOKEN):
		thread = "<none>"
	case err != nil:
		t.Fatalf("open current thread token: %v", err)
	default:
		defer threadToken.Close()
		thread = windowsTestTokenDescription(t, threadToken)
	}
	effective = windowsTestTokenDescription(t, windows.GetCurrentThreadEffectiveToken())
	return thread, effective
}

func assertWindowsTestThreadHasNoToken(t *testing.T) {
	t.Helper()
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &token)
	if err == nil {
		_ = token.Close()
		t.Fatal("thread has an impersonation token, want none")
	}
	if !errors.Is(err, windows.ERROR_NO_TOKEN) {
		t.Fatalf("open absent thread token error = %v, want ERROR_NO_TOKEN", err)
	}
}

func windowsTestTokenDescription(t *testing.T, token windows.Token) string {
	t.Helper()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("read token user: %v", err)
	}
	var size uint32
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		t.Fatalf("size token privileges: %v", err)
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(
		token,
		windows.TokenPrivileges,
		&buffer[0],
		uint32(len(buffer)),
		&size,
	); err != nil {
		t.Fatalf("read token privileges: %v", err)
	}
	privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0])).AllPrivileges()
	return fmt.Sprintf("%s:%v", user.User.Sid.String(), privileges)
}

func windowsTestTokenUint32Information(token windows.Token, class uint32) (uint32, error) {
	var value uint32
	var returned uint32
	err := windows.GetTokenInformation(
		token,
		class,
		(*byte)(unsafe.Pointer(&value)),
		uint32(unsafe.Sizeof(value)),
		&returned,
	)
	if err != nil {
		return 0, err
	}
	if returned != uint32(unsafe.Sizeof(value)) {
		return 0, fmt.Errorf("token information size = %d, want %d", returned, unsafe.Sizeof(value))
	}
	return value, nil
}

func windowsTestTokenHasPrivilege(token windows.Token, name string) (bool, error) {
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	var want windows.LUID
	if err := windows.LookupPrivilegeValue(nil, namePointer, &want); err != nil {
		return false, err
	}
	var size uint32
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return false, fmt.Errorf("size token privileges: %w", err)
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(
		token,
		windows.TokenPrivileges,
		&buffer[0],
		uint32(len(buffer)),
		&size,
	); err != nil {
		return false, fmt.Errorf("read token privileges: %w", err)
	}
	for _, privilege := range (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0])).AllPrivileges() {
		if privilege.Luid == want {
			return true, nil
		}
	}
	return false, nil
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

type windowsTestOrdinarySecurityContract struct {
	ownerSID        string
	groupSID        string
	daclState       string
	aces            []string
	protected       bool
	autoInherited   bool
	hasInheritedACE bool
}

func readWindowsTestOrdinarySecurityContract(
	t *testing.T,
	path string,
) windowsTestOrdinarySecurityContract {
	t.Helper()
	handle, err := openWindowsReplacementFile(path, windows.READ_CONTROL)
	if err != nil {
		t.Fatalf("open ordinary descriptor contract: %v", err)
	}
	defer windows.CloseHandle(handle)
	owned, err := captureWindowsSecurityDescriptor(handle, windowsOrdinarySecurityInformation)
	if err != nil {
		t.Fatalf("capture ordinary descriptor contract: %v", err)
	}
	defer func() {
		if err := owned.close(); err != nil {
			t.Fatalf("free ordinary descriptor contract: %v", err)
		}
	}()

	descriptor := owned.descriptor
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		t.Fatalf("read ordinary descriptor owner: %v", descriptorComponentError(err))
	}
	group, _, err := descriptor.Group()
	if err != nil || group == nil {
		t.Fatalf("read ordinary descriptor primary group: %v", descriptorComponentError(err))
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf("read ordinary descriptor control: %v", err)
	}
	contract := windowsTestOrdinarySecurityContract{
		ownerSID:      owner.String(),
		groupSID:      group.String(),
		protected:     control&windows.SE_DACL_PROTECTED != 0,
		autoInherited: control&windows.SE_DACL_AUTO_INHERITED != 0,
	}
	dacl, _, err := descriptor.DACL()
	switch {
	case errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND):
		contract.daclState = "absent"
		return contract
	case err != nil:
		t.Fatalf("read ordinary descriptor DACL: %v", err)
	case dacl == nil:
		contract.daclState = "null"
		return contract
	default:
		contract.daclState = "present"
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			t.Fatalf("read ordinary descriptor DACL ACE %d: %v", index, err)
		}
		if ace == nil || ace.Header.AceSize < uint16(unsafe.Sizeof(windows.ACE_HEADER{})) {
			t.Fatalf("ordinary descriptor DACL ACE %d is absent or truncated", index)
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			contract.hasInheritedACE = true
		}
		contract.aces = append(
			contract.aces,
			fmt.Sprintf(
				"%x",
				unsafe.Slice((*byte)(unsafe.Pointer(ace)), int(ace.Header.AceSize)),
			),
		)
	}
	return contract
}

func assertWindowsTestOrdinarySecurityContract(
	t *testing.T,
	got,
	want windowsTestOrdinarySecurityContract,
) {
	t.Helper()
	if got.ownerSID != want.ownerSID {
		t.Errorf("ordinary descriptor owner SID = %q, want %q", got.ownerSID, want.ownerSID)
	}
	if got.groupSID != want.groupSID {
		t.Errorf("ordinary descriptor primary group SID = %q, want %q", got.groupSID, want.groupSID)
	}
	if got.daclState != want.daclState {
		t.Errorf("ordinary descriptor DACL state = %q, want %q", got.daclState, want.daclState)
	}
	if !slices.Equal(got.aces, want.aces) {
		t.Errorf("ordinary descriptor DACL ACEs = %v, want %v", got.aces, want.aces)
	}
	if got.protected != want.protected {
		t.Errorf("ordinary descriptor DACL protected = %t, want %t", got.protected, want.protected)
	}
	if want.autoInherited && !got.autoInherited {
		t.Errorf(
			"ordinary descriptor DACL auto-inherited = %t, want retained true state",
			got.autoInherited,
		)
	}
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

func setWritableWindowsTestDACL(t *testing.T, path string, protected bool) {
	t.Helper()
	token := windows.GetCurrentThreadEffectiveToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("read current token user: %v", err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("create Everyone SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.ACCESS_MASK(windowsControlFileFullAccess),
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
			},
		},
		{
			AccessPermissions: windows.FILE_GENERIC_WRITE,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(everyone),
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("build writable test DACL: %v", err)
	}
	information := windows.SECURITY_INFORMATION(
		windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
	)
	if protected {
		information = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		information,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatalf("set writable test DACL: %v", err)
	}
}

func setWrongWindowsTestOwner(t *testing.T, path string) {
	t.Helper()
	scope, available, err := beginWindowsReplacementPrivileges()
	if err != nil {
		t.Fatalf("enable wrong-owner test privileges: %v", err)
	}
	if !available {
		t.Skip("current Windows token cannot assign a foreign control-state owner")
	}
	defer func() {
		if err := scope.close(); err != nil {
			t.Fatalf("restore wrong-owner test privileges: %v", err)
		}
	}()
	owner, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("create wrong-owner SID: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		owner,
		nil,
		nil,
		nil,
	); err != nil {
		if isWindowsCompleteSecurityUnavailable(err) {
			t.Skipf("current Windows token cannot assign a foreign control-state owner: %v", err)
		}
		t.Fatalf("set wrong control-state owner: %v", err)
	}
}

func assertWindowsControlFileSecurity(t *testing.T, path string) {
	t.Helper()
	policy, err := newWindowsControlSecurityPolicy()
	if err != nil {
		t.Fatalf("build expected control-file security policy: %v", err)
	}
	handle, err := openWindowsReplacementFile(path, windows.READ_CONTROL)
	if err != nil {
		t.Fatalf("open control file %s: %v", path, err)
	}
	defer windows.CloseHandle(handle)
	if err := policy.validate(handle, filepath.Base(path)); err != nil {
		t.Fatalf("control file %s does not have owner-only protected security: %v", path, err)
	}
}

func trySetWindowsTestSACL(t *testing.T, path string) (bool, string) {
	t.Helper()
	scope, available, err := beginWindowsReplacementPrivileges()
	if err != nil {
		t.Fatalf("enable test SACL privileges: %v", err)
	}
	if !available {
		return false, "current token lacks the complete descriptor privileges"
	}
	defer func() {
		if err := scope.close(); err != nil {
			t.Fatalf("restore test SACL privileges: %v", err)
		}
	}()
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil {
		t.Fatalf("read current token user: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.FILE_GENERIC_READ,
			AccessMode:        windows.SET_AUDIT_SUCCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("build test SACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.SACL_SECURITY_INFORMATION|windows.PROTECTED_SACL_SECURITY_INFORMATION,
		nil,
		nil,
		nil,
		acl,
	); err != nil {
		if isWindowsCompleteSecurityUnavailable(err) {
			return false, fmt.Sprintf("set test SACL: %v", err)
		}
		t.Fatalf("set test SACL: %v", err)
	}
	return true, ""
}

func tryReadWindowsTestCompleteSecurityDescriptor(
	t *testing.T,
	path string,
) (windowsTestSecurityDescriptor, bool, string) {
	t.Helper()
	scope, available, err := beginWindowsReplacementPrivileges()
	if err != nil {
		t.Fatalf("enable test descriptor privileges: %v", err)
	}
	if !available {
		return windowsTestSecurityDescriptor{},
			false,
			"current token lacks the complete descriptor privileges"
	}
	defer func() {
		if err := scope.close(); err != nil {
			t.Fatalf("release test descriptor privileges: %v", err)
		}
	}()

	handle, err := openWindowsReplacementFile(
		path,
		windows.READ_CONTROL|windows.ACCESS_SYSTEM_SECURITY,
	)
	if err != nil {
		if isWindowsCompleteSecurityUnavailable(err) {
			return windowsTestSecurityDescriptor{}, false, fmt.Sprintf("open test descriptor: %v", err)
		}
		t.Fatalf("open test descriptor: %v", err)
	}
	descriptor, captureErr := captureWindowsSecurityDescriptor(
		handle,
		windowsFullSecurityInformation,
	)
	closeErr := windows.CloseHandle(handle)
	if closeErr != nil {
		t.Fatalf("close test descriptor: %v", closeErr)
	}
	if captureErr != nil {
		if isWindowsCompleteSecurityUnavailable(captureErr) {
			return windowsTestSecurityDescriptor{},
				false,
				fmt.Sprintf("read complete security descriptor: %v", captureErr)
		}
		t.Fatalf("read complete security descriptor: %v", captureErr)
	}
	defer func() {
		if err := descriptor.close(); err != nil {
			t.Fatalf("free test security descriptor: %v", err)
		}
	}()
	if err := validateWindowsSecurityDescriptor(descriptor.descriptor); err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.descriptor.Control()
	if err != nil {
		t.Fatalf("read security descriptor control: %v", err)
	}
	sddl := descriptor.descriptor.String()
	if sddl == "" {
		t.Fatal("convert security descriptor to SDDL")
	}
	return windowsTestSecurityDescriptor{sddl: sddl, control: control}, true, ""
}

func readWindowsTestSecurityDescriptor(t *testing.T, path string) windowsTestSecurityDescriptor {
	t.Helper()
	handle, err := openWindowsReplacementFile(
		path,
		windows.READ_CONTROL,
	)
	if err != nil {
		t.Fatalf("open test descriptor: %v", err)
	}
	defer windows.CloseHandle(handle)
	descriptor, err := captureWindowsSecurityDescriptor(handle, windowsOrdinarySecurityInformation)
	if err != nil {
		t.Fatalf("read security descriptor: %v", err)
	}
	defer func() {
		if err := descriptor.close(); err != nil {
			t.Fatalf("free test security descriptor: %v", err)
		}
	}()
	if err := validateWindowsSecurityDescriptor(descriptor.descriptor); err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.descriptor.Control()
	if err != nil {
		t.Fatalf("read security descriptor control: %v", err)
	}
	sddl := descriptor.descriptor.String()
	if sddl == "" {
		t.Fatal("convert security descriptor to SDDL")
	}
	return windowsTestSecurityDescriptor{sddl: sddl, control: control}
}
