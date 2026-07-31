//go:build windows

package update

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
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
	windowsReplacementChildEnv  = "SSM_TEST_WINDOWS_REPLACEMENT_CHILD"
	windowsReplacementStageEnv  = "SSM_TEST_WINDOWS_REPLACEMENT_STAGE"
	windowsReplacementTargetEnv = "SSM_TEST_WINDOWS_REPLACEMENT_TARGET"
	windowsReplacementFailEnv   = "SSM_TEST_WINDOWS_REPLACEMENT_FAIL"
	windowsDescriptorFailEnv    = "SSM_TEST_WINDOWS_DESCRIPTOR_FAIL"
	windowsCleanupChildEnv      = "SSM_TEST_WINDOWS_CLEANUP_CHILD"
	windowsCleanupTargetEnv     = "SSM_TEST_WINDOWS_CLEANUP_TARGET"
	windowsExpectedFailureEnv   = "SSM_TEST_WINDOWS_EXPECTED_FAILURE"
	windowsOrdinaryUserEnv      = "SSM_TEST_WINDOWS_ORDINARY_USER"
	windowsFullTierDeniedEnv    = "SSM_TEST_WINDOWS_FULL_TIER_DENIED"
	windowsReplacementPauseEnv  = "SSM_TEST_WINDOWS_REPLACEMENT_PAUSE"
	windowsReplacementReadyEnv  = "SSM_TEST_WINDOWS_REPLACEMENT_READY"
	windowsReplacementGoEnv     = "SSM_TEST_WINDOWS_REPLACEMENT_GO"
	windowsSubstituteStageEnv   = "SSM_TEST_WINDOWS_SUBSTITUTE_STAGE"
	windowsMutateStageEnv       = "SSM_TEST_WINDOWS_MUTATE_STAGE"
	windowsRollbackFailEnv      = "SSM_TEST_WINDOWS_ROLLBACK_FAIL"
)

func TestWindowsNativeReplacementSecurity(t *testing.T) {
	t.Run("ordinary user preserves owner group DACL and inheritance", testWindowsOrdinaryUserReplacement)
	t.Run("effective token privilege detection cannot escape to the process token", testWindowsRestrictedImpersonationToken)
	t.Run("no thread token falls back to one process token and closes its handles", testWindowsNoThreadTokenProcessFallback)
	t.Run("process token fallback requires ERROR_NO_TOKEN", testWindowsProcessTokenFallbackRequiresNoThreadToken)
	t.Run("ordinary inherited descriptor capture apply and verification are semantic", testWindowsInheritedOrdinaryDescriptorPreparation)
	t.Run("ordinary descriptor differences identify the changed security component", testWindowsOrdinaryDescriptorDiagnostics)
	t.Run("complete descriptor RM control binding is byte exact", testWindowsCompleteDescriptorRMControlBinding)
	t.Run("strong file identity is required", testWindowsStrongFileIdentityRequired)
	t.Run("authenticated rollback record binds strong identities descriptor and bytes", testWindowsReplacementRecordDescriptorBinding)
	t.Run("optional complete descriptor denial falls back to ordinary preservation", testWindowsOptionalFullTierFallback)
	t.Run("complete descriptor is preserved when supported with ordinary fallback", testWindowsPrivilegedReplacement)
	t.Run("privileges and thread identity are restored", testWindowsReplacementPrivilegeRestoration)
	t.Run("SetThreadToken restoration failure is retried before unlock", testWindowsPreviousTokenRestorationFailure)
	t.Run("RevertToSelf restoration failure is retried before unlock", testWindowsNoTokenRestorationFailure)
	t.Run("privilege restoration is confirmed before unlock", testWindowsPrivilegeRestorationConfirmation)
	t.Run("persistent privilege restoration failure fail-stops before unlock", testWindowsPrivilegeRestorationFailStop)
	t.Run("native descriptor buffers are freed exactly once", testWindowsSecurityDescriptorOwnership)
	t.Run("mapped executable is replaced and completed rollback is cleaned", testWindowsMappedExecutableReplacementSucceedsAndCleansOnNextLaunch)
	t.Run("install failure rolls back", testWindowsMappedExecutableReplacementFailureRollsBack)
	t.Run("descriptor failure rolls back", testWindowsSecurityDescriptorApplyFailureRollsBack)
	t.Run("returned replacement failure preserves the canonical executable", testWindowsReturnedReplacementFailurePreservesCanonical)
	t.Run("post-commit cleanup failures are deferred success", testWindowsPostCommitCleanupFailuresAreDeferred)
	t.Run("concurrent updaters are excluded", testWindowsConcurrentUpdaters)
	t.Run("cleanup cannot delete a live updater rollback", testWindowsConcurrentCleanup)
	t.Run("ordinary startup discovery creates no sibling state", testWindowsOrdinaryStartupDiscoveryIsNonMutating)
	t.Run("unexplained stale rollback is preserved", testWindowsUnexplainedRollbackIsPreserved)
	t.Run("verified download callback races fail closed", testWindowsVerifiedDownloadCallbackRacesFailClosed)
	t.Run("stage substitution fails closed", testWindowsStageSubstitutionFailsClosed)
	t.Run("same-object stage mutation fails closed", testWindowsStageContentMutationFailsClosed)
	t.Run("source substitution at the rename gap is blocked", testWindowsSourceSubstitutionAtRenameGap)
	t.Run("canonical substitution at the rename gap fails closed until recovery", testWindowsCanonicalSubstitutionAtRenameGap)
	t.Run("rollback over a locked canonical substitute fails closed until recovery", testWindowsRollbackReplacesCanonicalSubstitute)
	t.Run("rollback rejects a late hard link to its image", testWindowsRollbackRejectsLateHardLink)
	t.Run("late hard links retain recovery evidence until safe recovery", testWindowsLateHardLinksCannotCompromiseTarget)
	t.Run("prepared and canonical recovery authenticate rollback bytes", testWindowsRecoveryRejectsSameIdentityContentMutation)
	t.Run("completed cleanup authenticates rollback bytes", testWindowsCompletedCleanupRejectsSameIdentityContentMutation)
	t.Run("prepared recovery rejects descriptor mutation with the same file ID", testWindowsPreparedRecoveryRejectsDescriptorMutation)
	t.Run("prepared full recovery rejects same-ID RM control mutation", testWindowsPreparedFullRecoveryRejectsRMControlMutation)
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

func testWindowsReturnedReplacementFailurePreservesCanonical(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.precommit-failure-stage.exe")
	copyWindowsTestExecutable(t, testExecutable, target, []byte("\nPRECOMMIT_ORIGINAL\n"))
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nPRECOMMIT_REPLACEMENT\n"))
	original, err := os.ReadFile(target) //nolint:gosec // test-owned replacement fixture
	if err != nil {
		t.Fatal(err)
	}

	originalHook := windowsReplacementTestHook
	windowsReplacementTestHook = func(phase string) error {
		if phase == windowsReplacementPhaseBeforeStageMove {
			return windows.ERROR_GEN_FAILURE
		}
		return nil
	}
	err = replaceExecutable(stage, target, windowsTestFileDigest(t, stage))
	windowsReplacementTestHook = originalHook
	if err == nil ||
		!strings.Contains(err.Error(), "revalidate verified Windows replacement before install") {
		t.Fatalf("pre-commit replacement error = %v", err)
	}
	assertWindowsFileBytes(t, target, original)
	if _, err := os.Stat(windowsReplacementBackup(target)); !os.IsNotExist(err) {
		t.Fatalf("reported replacement failure retained rollback image: %v", err)
	}
	if _, err := os.Stat(windowsReplacementRecord(target)); !os.IsNotExist(err) {
		t.Fatalf("reported replacement failure retained rollback record: %v", err)
	}
}

func testWindowsPostCommitCleanupFailuresAreDeferred(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		phase string
	}{
		{name: "security state close", phase: windowsReplacementPhaseSecurityClose},
		{name: "replacement lock close", phase: windowsReplacementPhaseLockClose},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "ssm.exe")
			stage := filepath.Join(directory, ".ssm.postcommit-stage.exe")
			copyWindowsTestExecutable(t, testExecutable, target, []byte("\nPOSTCOMMIT_ORIGINAL\n"))
			copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nPOSTCOMMIT_REPLACEMENT\n"))
			replacement, err := os.ReadFile(stage) //nolint:gosec // test-owned replacement fixture
			if err != nil {
				t.Fatal(err)
			}

			originalHook := windowsReplacementTestHook
			injected := 0
			windowsReplacementTestHook = func(phase string) error {
				if phase == test.phase {
					injected++
					return windows.ERROR_GEN_FAILURE
				}
				return nil
			}
			err = replaceExecutable(stage, target, windowsTestFileDigest(t, stage))
			windowsReplacementTestHook = originalHook
			if err != nil {
				t.Fatalf("committed replacement was reported as failed: %v", err)
			}
			if injected != 1 {
				t.Fatalf("%s injections = %d, want 1", test.name, injected)
			}
			assertWindowsFileBytes(t, target, replacement)

			recordBytes, err := os.ReadFile(windowsReplacementRecord(target)) //nolint:gosec // test-owned authenticated recovery fixture
			if err != nil {
				t.Fatalf("read deferred-cleanup rollback record: %v", err)
			}
			record, err := decodeWindowsReplacementRecord(recordBytes)
			if err != nil {
				t.Fatalf("decode deferred-cleanup rollback record: %v", err)
			}
			if record.state != windowsReplacementRecordCompleted {
				t.Fatalf("deferred-cleanup rollback state = %d, want completed", record.state)
			}
			if _, err := os.Stat(windowsReplacementBackup(target)); err != nil {
				t.Fatalf("deferred cleanup lost rollback image: %v", err)
			}

			if err := cleanupPreviousExecutable(target); err != nil {
				t.Fatalf("authenticated deferred cleanup failed: %v", err)
			}
			if _, err := os.Stat(windowsReplacementBackup(target)); !os.IsNotExist(err) {
				t.Fatalf("deferred cleanup retained rollback image: %v", err)
			}
			if _, err := os.Stat(windowsReplacementRecord(target)); !os.IsNotExist(err) {
				t.Fatalf("deferred cleanup retained rollback record: %v", err)
			}
		})
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
			wantBinding, err := bindWindowsSecurityDescriptor(want, false)
			if err != nil {
				t.Fatalf("bind wanted ordinary descriptor: %v", err)
			}
			gotBinding, err := bindWindowsSecurityDescriptor(got, false)
			if err != nil {
				t.Fatalf("bind changed ordinary descriptor: %v", err)
			}
			if err := compareWindowsSecurityBindings(wantBinding, gotBinding); err == nil {
				t.Fatal("changed ordinary descriptor retained the authenticated recovery binding")
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
		wantBinding, err := bindWindowsSecurityDescriptor(want, false)
		if err != nil {
			t.Fatal(err)
		}
		gotBinding, err := bindWindowsSecurityDescriptor(got, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := compareWindowsSecurityBindings(wantBinding, gotBinding); err != nil {
			t.Fatalf("Windows-normalized auto-inherited metadata changed the recovery binding: %v", err)
		}
	})

	t.Run("complete descriptor SACL", func(t *testing.T) {
		want, err := windows.SecurityDescriptorFromString(
			"O:SYG:BAD:(A;;FR;;;BU)S:(AU;SA;FR;;;BU)",
		)
		if err != nil {
			t.Fatal(err)
		}
		got, err := windows.SecurityDescriptorFromString(
			"O:SYG:BAD:(A;;FR;;;BU)S:(AU;SA;FW;;;BU)",
		)
		if err != nil {
			t.Fatal(err)
		}
		wantBinding, err := bindWindowsSecurityDescriptor(want, true)
		if err != nil {
			t.Fatal(err)
		}
		gotBinding, err := bindWindowsSecurityDescriptor(got, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := compareWindowsSecurityBindings(wantBinding, gotBinding); err == nil {
			t.Fatal("changed SACL retained the authenticated complete-descriptor binding")
		}
	})
}

func testWindowsCompleteDescriptorRMControlBinding(t *testing.T) {
	newDescriptor := func(t *testing.T) *windows.SECURITY_DESCRIPTOR {
		t.Helper()
		descriptor, err := windows.SecurityDescriptorFromString(
			"O:SYG:BAD:(A;;FR;;;BU)S:(AU;SA;FR;;;BU)",
		)
		if err != nil {
			t.Fatal(err)
		}
		return descriptor
	}
	bind := func(t *testing.T, descriptor *windows.SECURITY_DESCRIPTOR) windowsSecurityBinding {
		t.Helper()
		binding, err := bindWindowsSecurityDescriptor(descriptor, true)
		if err != nil {
			t.Fatal(err)
		}
		return binding
	}

	absent := bind(t, newDescriptor(t))
	presentZeroDescriptor := newDescriptor(t)
	presentZeroDescriptor.SetRMControl(0)
	presentZero := bind(t, presentZeroDescriptor)
	if err := compareWindowsSecurityBindings(absent, presentZero); err == nil {
		t.Fatal("present zero RM control retained the absent RM-control binding")
	}

	expectedDescriptor := newDescriptor(t)
	expectedDescriptor.SetRMControl(42)
	expected := bind(t, expectedDescriptor)
	mutatedDescriptor := newDescriptor(t)
	mutatedDescriptor.SetRMControl(43)
	mutated := bind(t, mutatedDescriptor)
	if err := compareWindowsSecurityBindings(expected, mutated); err == nil {
		t.Fatal("changed RM-control byte retained the authenticated complete-descriptor binding")
	}

	mutatedDescriptor.SetRMControl(42)
	restored := bind(t, mutatedDescriptor)
	if err := compareWindowsSecurityBindings(expected, restored); err != nil {
		t.Fatalf("restored exact RM-control byte did not restore the binding: %v", err)
	}
}

func testWindowsReplacementRecordDescriptorBinding(t *testing.T) {
	var descriptorDigest [sha256.Size]byte
	var rollbackDigest [sha256.Size]byte
	for index := range descriptorDigest {
		descriptorDigest[index] = byte(index + 1)
		rollbackDigest[index] = byte(0x80 + index)
	}
	want := windowsReplacementRecordData{
		state: windowsReplacementRecordPrepared,
		original: windowsFileIdentity{
			volumeSerialNumber: 0x0807060504030201,
			fileID: [16]byte{
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
		},
		installed: windowsFileIdentity{
			volumeSerialNumber: 0x2827262524232221,
			fileID: [16]byte{
				0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
				0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
			},
		},
		rollbackDigest: rollbackDigest,
		securityBinding: windowsSecurityBinding{
			metadata: windowsSecurityBindingOrdinary |
				windowsSecurityBindingDACLAutoInheritedRequired,
			digest: descriptorDigest,
		},
	}
	encoded := encodeWindowsReplacementRecord(want)
	if len(encoded) != 136 {
		t.Fatalf("authenticated rollback record size = %d, want 136", len(encoded))
	}
	if got := binary.LittleEndian.Uint32(encoded[8:12]); got != 3 {
		t.Fatalf("authenticated rollback record version = %d, want 3", got)
	}
	wantOriginalEncoding := []byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	if !bytes.Equal(encoded[16:40], wantOriginalEncoding) {
		t.Fatalf("strong file identity encoding = %x, want %x", encoded[16:40], wantOriginalEncoding)
	}
	got, err := decodeWindowsReplacementRecord(encoded)
	if err != nil {
		t.Fatalf("decode authenticated rollback record: %v", err)
	}
	if got != want {
		t.Fatalf("authenticated rollback record = %#v, want %#v", got, want)
	}

	corruptDigest := append([]byte(nil), encoded...)
	corruptDigest[68] ^= 0xff
	if _, err := decodeWindowsReplacementRecord(corruptDigest); err == nil ||
		!strings.Contains(err.Error(), "checksum is invalid") {
		t.Fatalf("descriptor-binding corruption error = %v, want checksum rejection", err)
	}

	invalidBinding := append([]byte(nil), encoded...)
	binary.LittleEndian.PutUint32(invalidBinding[64:68], 0)
	binary.LittleEndian.PutUint32(
		invalidBinding[132:136],
		crc32.ChecksumIEEE(invalidBinding[:132]),
	)
	if _, err := decodeWindowsReplacementRecord(invalidBinding); err == nil ||
		!strings.Contains(err.Error(), "security descriptor binding is invalid") {
		t.Fatalf("invalid descriptor-binding metadata error = %v, want binding rejection", err)
	}

	legacy := make([]byte, 80)
	copy(legacy[:8], []byte{'S', 'S', 'M', 'O', 'L', 'D', '2', 0})
	binary.LittleEndian.PutUint32(legacy[8:12], 2)
	binary.LittleEndian.PutUint32(legacy[12:16], windowsReplacementRecordPrepared)
	binary.LittleEndian.PutUint32(legacy[16:20], 1)
	binary.LittleEndian.PutUint32(legacy[20:24], 2)
	binary.LittleEndian.PutUint32(legacy[24:28], 3)
	binary.LittleEndian.PutUint32(legacy[28:32], 4)
	binary.LittleEndian.PutUint32(legacy[32:36], 5)
	binary.LittleEndian.PutUint32(legacy[36:40], 6)
	binary.LittleEndian.PutUint32(legacy[40:44], windowsSecurityBindingOrdinary)
	copy(legacy[44:76], descriptorDigest[:])
	binary.LittleEndian.PutUint32(legacy[76:80], crc32.ChecksumIEEE(legacy[:76]))
	if _, err := decodeWindowsReplacementRecord(legacy); err == nil ||
		!strings.Contains(err.Error(), "legacy Windows rollback ownership record version 2") {
		t.Fatalf("legacy weak-identity rollback record error = %v, want fail-closed version rejection", err)
	}
}

func testWindowsStrongFileIdentityRequired(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.exe")
	copyWindowsTestExecutable(t, testExecutable, path, nil)
	handle, err := openWindowsReplacementFile(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)

	original := getWindowsFileInformationByHandleEx
	getWindowsFileInformationByHandleEx = func(
		windows.Handle,
		uint32,
		*byte,
		uint32,
	) error {
		return windows.ERROR_NOT_SUPPORTED
	}
	defer func() { getWindowsFileInformationByHandleEx = original }()
	if _, _, err := inspectWindowsReplacementHandleObject(handle, "identity fixture"); err == nil ||
		!strings.Contains(err.Error(), "strong file identity") {
		t.Fatalf("strong-identity capability error = %v, want fail-closed rejection", err)
	}
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

func testWindowsPreviousTokenRestorationFailure(t *testing.T) {
	scope, beforeThread, cleanup := newWindowsTestRestorationScope(t, true)
	defer cleanup()

	restoreCalls := 0
	scope.setThreadToken = func(token windows.Token) error {
		restoreCalls++
		if restoreCalls == 1 {
			return windows.ERROR_GEN_FAILURE
		}
		return windows.SetThreadToken(nil, token)
	}
	if err := scope.restore(); err == nil ||
		!strings.Contains(err.Error(), "restore previous Windows thread token") {
		t.Fatalf("first previous-token restoration error = %v", err)
	}
	if !scope.installed {
		t.Fatal("failed previous-token restoration marked the privileged token uninstalled")
	}
	if err := scope.close(); err != nil {
		t.Fatalf("retry previous-token restoration: %v", err)
	}
	if restoreCalls != 2 {
		t.Fatalf("previous-token restoration calls = %d, want 2", restoreCalls)
	}
	afterThread, _ := windowsTestTokenState(t)
	if afterThread != beforeThread {
		t.Fatalf("restored previous thread token = %q, want %q", afterThread, beforeThread)
	}
}

func testWindowsNoTokenRestorationFailure(t *testing.T) {
	scope, _, cleanup := newWindowsTestRestorationScope(t, false)
	defer cleanup()

	restoreCalls := 0
	scope.revertToSelf = func() error {
		restoreCalls++
		if restoreCalls == 1 {
			return windows.ERROR_GEN_FAILURE
		}
		return windows.RevertToSelf()
	}
	if err := scope.restore(); err == nil ||
		!strings.Contains(err.Error(), "revert Windows thread token") {
		t.Fatalf("first no-token restoration error = %v", err)
	}
	if !scope.installed {
		t.Fatal("failed RevertToSelf marked the privileged token uninstalled")
	}
	if err := scope.close(); err != nil {
		t.Fatalf("retry RevertToSelf restoration: %v", err)
	}
	if restoreCalls != 2 {
		t.Fatalf("RevertToSelf calls = %d, want 2", restoreCalls)
	}
	assertWindowsTestThreadHasNoToken(t)
}

func testWindowsPrivilegeRestorationConfirmation(t *testing.T) {
	scope, _, cleanup := newWindowsTestRestorationScope(t, false)
	defer cleanup()

	scope.revertToSelf = func() error {
		return nil
	}
	if err := scope.restore(); err == nil ||
		!strings.Contains(err.Error(), "confirm Windows thread token restoration") {
		t.Fatalf("unconfirmed restoration error = %v", err)
	}
	if !scope.installed {
		t.Fatal("unconfirmed restoration marked the privileged token uninstalled")
	}
	scope.revertToSelf = windows.RevertToSelf
	if err := scope.close(); err != nil {
		t.Fatalf("restore after false-success injection: %v", err)
	}
	assertWindowsTestThreadHasNoToken(t)
}

func testWindowsPrivilegeRestorationFailStop(t *testing.T) {
	scope, _, cleanup := newWindowsTestRestorationScope(t, false)
	defer cleanup()

	scope.revertToSelf = func() error {
		return windows.ERROR_GEN_FAILURE
	}
	unlockCalls := 0
	scope.unlockOSThread = func() {
		unlockCalls++
	}
	failStopErr := error(nil)
	failStopMarker := errors.New("test privilege restoration fail-stop")
	scope.failSafe = func(err error) {
		failStopErr = err
		panic(failStopMarker)
	}

	var recovered any
	func() {
		defer func() {
			recovered = recover()
		}()
		_ = scope.close()
	}()
	if recovered != failStopMarker {
		t.Fatalf("persistent restoration failure panic = %v, want fail-stop marker", recovered)
	}
	if failStopErr == nil ||
		!strings.Contains(failStopErr.Error(), "revert Windows thread token") {
		t.Fatalf("persistent restoration fail-stop error = %v", failStopErr)
	}
	if unlockCalls != 0 {
		t.Fatalf("persistent restoration failure unlocked OS thread %d times", unlockCalls)
	}
	if !scope.active || !scope.installed {
		t.Fatal("persistent restoration failure released the active privileged scope")
	}
}

func newWindowsTestRestorationScope(
	t *testing.T,
	hadPrevious bool,
) (*windowsReplacementPrivilegeScope, string, func()) {
	t.Helper()

	var restoreOuter func() error
	if hadPrevious {
		var err error
		restoreOuter, err = impersonateWindowsTestTokenWithoutPrivileges()
		if err != nil {
			t.Fatalf("install test previous impersonation token: %v", err)
		}
	} else {
		runtime.LockOSThread()
		assertWindowsTestThreadHasNoToken(t)
		restoreOuter = func() error {
			runtime.UnlockOSThread()
			return nil
		}
	}
	beforeThread, _ := windowsTestTokenState(t)
	runtime.LockOSThread()

	scope := &windowsReplacementPrivilegeScope{
		closeToken:  func(token windows.Token) error { return token.Close() },
		hadPrevious: hadPrevious,
		installed:   true,
		active:      true,
		setThreadToken: func(token windows.Token) error {
			return windows.SetThreadToken(nil, token)
		},
		revertToSelf:   windows.RevertToSelf,
		unlockOSThread: runtime.UnlockOSThread,
		failSafe:       failWindowsPrivilegeRestoration,
	}
	if hadPrevious {
		if err := windows.OpenThreadToken(
			windows.CurrentThread(),
			windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE,
			false,
			&scope.previousToken,
		); err != nil {
			runtime.UnlockOSThread()
			_ = restoreOuter()
			t.Fatalf("open test previous impersonation token: %v", err)
		}
	}

	source := scope.previousToken
	var processToken windows.Token
	if !hadPrevious {
		if err := windows.OpenProcessToken(
			windows.CurrentProcess(),
			windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE,
			&processToken,
		); err != nil {
			runtime.UnlockOSThread()
			_ = restoreOuter()
			t.Fatalf("open test process token: %v", err)
		}
		source = processToken
	}
	if err := windows.DuplicateTokenEx(
		source,
		windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&scope.token,
	); err != nil {
		_ = processToken.Close()
		_ = scope.previousToken.Close()
		runtime.UnlockOSThread()
		_ = restoreOuter()
		t.Fatalf("duplicate test installed impersonation token: %v", err)
	}
	if processToken != 0 {
		if err := processToken.Close(); err != nil {
			_ = scope.token.Close()
			_ = scope.previousToken.Close()
			runtime.UnlockOSThread()
			_ = restoreOuter()
			t.Fatalf("close test process token: %v", err)
		}
	}
	if err := windows.SetThreadToken(nil, scope.token); err != nil {
		_ = scope.token.Close()
		_ = scope.previousToken.Close()
		runtime.UnlockOSThread()
		_ = restoreOuter()
		t.Fatalf("install test replacement impersonation token: %v", err)
	}

	cleanup := func() {
		if scope.active {
			if scope.hadPrevious && scope.previousToken != 0 {
				_ = windows.SetThreadToken(nil, scope.previousToken)
			} else {
				_ = windows.RevertToSelf()
			}
			if scope.token != 0 {
				_ = scope.token.Close()
				scope.token = 0
			}
			if scope.previousToken != 0 {
				_ = scope.previousToken.Close()
				scope.previousToken = 0
			}
			scope.active = false
			scope.installed = false
			runtime.UnlockOSThread()
		}
		if err := restoreOuter(); err != nil {
			t.Fatalf("restore outer test token state: %v", err)
		}
	}
	return scope, beforeThread, cleanup
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

func testWindowsOrdinaryStartupDiscoveryIsNonMutating(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "ssm.exe")
	copyWindowsTestExecutable(t, testExecutable, target, nil)

	if err := cleanupPreviousExecutable(target); err != nil {
		t.Fatalf("ordinary startup discovery failed: %v", err)
	}
	for _, path := range []string{
		windowsReplacementLock(target),
		windowsReplacementRecord(target),
		windowsReplacementBackup(target),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("ordinary startup discovery mutated sibling %s: %v", filepath.Base(path), err)
		}
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
	for _, test := range []struct {
		phase         string
		expectedError string
	}{
		{
			phase:         windowsReplacementPhaseAfterLock,
			expectedError: "digest does not match authenticated bytes",
		},
		{
			phase:         windowsReplacementPhaseBeforeTargetMove,
			expectedError: "rename inspected stage",
		},
		{
			phase:         windowsReplacementPhaseBeforeStageMove,
			expectedError: "rename inspected stage",
		},
	} {
		t.Run(test.phase, func(t *testing.T) {
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
				windowsSubstituteStageEnv+"="+test.phase,
				windowsExpectedFailureEnv+"="+test.expectedError,
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

func testWindowsVerifiedDownloadCallbackRacesFailClosed(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "path substitution before replacement handle acquisition",
			mutate: func(t *testing.T, stage string) {
				t.Helper()
				if err := os.Rename(stage, stage+".verified"); err != nil {
					t.Fatal(err)
				}
				copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nCALLBACK_SUBSTITUTE\n"))
			},
		},
		{
			name: "same-object in-place mutation",
			mutate: func(t *testing.T, stage string) {
				t.Helper()
				file, err := os.OpenFile(stage, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // test-owned callback race fixture
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write([]byte("\nCALLBACK_IN_PLACE_MUTATION\n")); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			restoreUpdateTestHooks(t)
			setTestHome(t, t.TempDir())
			t.Setenv("SSM_UPDATE_REPO", "owner/repo")
			directory := t.TempDir()
			target := filepath.Join(directory, "ssm.exe")
			copyWindowsTestExecutable(t, testExecutable, target, nil)
			original, err := os.ReadFile(target) //nolint:gosec // test-owned executable fixture
			if err != nil {
				t.Fatal(err)
			}
			executablePath = func() (string, error) { return target, nil }
			evalSymlinks = func(path string) (string, error) { return path, nil }
			const version = "v9.9.9"
			payload := appendTestExecutableMarker(t, testExecutable, "\nVERIFIED_CALLBACK_STAGE\n")
			httpClient = migrationHTTPClient(t, version, payload, true)

			callbackCalled := false
			err = DownloadVersionBeforeReplace(version, false, func() error {
				callbackCalled = true
				matches, globErr := filepath.Glob(filepath.Join(directory, ".ssm.exe.*.new"))
				if globErr != nil {
					return globErr
				}
				if len(matches) != 1 {
					return fmt.Errorf("verified callback stage count = %d, want 1", len(matches))
				}
				test.mutate(t, matches[0])
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), "digest does not match authenticated bytes") {
				t.Fatalf("callback race error = %v, want authenticated-digest rejection", err)
			}
			if !callbackCalled {
				t.Fatal("verified callback race did not reach the callback")
			}
			assertWindowsFileBytes(t, target, original)
			if _, err := os.Stat(windowsReplacementBackup(target)); !os.IsNotExist(err) {
				t.Fatalf("callback race created rollback evidence: %v", err)
			}
		})
	}
}

func testWindowsStageContentMutationFailsClosed(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.mutated-stage.exe")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nVERIFIED_STAGE\n"))
	original := appendTestExecutableMarker(t, testExecutable, "")

	command := windowsReplacementTestCommand(target, stage)
	command.Env = append(command.Env,
		windowsMutateStageEnv+"="+windowsReplacementPhaseAfterLock,
		windowsExpectedFailureEnv+"=digest does not match authenticated bytes",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("stage content-mutation fixture failed: %v; output=%q", err, output)
	}
	assertWindowsFileBytes(t, target, original)
	if _, err := os.Stat(windowsReplacementBackup(target)); !os.IsNotExist(err) {
		t.Fatalf("stage content mutation created rollback state: %v", err)
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
	setRestrictiveWindowsTestDACL(t, target)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nVERIFIED_CANONICAL_GAP_STAGE\n"))
	original, err := os.ReadFile(target) //nolint:gosec // test-owned mapped executable
	if err != nil {
		t.Fatal(err)
	}
	originalIdentity, err := inspectWindowsReplacementPath(target, "canonical-gap original executable")
	if err != nil {
		t.Fatal(err)
	}
	originalDescriptor := readWindowsTestSecurityDescriptor(t, target)
	want, err := os.ReadFile(stage) //nolint:gosec // test-owned verified stage
	if err != nil {
		t.Fatal(err)
	}
	stageIdentity, err := inspectWindowsReplacementPath(stage, "canonical-gap verified stage")
	if err != nil {
		t.Fatal(err)
	}

	updater := windowsReplacementTestCommand(target, stage)
	updater.Env = append(updater.Env,
		windowsReplacementPauseEnv+"="+windowsReplacementPhaseStageRenameGap,
		windowsReplacementReadyEnv+"="+ready,
		windowsReplacementGoEnv+"="+proceed,
		windowsExpectedFailureEnv+"=rollback failed",
	)
	var updaterOutput bytes.Buffer
	updater.Stdout = &updaterOutput
	updater.Stderr = &updaterOutput
	if err := updater.Start(); err != nil {
		t.Fatal(err)
	}
	waitForWindowsTestPath(t, ready)

	attackerCanonical := appendTestExecutableMarker(t, testExecutable, "\nATTACKER_CANONICAL_SUBSTITUTE\n")
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
	if waitErr := updater.Wait(); waitErr != nil {
		_ = windows.CloseHandle(attackerHandle)
		t.Fatalf("canonical-substitute failure fixture failed: %v; output=%q", waitErr, updaterOutput.String())
	}
	t.Run("while hostile no-delete-share lock remains", func(t *testing.T) {
		assertWindowsFileBytes(t, target, attackerCanonical)
		assertWindowsPreparedRecoveryEvidence(
			t,
			target,
			originalIdentity,
			stageIdentity,
			1,
			original,
			originalDescriptor,
		)
		blockedStage := filepath.Join(directory, ".ssm.blocked-canonical-stage.exe")
		copyWindowsTestExecutable(t, testExecutable, blockedStage, []byte("\nBLOCKED_CANONICAL_UPDATE\n"))
		assertWindowsPreparedRecoveryBlocksCleanupAndUpdate(
			t,
			testExecutable,
			target,
			blockedStage,
			"recover incomplete Windows executable replacement",
		)
		assertWindowsPreparedRecoveryEvidence(
			t,
			target,
			originalIdentity,
			stageIdentity,
			1,
			original,
			originalDescriptor,
		)
		assertWindowsFileBytes(t, target, attackerCanonical)
	})

	if closeErr := windows.CloseHandle(attackerHandle); closeErr != nil {
		t.Fatalf("close attacker substitute handle: %v", closeErr)
	}
	t.Run("after hostile handle release", func(t *testing.T) {
		runWindowsRecoveryCleanup(t, testExecutable, target)
		assertWindowsRecoveredOriginal(
			t,
			target,
			originalIdentity,
			original,
			originalDescriptor,
		)
		assertWindowsFileBytes(t, stage, want)
	})
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
	setRestrictiveWindowsTestDACL(t, target)
	original, err := os.ReadFile(target) //nolint:gosec // test-owned mapped executable
	if err != nil {
		t.Fatal(err)
	}
	originalIdentity, err := inspectWindowsReplacementPath(target, "rollback-substitute original executable")
	if err != nil {
		t.Fatal(err)
	}
	originalDescriptor := readWindowsTestSecurityDescriptor(t, target)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nROLLBACK_SUBSTITUTE_STAGE\n"))
	stageIdentity, err := inspectWindowsReplacementPath(stage, "rollback-substitute verified stage")
	if err != nil {
		t.Fatal(err)
	}

	updater := windowsReplacementTestCommand(target, stage)
	updater.Env = append(updater.Env,
		windowsReplacementFailEnv+"=1",
		windowsReplacementPauseEnv+"="+windowsReplacementPhaseStageRenameGap,
		windowsReplacementReadyEnv+"="+ready,
		windowsReplacementGoEnv+"="+proceed,
		windowsExpectedFailureEnv+"=rollback failed",
	)
	var updaterOutput bytes.Buffer
	updater.Stdout = &updaterOutput
	updater.Stderr = &updaterOutput
	if err := updater.Start(); err != nil {
		t.Fatal(err)
	}
	waitForWindowsTestPath(t, ready)

	attackerCanonical := appendTestExecutableMarker(t, testExecutable, "\nATTACKER_ROLLBACK_SUBSTITUTE\n")
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
	if waitErr := updater.Wait(); waitErr != nil {
		_ = windows.CloseHandle(attackerHandle)
		t.Fatalf("rollback substitute fixture failed: %v; output=%q", waitErr, updaterOutput.String())
	}
	t.Run("while hostile no-delete-share lock remains", func(t *testing.T) {
		assertWindowsFileBytes(t, target, attackerCanonical)
		assertWindowsPreparedRecoveryEvidence(
			t,
			target,
			originalIdentity,
			stageIdentity,
			1,
			original,
			originalDescriptor,
		)
		blockedStage := filepath.Join(directory, ".ssm.blocked-rollback-stage.exe")
		copyWindowsTestExecutable(t, testExecutable, blockedStage, []byte("\nBLOCKED_ROLLBACK_UPDATE\n"))
		assertWindowsPreparedRecoveryBlocksCleanupAndUpdate(
			t,
			testExecutable,
			target,
			blockedStage,
			"recover incomplete Windows executable replacement",
		)
		assertWindowsPreparedRecoveryEvidence(
			t,
			target,
			originalIdentity,
			stageIdentity,
			1,
			original,
			originalDescriptor,
		)
		assertWindowsFileBytes(t, target, attackerCanonical)
	})

	if closeErr := windows.CloseHandle(attackerHandle); closeErr != nil {
		t.Fatalf("close rollback substitute handle: %v", closeErr)
	}
	t.Run("after hostile handle release", func(t *testing.T) {
		runWindowsRecoveryCleanup(t, testExecutable, target)
		assertWindowsRecoveredOriginal(
			t,
			target,
			originalIdentity,
			original,
			originalDescriptor,
		)
	})
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
			setRestrictiveWindowsTestDACL(t, target)
			original, err := os.ReadFile(target) //nolint:gosec // test-owned mapped executable
			if err != nil {
				t.Fatal(err)
			}
			originalIdentity, err := inspectWindowsReplacementPath(target, "late-link original executable")
			if err != nil {
				t.Fatal(err)
			}
			originalDescriptor := readWindowsTestSecurityDescriptor(t, target)
			copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nLATE_LINK_STAGE\n"))
			verified, err := os.ReadFile(stage) //nolint:gosec // test-owned verified stage
			if err != nil {
				t.Fatal(err)
			}
			stageIdentity, err := inspectWindowsReplacementPath(stage, "late-link verified stage")
			if err != nil {
				t.Fatal(err)
			}

			updater := windowsReplacementTestCommand(target, stage)
			updater.Env = append(updater.Env,
				windowsReplacementPauseEnv+"="+test.phase,
				windowsReplacementReadyEnv+"="+ready,
				windowsReplacementGoEnv+"="+proceed,
				windowsExpectedFailureEnv+"=hard links",
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
				t.Fatalf("late hard-link fixture could not create its adversarial link: %v; updater_error=%v output=%q", linkErr, waitErr, updaterOutput.String())
			}
			if waitErr != nil {
				t.Fatalf("late hard-link failure fixture failed: %v; output=%q", waitErr, updaterOutput.String())
			}
			if test.name == "target" {
				if _, err := os.Stat(target); !os.IsNotExist(err) {
					t.Fatalf("late target hard link left an unexpected canonical target: %v", err)
				}
				assertWindowsFileBytes(t, alias, original)
			} else {
				assertWindowsFileBytes(t, target, verified)
				assertWindowsFileBytes(t, alias, verified)
			}
			originalLinks := uint32(1)
			if test.name == "target" {
				originalLinks = 2
			}
			t.Run("while hostile hard link remains", func(t *testing.T) {
				assertWindowsPreparedRecoveryEvidence(
					t,
					target,
					originalIdentity,
					stageIdentity,
					originalLinks,
					original,
					originalDescriptor,
				)
				blockedStage := filepath.Join(directory, ".ssm.blocked-late-link-stage.exe")
				copyWindowsTestExecutable(t, testExecutable, blockedStage, []byte("\nBLOCKED_LATE_LINK_UPDATE\n"))
				assertWindowsPreparedRecoveryBlocksCleanupAndUpdate(
					t,
					testExecutable,
					target,
					blockedStage,
					"hard links",
				)
				assertWindowsPreparedRecoveryEvidence(
					t,
					target,
					originalIdentity,
					stageIdentity,
					originalLinks,
					original,
					originalDescriptor,
				)
				if test.name == "target" {
					if _, err := os.Stat(target); !os.IsNotExist(err) {
						t.Fatalf("blocked target-link recovery created an unexpected canonical target: %v", err)
					}
				} else {
					assertWindowsFileBytes(t, target, verified)
				}
			})

			if err := os.Remove(alias); err != nil {
				t.Fatalf("release late hard-link fixture: %v", err)
			}
			t.Run("after hostile hard link removal", func(t *testing.T) {
				runWindowsRecoveryCleanup(t, testExecutable, target)
				assertWindowsRecoveredOriginal(
					t,
					target,
					originalIdentity,
					original,
					originalDescriptor,
				)
			})
		})
	}
}

func testWindowsPreparedRecoveryRejectsDescriptorMutation(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.descriptor-mutation-stage.exe")
	stageAlias := filepath.Join(directory, "descriptor-mutation-stage-alias.exe")
	ready := filepath.Join(directory, "descriptor-mutation.ready")
	proceed := filepath.Join(directory, "descriptor-mutation.proceed")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	setRestrictiveWindowsTestDACL(t, target)
	original, err := os.ReadFile(target) //nolint:gosec // test-owned mapped executable
	if err != nil {
		t.Fatal(err)
	}
	originalIdentity, err := inspectWindowsReplacementPath(
		target,
		"descriptor-mutation original executable",
	)
	if err != nil {
		t.Fatal(err)
	}
	originalDescriptor := readWindowsTestSecurityDescriptor(t, target)
	copyWindowsTestExecutable(
		t,
		testExecutable,
		stage,
		[]byte("\nDESCRIPTOR_MUTATION_STAGE\n"),
	)
	stageIdentity, err := inspectWindowsReplacementPath(
		stage,
		"descriptor-mutation verified stage",
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := os.ReadFile(stage) //nolint:gosec // test-owned verified stage
	if err != nil {
		t.Fatal(err)
	}

	updater := windowsReplacementTestCommand(target, stage)
	updater.Env = append(updater.Env,
		windowsOrdinaryUserEnv+"=1",
		windowsReplacementPauseEnv+"="+windowsReplacementPhaseStageRenameGap,
		windowsReplacementReadyEnv+"="+ready,
		windowsReplacementGoEnv+"="+proceed,
		windowsExpectedFailureEnv+"=hard links",
	)
	var updaterOutput bytes.Buffer
	updater.Stdout = &updaterOutput
	updater.Stderr = &updaterOutput
	if err := updater.Start(); err != nil {
		t.Fatal(err)
	}
	waitForWindowsTestPath(t, ready)
	linkErr := os.Link(stage, stageAlias)
	if err := os.WriteFile(proceed, []byte("continue"), 0o600); err != nil { //nolint:gosec // test-owned synchronization fixture
		t.Fatal(err)
	}
	waitErr := updater.Wait()
	if linkErr != nil {
		t.Fatalf(
			"create descriptor-mutation adversarial link: %v; updater_error=%v output=%q",
			linkErr,
			waitErr,
			updaterOutput.String(),
		)
	}
	if waitErr != nil {
		t.Fatalf("prepare descriptor-mutation recovery fixture: %v; output=%q", waitErr, updaterOutput.String())
	}
	assertWindowsPreparedRecoveryEvidence(
		t,
		target,
		originalIdentity,
		stageIdentity,
		1,
		original,
		originalDescriptor,
	)
	assertWindowsFileBytes(t, target, verified)
	if err := os.Remove(stageAlias); err != nil {
		t.Fatalf("release descriptor-mutation hard link: %v", err)
	}

	backup := windowsReplacementBackup(target)
	beforeMutationIdentity, err := inspectWindowsReplacementPath(
		backup,
		"rollback image before descriptor mutation",
	)
	if err != nil {
		t.Fatal(err)
	}
	setWritableWindowsTestDACL(t, backup, true)
	afterMutationIdentity, err := inspectWindowsReplacementPath(
		backup,
		"rollback image after descriptor mutation",
	)
	if err != nil {
		t.Fatal(err)
	}
	if afterMutationIdentity != beforeMutationIdentity {
		t.Fatalf(
			"descriptor mutation changed rollback File ID: got %+v, want %+v",
			afterMutationIdentity,
			beforeMutationIdentity,
		)
	}

	cleanup := exec.Command(
		testExecutable,
		"-test.run=^TestWindowsCleanupPreviousExecutableChildProcess$",
		"-test.count=1",
	) //nolint:gosec // fixed test-owned executable and arguments
	cleanup.Env = append(os.Environ(),
		windowsCleanupChildEnv+"=1",
		windowsCleanupTargetEnv+"="+target,
		windowsExpectedFailureEnv+"=security descriptor contract changed",
	)
	if output, err := cleanup.CombinedOutput(); err != nil {
		t.Fatalf("descriptor-mutation recovery fixture failed: %v; output=%q", err, output)
	}
	assertWindowsFileBytes(t, backup, original)
	assertWindowsFileBytes(t, target, verified)
	if _, err := os.Stat(windowsReplacementRecord(target)); err != nil {
		t.Fatalf("descriptor mismatch did not preserve authenticated recovery state: %v", err)
	}
	if gotIdentity, err := inspectWindowsReplacementPath(
		backup,
		"retained descriptor-mutated rollback image",
	); err != nil || gotIdentity != originalIdentity {
		t.Fatalf(
			"descriptor mismatch changed retained rollback identity: got %+v err=%v, want %+v",
			gotIdentity,
			err,
			originalIdentity,
		)
	}

	setRestrictiveWindowsTestDACL(t, backup)
	runWindowsRecoveryCleanup(t, testExecutable, target)
	assertWindowsRecoveredOriginal(
		t,
		target,
		originalIdentity,
		original,
		originalDescriptor,
	)
}

func testWindowsRecoveryRejectsSameIdentityContentMutation(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, alreadyCanonical := range []bool{false, true} {
		name := "prepared rollback image"
		if alreadyCanonical {
			name = "already canonical rollback image"
		}
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "ssm.exe")
			stage := filepath.Join(directory, ".ssm.content-mutation-stage.exe")
			copyWindowsTestExecutable(t, testExecutable, target, nil)
			copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nCONTENT_MUTATION_STAGE\n"))
			original, err := os.ReadFile(target) //nolint:gosec // test-owned mapped executable
			if err != nil {
				t.Fatal(err)
			}
			originalIdentity, err := inspectWindowsReplacementPath(
				target,
				"content-mutation original executable",
			)
			if err != nil {
				t.Fatal(err)
			}
			originalDescriptor := readWindowsTestSecurityDescriptor(t, target)

			command := windowsReplacementTestCommand(target, stage)
			command.Env = append(command.Env,
				windowsReplacementFailEnv+"=1",
				windowsRollbackFailEnv+"=1",
				windowsExpectedFailureEnv+"=rollback failed",
			)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("prepare content-mutation recovery fixture: %v; output=%q", err, output)
			}

			backup := windowsReplacementBackup(target)
			mutatedPath := backup
			if alreadyCanonical {
				if err := os.Rename(backup, target); err != nil {
					t.Fatalf("place rollback image at canonical path: %v", err)
				}
				mutatedPath = target
			}
			beforeMutation, err := inspectWindowsReplacementPath(
				mutatedPath,
				"rollback image before content mutation",
			)
			if err != nil {
				t.Fatal(err)
			}
			mutated := append([]byte(nil), original...)
			mutated[len(mutated)-1] ^= 0xff
			writeWindowsTestFileInPlace(t, mutatedPath, mutated)
			afterMutation, err := inspectWindowsReplacementPath(
				mutatedPath,
				"rollback image after content mutation",
			)
			if err != nil {
				t.Fatal(err)
			}
			if afterMutation != beforeMutation || afterMutation != originalIdentity {
				t.Fatalf(
					"content mutation changed strong file identity: got %+v, want %+v",
					afterMutation,
					originalIdentity,
				)
			}

			cleanup := exec.Command(
				testExecutable,
				"-test.run=^TestWindowsCleanupPreviousExecutableChildProcess$",
				"-test.count=1",
			) //nolint:gosec // fixed test-owned executable and arguments
			cleanup.Env = append(os.Environ(),
				windowsCleanupChildEnv+"=1",
				windowsCleanupTargetEnv+"="+target,
				windowsExpectedFailureEnv+"=digest does not match authenticated bytes",
			)
			if output, err := cleanup.CombinedOutput(); err != nil {
				t.Fatalf("content-mutation recovery fixture failed: %v; output=%q", err, output)
			}
			assertWindowsFileBytes(t, mutatedPath, mutated)
			if _, err := os.Stat(windowsReplacementRecord(target)); err != nil {
				t.Fatalf("content mismatch lost authenticated recovery record: %v", err)
			}

			writeWindowsTestFileInPlace(t, mutatedPath, original)
			restoredIdentity, err := inspectWindowsReplacementPath(
				mutatedPath,
				"rollback image after exact content restoration",
			)
			if err != nil || restoredIdentity != originalIdentity {
				t.Fatalf(
					"exact content restoration identity = %+v err=%v, want %+v",
					restoredIdentity,
					err,
					originalIdentity,
				)
			}
			runWindowsRecoveryCleanup(t, testExecutable, target)
			assertWindowsRecoveredOriginal(
				t,
				target,
				originalIdentity,
				original,
				originalDescriptor,
			)
		})
	}
}

func testWindowsCompletedCleanupRejectsSameIdentityContentMutation(t *testing.T) {
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.completed-content-stage.exe")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nCOMPLETED_CONTENT_STAGE\n"))
	original, err := os.ReadFile(target) //nolint:gosec // test-owned executable fixture
	if err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(stage) //nolint:gosec // test-owned executable fixture
	if err != nil {
		t.Fatal(err)
	}

	command := windowsReplacementTestCommand(target, stage)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("prepare completed content-mutation fixture: %v; output=%q", err, output)
	}
	backup := windowsReplacementBackup(target)
	backupIdentity, err := inspectWindowsReplacementPath(
		backup,
		"completed rollback image before content mutation",
	)
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), original...)
	mutated[len(mutated)-1] ^= 0xff
	writeWindowsTestFileInPlace(t, backup, mutated)
	mutatedIdentity, err := inspectWindowsReplacementPath(
		backup,
		"completed rollback image after content mutation",
	)
	if err != nil || mutatedIdentity != backupIdentity {
		t.Fatalf(
			"completed rollback content mutation identity = %+v err=%v, want %+v",
			mutatedIdentity,
			err,
			backupIdentity,
		)
	}

	cleanup := exec.Command(
		testExecutable,
		"-test.run=^TestWindowsCleanupPreviousExecutableChildProcess$",
		"-test.count=1",
	) //nolint:gosec // fixed test-owned executable and arguments
	cleanup.Env = append(os.Environ(),
		windowsCleanupChildEnv+"=1",
		windowsCleanupTargetEnv+"="+target,
		windowsExpectedFailureEnv+"=digest does not match authenticated bytes",
	)
	if output, err := cleanup.CombinedOutput(); err != nil {
		t.Fatalf("completed content-mutation cleanup fixture failed: %v; output=%q", err, output)
	}
	assertWindowsFileBytes(t, backup, mutated)
	assertWindowsFileBytes(t, target, installed)
	if _, err := os.Stat(windowsReplacementRecord(target)); err != nil {
		t.Fatalf("completed content mismatch lost authenticated recovery record: %v", err)
	}

	writeWindowsTestFileInPlace(t, backup, original)
	restoredIdentity, err := inspectWindowsReplacementPath(
		backup,
		"completed rollback image after exact content restoration",
	)
	if err != nil || restoredIdentity != backupIdentity {
		t.Fatalf(
			"completed rollback exact restoration identity = %+v err=%v, want %+v",
			restoredIdentity,
			err,
			backupIdentity,
		)
	}
	runWindowsRecoveryCleanup(t, testExecutable, target)
	assertWindowsFileBytes(t, target, installed)
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("exactly restored completed rollback image was not cleaned: %v", err)
	}
	if _, err := os.Stat(windowsReplacementRecord(target)); !os.IsNotExist(err) {
		t.Fatalf("exactly restored completed rollback record was not cleaned: %v", err)
	}
}

func testWindowsPreparedFullRecoveryRejectsRMControlMutation(t *testing.T) {
	const (
		expectedRMControl = byte(42)
		mutatedRMControl  = byte(43)
	)
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()

	probeTarget := filepath.Join(directory, "rm-control-probe-target.exe")
	probeStage := filepath.Join(directory, "rm-control-probe-stage.exe")
	copyWindowsTestExecutable(t, testExecutable, probeTarget, nil)
	copyWindowsTestExecutable(t, testExecutable, probeStage, nil)
	if available, reason := trySetWindowsTestRMControl(t, probeTarget, expectedRMControl); !available {
		t.Skipf("host cannot persist file RM control for the complete descriptor tier: %s", reason)
	}
	if available, reason := trySetWindowsTestRMControl(t, probeStage, mutatedRMControl); !available {
		t.Skipf("host cannot persist a different fresh-stage RM control value: %s", reason)
	}
	probeState, err := prepareWindowsReplacementSecurity(probeStage, probeTarget)
	if err != nil {
		t.Skipf("host cannot preserve file RM control through the complete descriptor tier: %v", err)
	}
	if !probeState.tier.full {
		if err := probeState.close(); err != nil {
			t.Fatalf("close ordinary RM-control capability probe: %v", err)
		}
		t.Skip("host selected the ordinary descriptor tier for the RM-control capability probe")
	}
	if err := probeState.close(); err != nil {
		t.Fatalf("close complete RM-control capability probe: %v", err)
	}

	target := filepath.Join(directory, "ssm.exe")
	stage := filepath.Join(directory, ".ssm.rm-control-stage.exe")
	stageAlias := filepath.Join(directory, "rm-control-stage-alias.exe")
	ready := filepath.Join(directory, "rm-control.ready")
	proceed := filepath.Join(directory, "rm-control.proceed")
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	copyWindowsTestExecutable(
		t,
		testExecutable,
		stage,
		[]byte("\nRM_CONTROL_MUTATION_STAGE\n"),
	)
	if available, reason := trySetWindowsTestRMControl(t, target, expectedRMControl); !available {
		t.Fatalf("RM-control capability became unavailable for target: %s", reason)
	}
	if available, reason := trySetWindowsTestRMControl(t, stage, mutatedRMControl); !available {
		t.Fatalf("RM-control capability became unavailable for fresh stage: %s", reason)
	}
	stageDescriptor, available, reason := tryReadWindowsTestCompleteSecurityDescriptor(t, stage)
	if !available {
		t.Fatalf("read fresh-stage complete descriptor: %s", reason)
	}
	if stageDescriptor.control&windows.SE_RM_CONTROL_VALID == 0 ||
		stageDescriptor.rmControl != mutatedRMControl {
		t.Fatalf(
			"fresh-stage RM control = present:%t value:%d, want present:true value:%d",
			stageDescriptor.control&windows.SE_RM_CONTROL_VALID != 0,
			stageDescriptor.rmControl,
			mutatedRMControl,
		)
	}
	original, err := os.ReadFile(target) //nolint:gosec // test-owned mapped executable
	if err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(stage) //nolint:gosec // test-owned verified stage
	if err != nil {
		t.Fatal(err)
	}
	originalIdentity, err := inspectWindowsReplacementPath(
		target,
		"RM-control original executable",
	)
	if err != nil {
		t.Fatal(err)
	}
	stageIdentity, err := inspectWindowsReplacementPath(
		stage,
		"RM-control verified stage",
	)
	if err != nil {
		t.Fatal(err)
	}
	originalDescriptor, available, reason :=
		tryReadWindowsTestCompleteSecurityDescriptor(t, target)
	if !available {
		t.Fatalf("complete descriptor capability became unavailable: %s", reason)
	}
	if originalDescriptor.control&windows.SE_RM_CONTROL_VALID == 0 ||
		originalDescriptor.rmControl != expectedRMControl {
		t.Fatalf(
			"original RM control = present:%t value:%d, want present:true value:%d",
			originalDescriptor.control&windows.SE_RM_CONTROL_VALID != 0,
			originalDescriptor.rmControl,
			expectedRMControl,
		)
	}

	updater := windowsReplacementTestCommand(target, stage)
	updater.Env = append(updater.Env,
		windowsReplacementPauseEnv+"="+windowsReplacementPhaseStageRenameGap,
		windowsReplacementReadyEnv+"="+ready,
		windowsReplacementGoEnv+"="+proceed,
		windowsExpectedFailureEnv+"=hard links",
	)
	var updaterOutput bytes.Buffer
	updater.Stdout = &updaterOutput
	updater.Stderr = &updaterOutput
	if err := updater.Start(); err != nil {
		t.Fatal(err)
	}
	waitForWindowsTestPath(t, ready)
	linkErr := os.Link(stage, stageAlias)
	if err := os.WriteFile(proceed, []byte("continue"), 0o600); err != nil { //nolint:gosec // test-owned synchronization fixture
		t.Fatal(err)
	}
	waitErr := updater.Wait()
	if linkErr != nil {
		t.Fatalf(
			"create RM-control recovery adversarial link: %v; updater_error=%v output=%q",
			linkErr,
			waitErr,
			updaterOutput.String(),
		)
	}
	if waitErr != nil {
		t.Fatalf("prepare RM-control recovery fixture: %v; output=%q", waitErr, updaterOutput.String())
	}
	if err := os.Remove(stageAlias); err != nil {
		t.Fatalf("release RM-control recovery hard link: %v", err)
	}

	backup := windowsReplacementBackup(target)
	assertWindowsFileBytes(t, backup, original)
	assertWindowsFileBytes(t, target, installed)
	backupIdentity, err := inspectWindowsReplacementPath(
		backup,
		"RM-control rollback image before mutation",
	)
	if err != nil {
		t.Fatal(err)
	}
	if backupIdentity != originalIdentity {
		t.Fatalf(
			"RM-control rollback identity = %+v, want %+v",
			backupIdentity,
			originalIdentity,
		)
	}
	recordPath := windowsReplacementRecord(target)
	recordBytes, err := os.ReadFile(recordPath) //nolint:gosec // test-owned authenticated recovery fixture
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeWindowsReplacementRecord(recordBytes)
	if err != nil {
		t.Fatal(err)
	}
	if record.state != windowsReplacementRecordPrepared ||
		record.original != originalIdentity ||
		record.installed != stageIdentity {
		t.Fatalf("RM-control prepared recovery record = %#v", record)
	}
	if record.securityBinding.metadata&windowsSecurityBindingTierMask != windowsSecurityBindingFull {
		t.Fatalf(
			"RM-control recovery binding tier = %d, want full",
			record.securityBinding.metadata&windowsSecurityBindingTierMask,
		)
	}
	assertWindowsControlFileSecurity(t, recordPath)

	if available, reason := trySetWindowsTestRMControl(t, backup, mutatedRMControl); !available {
		t.Fatalf("mutate rollback RM control: %s", reason)
	}
	mutatedIdentity, err := inspectWindowsReplacementPath(
		backup,
		"RM-control rollback image after mutation",
	)
	if err != nil {
		t.Fatal(err)
	}
	if mutatedIdentity != backupIdentity {
		t.Fatalf(
			"RM-control mutation changed rollback File ID: got %+v, want %+v",
			mutatedIdentity,
			backupIdentity,
		)
	}

	cleanup := exec.Command(
		testExecutable,
		"-test.run=^TestWindowsCleanupPreviousExecutableChildProcess$",
		"-test.count=1",
	) //nolint:gosec // fixed test-owned executable and arguments
	cleanup.Env = append(os.Environ(),
		windowsCleanupChildEnv+"=1",
		windowsCleanupTargetEnv+"="+target,
		windowsExpectedFailureEnv+"=security descriptor contract changed",
	)
	if output, err := cleanup.CombinedOutput(); err != nil {
		t.Fatalf("RM-control mutation recovery fixture failed: %v; output=%q", err, output)
	}
	assertWindowsFileBytes(t, backup, original)
	assertWindowsFileBytes(t, target, installed)
	if _, err := os.Stat(recordPath); err != nil {
		t.Fatalf("RM-control mismatch did not retain authenticated recovery evidence: %v", err)
	}
	retainedIdentity, err := inspectWindowsReplacementPath(
		backup,
		"retained RM-control-mutated rollback image",
	)
	if err != nil || retainedIdentity != originalIdentity {
		t.Fatalf(
			"RM-control mismatch changed retained rollback identity: got %+v err=%v, want %+v",
			retainedIdentity,
			err,
			originalIdentity,
		)
	}

	if available, reason := trySetWindowsTestRMControl(t, backup, expectedRMControl); !available {
		t.Fatalf("restore exact rollback RM control: %s", reason)
	}
	runWindowsRecoveryCleanup(t, testExecutable, target)
	assertWindowsFileBytes(t, target, original)
	recoveredIdentity, err := inspectWindowsReplacementPath(
		target,
		"RM-control recovered executable",
	)
	if err != nil || recoveredIdentity != originalIdentity {
		t.Fatalf(
			"RM-control recovered identity = %+v err=%v, want %+v",
			recoveredIdentity,
			err,
			originalIdentity,
		)
	}
	recoveredDescriptor, available, reason :=
		tryReadWindowsTestCompleteSecurityDescriptor(t, target)
	if !available {
		t.Fatalf("read recovered complete descriptor: %s", reason)
	}
	if recoveredDescriptor != originalDescriptor {
		t.Fatalf(
			"recovered complete descriptor = %#v, want %#v",
			recoveredDescriptor,
			originalDescriptor,
		)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("successful RM-control recovery retained rollback image: %v", err)
	}
	if _, err := os.Stat(recordPath); !os.IsNotExist(err) {
		t.Fatalf("successful RM-control recovery retained ownership state: %v", err)
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
	stage := filepath.Join(directory, ".ssm.untrusted-lock-stage.exe")
	lockPath := windowsReplacementLock(target)
	copyWindowsTestExecutable(t, testExecutable, target, nil)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nUNTRUSTED_LOCK_STAGE\n"))
	original, err := os.ReadFile(target) //nolint:gosec // test-owned replacement fixture
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, []byte("attacker-controlled lock"), 0o666); err != nil { //nolint:gosec // intentionally inherited attacker-forgeable test lock
		t.Fatal(err)
	}
	setWritableWindowsTestDACL(t, lockPath, false)

	err = cleanupPreviousExecutable(target)
	if err != nil {
		t.Fatalf("ordinary recovery discovery trusted an unauthenticated lock: %v", err)
	}

	err = replaceExecutable(stage, target, windowsTestFileDigest(t, stage))
	if err == nil || !strings.Contains(err.Error(), "security policy") {
		t.Fatalf("inherited update lock error = %v, want security-policy rejection", err)
	}
	assertWindowsFileBytes(t, target, original)
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
		if err := replaceExecutable(stageTarget, targetLink, windowsTestFileDigest(t, stageTarget)); err == nil ||
			!strings.Contains(err.Error(), "reparse point") && !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("target reparse point error = %v", err)
		}
		if err := replaceExecutable(stage, target, windowsTestFileDigest(t, stageTarget)); err == nil ||
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
	setRestrictiveWindowsTestDACL(t, target)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nROLLBACK_FAILURE_STAGE\n"))
	original, err := os.ReadFile(target) //nolint:gosec // test-owned executable fixture
	if err != nil {
		t.Fatal(err)
	}
	originalIdentity, err := inspectWindowsReplacementPath(target, "rollback-failure original executable")
	if err != nil {
		t.Fatal(err)
	}
	originalDescriptor := readWindowsTestSecurityDescriptor(t, target)
	stageIdentity, err := inspectWindowsReplacementPath(stage, "rollback-failure verified stage")
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

	assertWindowsPreparedRecoveryEvidence(
		t,
		target,
		originalIdentity,
		stageIdentity,
		1,
		original,
		originalDescriptor,
	)
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("rollback failure reported an unexpected canonical target: %v", err)
	}

	runWindowsRecoveryCleanup(t, testExecutable, target)
	assertWindowsRecoveredOriginal(
		t,
		target,
		originalIdentity,
		original,
		originalDescriptor,
	)
}

func TestWindowsReplacementChildProcess(t *testing.T) {
	if os.Getenv(windowsReplacementChildEnv) != "1" {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if target := os.Getenv(windowsReplacementTargetEnv); target != "" {
		executable = target
	}
	stage := os.Getenv(windowsReplacementStageEnv)
	stageDigest := windowsTestFileDigest(t, stage)
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
		originalCompleteApply := applyWindowsCompleteSecurity
		fullSelections := 0
		fullCaptures := 0
		fullApplyCalls := 0
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
				return originalCapture(handle, windowsOrdinarySecurityInformation)
			}
			ordinaryCaptures++
			return originalCapture(handle, information)
		}
		applyWindowsCompleteSecurity = func(string, *windows.SECURITY_DESCRIPTOR) error {
			fullApplyCalls++
			return errWindowsRMControlUnavailable
		}
		defer func() {
			beginWindowsReplacementSecurityPrivileges = originalBegin
			captureWindowsReplacementDescriptor = originalCapture
			applyWindowsCompleteSecurity = originalCompleteApply
		}()

		err = replaceExecutable(stage, executable, stageDigest)
		if err != nil {
			t.Fatalf("replacement did not fall back from optional complete descriptor capture: %v", err)
		}
		if fullSelections != 1 {
			t.Fatalf("complete descriptor tier selections = %d, want 1", fullSelections)
		}
		if fullCaptures != 1 {
			t.Fatalf("complete descriptor capture calls = %d, want 1", fullCaptures)
		}
		if fullApplyCalls != 1 {
			t.Fatalf("complete descriptor application calls = %d, want 1 capability probe", fullApplyCalls)
		}
		if ordinaryCaptures == 0 {
			t.Fatal("ordinary descriptor capture was not reached after denied complete capture")
		}
		return
	}
	if pause := os.Getenv(windowsReplacementPauseEnv); pause != "" ||
		os.Getenv(windowsSubstituteStageEnv) != "" ||
		os.Getenv(windowsMutateStageEnv) != "" {
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
			if phase == os.Getenv(windowsMutateStageEnv) {
				file, err := os.OpenFile(stage, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // test-owned race fixture
				if err != nil {
					return fmt.Errorf("open verified stage for in-place mutation: %w", err)
				}
				if _, err := file.Write([]byte("\nIN_PLACE_MUTATION\n")); err != nil {
					_ = file.Close()
					return fmt.Errorf("mutate verified stage in place: %w", err)
				}
				if err := file.Close(); err != nil {
					return fmt.Errorf("close mutated verified stage: %w", err)
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
		err = replaceExecutable(stage, executable, stageDigest)
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

		err = replaceExecutable(stage, executable, stageDigest)
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
	err = replaceExecutable(stage, executable, stageDigest)
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

func assertWindowsPreparedRecoveryEvidence(
	t *testing.T,
	target string,
	originalIdentity,
	stageIdentity windowsFileIdentity,
	originalLinks uint32,
	original []byte,
	originalDescriptor windowsTestSecurityDescriptor,
) {
	t.Helper()
	backup := windowsReplacementBackup(target)
	assertWindowsFileBytes(t, backup, original)
	backupHandle, err := openWindowsReplacementFile(backup, 0)
	if err != nil {
		t.Fatal(err)
	}
	gotIdentity, gotLinks, inspectErr := inspectWindowsReplacementHandleObject(
		backupHandle,
		"retained Windows rollback image",
	)
	closeErr := windows.CloseHandle(backupHandle)
	if inspectErr != nil {
		t.Fatal(inspectErr)
	}
	if closeErr != nil {
		t.Fatalf("close retained Windows rollback image: %v", closeErr)
	}
	if gotIdentity != originalIdentity {
		t.Fatalf("retained Windows rollback identity = %+v, want %+v", gotIdentity, originalIdentity)
	}
	if gotLinks != originalLinks {
		t.Fatalf("retained Windows rollback links = %d, want %d", gotLinks, originalLinks)
	}
	gotDescriptor := readWindowsTestSecurityDescriptor(t, backup)
	if gotDescriptor != originalDescriptor {
		t.Fatalf(
			"retained Windows rollback descriptor = %#v, want %#v",
			gotDescriptor,
			originalDescriptor,
		)
	}
	recordPath := windowsReplacementRecord(target)
	data, err := os.ReadFile(recordPath) //nolint:gosec // test-owned authenticated recovery fixture
	if err != nil {
		t.Fatalf("read retained Windows rollback ownership record: %v", err)
	}
	record, err := decodeWindowsReplacementRecord(data)
	if err != nil {
		t.Fatalf("decode retained Windows rollback ownership record: %v", err)
	}
	if record.state != windowsReplacementRecordPrepared {
		t.Fatalf("retained Windows rollback state = %d, want prepared", record.state)
	}
	if record.original != originalIdentity {
		t.Fatalf("retained Windows rollback original identity = %+v, want %+v", record.original, originalIdentity)
	}
	if record.installed != stageIdentity {
		t.Fatalf("retained Windows rollback stage identity = %+v, want %+v", record.installed, stageIdentity)
	}
	if wantDigest := sha256.Sum256(original); record.rollbackDigest != wantDigest {
		t.Fatalf("retained Windows rollback digest = %x, want %x", record.rollbackDigest, wantDigest)
	}
	assertWindowsControlFileSecurity(t, recordPath)
}

func assertWindowsPreparedRecoveryBlocksCleanupAndUpdate(
	t *testing.T,
	runner,
	target,
	stage,
	expected string,
) {
	t.Helper()
	cleanup := exec.Command(runner, "-test.run=^TestWindowsCleanupPreviousExecutableChildProcess$", "-test.count=1") //nolint:gosec // fixed test-owned executable and arguments
	cleanup.Env = append(os.Environ(),
		windowsCleanupChildEnv+"=1",
		windowsCleanupTargetEnv+"="+target,
		windowsExpectedFailureEnv+"="+expected,
	)
	if output, err := cleanup.CombinedOutput(); err != nil {
		t.Fatalf("blocked Windows recovery cleanup fixture failed: %v; output=%q", err, output)
	}

	wantStage, err := os.ReadFile(stage) //nolint:gosec // test-owned verified stage
	if err != nil {
		t.Fatal(err)
	}
	update := exec.Command(runner, "-test.run=^TestWindowsReplacementChildProcess$", "-test.count=1") //nolint:gosec // fixed test-owned executable and arguments
	update.Env = append(os.Environ(),
		windowsReplacementChildEnv+"=1",
		windowsReplacementTargetEnv+"="+target,
		windowsReplacementStageEnv+"="+stage,
		windowsExpectedFailureEnv+"=clean previous Windows executable",
	)
	if output, err := update.CombinedOutput(); err != nil {
		t.Fatalf("blocked Windows recovery update fixture failed: %v; output=%q", err, output)
	}
	assertWindowsFileBytes(t, stage, wantStage)
}

func runWindowsRecoveryCleanup(t *testing.T, runner, target string) {
	t.Helper()
	cleanup := exec.Command(runner, "-test.run=^TestWindowsCleanupPreviousExecutableChildProcess$", "-test.count=1") //nolint:gosec // fixed test-owned executable and arguments
	cleanup.Env = append(os.Environ(),
		windowsCleanupChildEnv+"=1",
		windowsCleanupTargetEnv+"="+target,
	)
	if output, err := cleanup.CombinedOutput(); err != nil {
		t.Fatalf("Windows recovery cleanup failed: %v; output=%q", err, output)
	}
}

func assertWindowsRecoveredOriginal(
	t *testing.T,
	target string,
	originalIdentity windowsFileIdentity,
	original []byte,
	originalDescriptor windowsTestSecurityDescriptor,
) {
	t.Helper()
	assertWindowsFileBytes(t, target, original)
	gotIdentity, err := inspectWindowsReplacementPath(target, "recovered Windows executable")
	if err != nil {
		t.Fatal(err)
	}
	if gotIdentity != originalIdentity {
		t.Fatalf("recovered Windows executable identity = %+v, want %+v", gotIdentity, originalIdentity)
	}
	gotDescriptor := readWindowsTestSecurityDescriptor(t, target)
	if gotDescriptor != originalDescriptor {
		t.Fatalf("recovered Windows executable descriptor = %#v, want %#v", gotDescriptor, originalDescriptor)
	}
	if _, err := os.Stat(windowsReplacementBackup(target)); !os.IsNotExist(err) {
		t.Fatalf("successful Windows recovery retained rollback image: %v", err)
	}
	if _, err := os.Stat(windowsReplacementRecord(target)); !os.IsNotExist(err) {
		t.Fatalf("successful Windows recovery retained ownership state: %v", err)
	}
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

func windowsTestFileDigest(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test-owned executable fixture
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(data)
}

func writeWindowsTestFileInPlace(t *testing.T, path string, data []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0) //nolint:gosec // test-owned mutation fixture
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func appendTestExecutableMarker(t *testing.T, source, marker string) []byte {
	t.Helper()
	data, err := os.ReadFile(source) //nolint:gosec // source is the running test executable
	if err != nil {
		t.Fatal(err)
	}
	return append(data, []byte(marker)...)
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
	sddl      string
	control   windows.SECURITY_DESCRIPTOR_CONTROL
	rmControl byte
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

func trySetWindowsTestRMControl(
	t *testing.T,
	path string,
	value byte,
) (bool, string) {
	t.Helper()
	scope, available, err := beginWindowsReplacementPrivileges()
	if err != nil {
		t.Fatalf("enable test RM-control privileges: %v", err)
	}
	if !available {
		return false, "current token lacks the complete descriptor privileges"
	}
	defer func() {
		if err := scope.close(); err != nil {
			t.Fatalf("restore test RM-control privileges: %v", err)
		}
	}()

	handle, err := openWindowsReplacementFile(
		path,
		windows.READ_CONTROL|windows.ACCESS_SYSTEM_SECURITY,
	)
	if err != nil {
		if isWindowsCompleteSecurityUnavailable(err) {
			return false, fmt.Sprintf("open complete descriptor for RM control: %v", err)
		}
		t.Fatalf("open complete descriptor for RM control: %v", err)
	}
	defer func() {
		if err := windows.CloseHandle(handle); err != nil {
			t.Fatalf("close RM-control test file: %v", err)
		}
	}()
	descriptor, err := captureWindowsSecurityDescriptor(
		handle,
		windowsFullSecurityInformation,
	)
	if err != nil {
		if isWindowsCompleteSecurityUnavailable(err) {
			return false, fmt.Sprintf("capture complete descriptor for RM control: %v", err)
		}
		t.Fatalf("capture complete descriptor for RM control: %v", err)
	}
	defer func() {
		if err := descriptor.close(); err != nil {
			t.Fatalf("free RM-control test descriptor: %v", err)
		}
	}()
	descriptor.descriptor.SetRMControl(value)
	if err := validateWindowsSecurityDescriptor(descriptor.descriptor); err != nil {
		t.Fatalf("set test RM control in complete descriptor: %v", err)
	}
	if callErr := applyWindowsCompleteSecurityDescriptor(path, descriptor.descriptor); callErr != nil {
		if isWindowsCompleteSecurityUnavailable(callErr) ||
			errors.Is(callErr, windows.ERROR_SHARING_VIOLATION) {
			return false, fmt.Sprintf("persist complete descriptor RM control: %v", callErr)
		}
		t.Fatalf("persist complete descriptor RM control: %v", callErr)
	}

	got, err := captureWindowsSecurityDescriptor(
		handle,
		windowsFullSecurityInformation,
	)
	if err != nil {
		t.Fatalf("recapture complete descriptor RM control: %v", err)
	}
	defer func() {
		if err := got.close(); err != nil {
			t.Fatalf("free recaptured RM-control test descriptor: %v", err)
		}
	}()
	control, _, err := got.descriptor.Control()
	if err != nil {
		t.Fatalf("read recaptured RM-control descriptor control: %v", err)
	}
	if control&windows.SE_RM_CONTROL_VALID == 0 {
		return false, "filesystem did not retain SE_RM_CONTROL_VALID"
	}
	gotValue, err := got.descriptor.RMControl()
	if err != nil {
		t.Fatalf("read recaptured RM-control byte: %v", err)
	}
	if gotValue != value {
		return false, fmt.Sprintf(
			"filesystem retained RM-control byte %d, want %d",
			gotValue,
			value,
		)
	}
	return true, ""
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
	var rmControl byte
	if control&windows.SE_RM_CONTROL_VALID != 0 {
		rmControl, err = descriptor.descriptor.RMControl()
		if err != nil {
			t.Fatalf("read security descriptor RM control: %v", err)
		}
	}
	return windowsTestSecurityDescriptor{
		sddl:      sddl,
		control:   control,
		rmControl: rmControl,
	}, true, ""
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
	var rmControl byte
	if control&windows.SE_RM_CONTROL_VALID != 0 {
		rmControl, err = descriptor.descriptor.RMControl()
		if err != nil {
			t.Fatalf("read security descriptor RM control: %v", err)
		}
	}
	return windowsTestSecurityDescriptor{
		sddl:      sddl,
		control:   control,
		rmControl: rmControl,
	}
}
