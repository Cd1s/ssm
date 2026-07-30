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
	windowsReplacementPauseEnv = "SSM_TEST_WINDOWS_REPLACEMENT_PAUSE"
	windowsReplacementReadyEnv = "SSM_TEST_WINDOWS_REPLACEMENT_READY"
	windowsReplacementGoEnv    = "SSM_TEST_WINDOWS_REPLACEMENT_GO"
	windowsSubstituteStageEnv  = "SSM_TEST_WINDOWS_SUBSTITUTE_STAGE"
	windowsRollbackFailEnv     = "SSM_TEST_WINDOWS_ROLLBACK_FAIL"
)

func TestWindowsNativeReplacementSecurity(t *testing.T) {
	t.Run("ordinary user preserves owner group DACL and inheritance", testWindowsOrdinaryUserReplacement)
	t.Run("privileged user preserves the complete descriptor", testWindowsPrivilegedReplacement)
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
	setWindowsTestSACL(t, target)
	wantDescriptor := readWindowsTestSecurityDescriptor(t, target, true)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nSSM_WINDOWS_DESCRIPTOR_MARKER\n"))

	command := exec.Command(target, "-test.run=^TestWindowsReplacementChildProcess$", "-test.count=1") //nolint:gosec // fixed test-owned executable and arguments
	command.Env = append(os.Environ(),
		windowsReplacementChildEnv+"=1",
		windowsReplacementStageEnv+"="+stage,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("mapped executable replacement failed: %v; output=%q", err, output)
	}

	gotDescriptor := readWindowsTestSecurityDescriptor(t, target, true)
	if gotDescriptor != wantDescriptor {
		t.Fatalf("replacement security descriptor = %#v, want %#v", gotDescriptor, wantDescriptor)
	}
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
	setRestrictiveWindowsTestDACL(t, target)
	original, err := os.ReadFile(target) //nolint:gosec // test-owned executable fixture
	if err != nil {
		t.Fatal(err)
	}
	wantDescriptor := readWindowsTestSecurityDescriptor(t, target, false)
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
	gotDescriptor := readWindowsTestSecurityDescriptor(t, target, false)
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
	wantDescriptor := readWindowsTestSecurityDescriptor(t, target, false)
	copyWindowsTestExecutable(t, testExecutable, stage, []byte("\nSSM_WINDOWS_ORDINARY_MARKER\n"))

	command := windowsReplacementTestCommand(target, stage)
	command.Env = append(command.Env, windowsOrdinaryUserEnv+"=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ordinary non-privileged replacement failed: %v; output=%q", err, output)
	}

	gotDescriptor := readWindowsTestSecurityDescriptor(t, target, false)
	if gotDescriptor != wantDescriptor {
		t.Fatalf("ordinary replacement security descriptor = %#v, want %#v", gotDescriptor, wantDescriptor)
	}
}

func testWindowsReplacementPrivilegeRestoration(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	beforeThread, beforeEffective := windowsTestTokenState(t)
	scope, _, err := beginWindowsReplacementPrivileges()
	if err != nil {
		t.Fatalf("begin optional replacement privileges: %v", err)
	}
	if scope != nil {
		if err := scope.close(); err != nil {
			t.Fatalf("close optional replacement privileges: %v", err)
		}
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

	var restrictedToken windows.Token
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
		uintptr(unsafe.Pointer(&restrictedToken)),
	)
	if result == 0 {
		runtime.UnlockOSThread()
		if callErr == nil || errors.Is(callErr, windows.ERROR_SUCCESS) {
			callErr = windows.ERROR_GEN_FAILURE
		}
		return nil, callErr
	}
	if err := windows.SetThreadToken(nil, restrictedToken); err != nil {
		_ = restrictedToken.Close()
		runtime.UnlockOSThread()
		return nil, err
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
		if os.Getenv("SSM_REQUIRE_WINDOWS_PRIVILEGED_TEST") == "1" {
			t.Fatal("native Windows gate requires SeRestorePrivilege for wrong-owner control-state coverage")
		}
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

func setWindowsTestSACL(t *testing.T, path string) {
	t.Helper()
	scope, available, err := beginWindowsReplacementPrivileges()
	if err != nil {
		t.Fatalf("enable test SACL privileges: %v", err)
	}
	if !available {
		if os.Getenv("SSM_REQUIRE_WINDOWS_PRIVILEGED_TEST") == "1" {
			t.Fatal("native Windows gate requires SeBackupPrivilege, SeRestorePrivilege, and SeSecurityPrivilege")
		}
		t.Skip("current Windows token does not assign the complete descriptor privileges")
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
		t.Fatalf("set test SACL: %v", err)
	}
}

func readWindowsTestSecurityDescriptor(t *testing.T, path string, full bool) windowsTestSecurityDescriptor {
	t.Helper()
	access := uint32(windows.READ_CONTROL)
	information := windowsOrdinarySecurityInformation
	var scope *windowsReplacementPrivilegeScope
	if full {
		var available bool
		var err error
		scope, available, err = beginWindowsReplacementPrivileges()
		if err != nil {
			t.Fatalf("enable test descriptor privileges: %v", err)
		}
		if !available {
			t.Fatal("complete test descriptor privileges became unavailable")
		}
		access |= windows.ACCESS_SYSTEM_SECURITY
		information = windowsFullSecurityInformation
		defer func() {
			if err := scope.close(); err != nil {
				t.Fatalf("release test descriptor privileges: %v", err)
			}
		}()
	}
	handle, err := openWindowsReplacementFile(
		path,
		access,
	)
	if err != nil {
		t.Fatalf("open test descriptor: %v", err)
	}
	defer windows.CloseHandle(handle)
	descriptor, err := captureWindowsSecurityDescriptor(handle, information)
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
