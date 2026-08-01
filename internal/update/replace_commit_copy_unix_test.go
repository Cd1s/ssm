//go:build linux || darwin || freebsd || openbsd

package update

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixDescriptorCopyCommit(t *testing.T) {
	t.Run("success", testUnixDescriptorCopyCommitSuccess)
	t.Run("rejects staging pathname substitution", testUnixDescriptorCopyCommitPathSubstitution)
	t.Run("rejects private entry substitution", testUnixDescriptorCopyCommitEntrySubstitution)
	t.Run("rejects post-verification pathname substitution", func(t *testing.T) {
		testUnixCommitPostVerificationPathSubstitution(t, commitAuthenticatedUnixReplacementByCopy)
	})
	t.Run("rejects post-verification in-place mutation", func(t *testing.T) {
		testUnixCommitPostVerificationInPlaceMutation(t, commitAuthenticatedUnixReplacementByCopy)
	})
}

type unixCommitTestFunc func(
	*os.File,
	string,
	string,
	[sha256.Size]byte,
	os.FileMode,
) error

func testUnixDescriptorCopyCommitSuccess(t *testing.T) {
	target, install, installPath, digest := newUnixDescriptorCopyCommitFixture(t)

	if err := commitAuthenticatedUnixReplacementByCopy(
		install,
		installPath,
		target,
		digest,
		0o751,
	); err != nil {
		t.Fatalf("descriptor-copy commit: %v", err)
	}

	assertExecutablePreserved(t, target, []byte("authenticated replacement"), 0o751)
	if _, err := os.Lstat(installPath); !os.IsNotExist(err) {
		t.Fatalf("authenticated staging pathname remains after commit: %v", err)
	}
}

func testUnixDescriptorCopyCommitPathSubstitution(t *testing.T) {
	target, install, installPath, digest := newUnixDescriptorCopyCommitFixture(t)
	oldHook := unixReplacementTestHook
	t.Cleanup(func() { unixReplacementTestHook = oldHook })
	hookCalled := false
	unixReplacementTestHook = func(phase, _, path string) error {
		if phase != "commit_copy_path_checked" {
			return nil
		}
		hookCalled = true
		if err := os.Rename(path, path+".verified"); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("attacker bytes"), 0o751) //nolint:gosec // adversarial test-owned pathname substitution
	}

	err := commitAuthenticatedUnixReplacementByCopy(
		install,
		installPath,
		target,
		digest,
		0o751,
	)
	if !hookCalled {
		t.Fatal("staging substitution did not reach the descriptor-copy commit seam")
	}
	if err == nil || !strings.Contains(err.Error(), "staging object changed during commit") {
		t.Fatalf("staging substitution error = %v, want exact-object rejection", err)
	}
	assertExecutablePreserved(t, target, []byte("old"), 0o751)
}

func testUnixDescriptorCopyCommitEntrySubstitution(t *testing.T) {
	target, install, installPath, digest := newUnixDescriptorCopyCommitFixture(t)
	oldHook := unixReplacementTestHook
	t.Cleanup(func() { unixReplacementTestHook = oldHook })
	hookCalled := false
	unixReplacementTestHook = func(phase, _, path string) error {
		if phase != "commit_copy_ready" {
			return nil
		}
		hookCalled = true
		if err := os.Rename(path, path+".verified"); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("attacker bytes"), 0o751) //nolint:gosec // adversarial test-owned commit-entry substitution
	}

	err := commitAuthenticatedUnixReplacementByCopy(
		install,
		installPath,
		target,
		digest,
		0o751,
	)
	if !hookCalled {
		t.Fatal("entry substitution did not reach the descriptor-copy commit seam")
	}
	if err == nil || !strings.Contains(err.Error(), "commit entry changed before rename") {
		t.Fatalf("entry substitution error = %v, want exact-object rejection", err)
	}
	assertExecutablePreserved(t, target, []byte("old"), 0o751)
}

func testUnixCommitPostVerificationPathSubstitution(t *testing.T, commit unixCommitTestFunc) {
	t.Helper()
	target, install, installPath, digest := newUnixDescriptorCopyCommitFixture(t)
	originalInfo, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	oldHook := unixReplacementTestHook
	t.Cleanup(func() { unixReplacementTestHook = oldHook })
	hookCalled := false
	unixReplacementTestHook = func(phase, _, path string) error {
		if phase != "commit_entry_verified" {
			return nil
		}
		hookCalled = true
		if err := os.Rename(path, path+".verified"); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("late attacker pathname"), 0o751) //nolint:gosec // adversarial test-owned pathname substitution
	}

	err = commit(install, installPath, target, digest, 0o751)
	if !hookCalled {
		t.Fatal("pathname substitution did not reach the post-verification commit seam")
	}
	if err == nil || !strings.Contains(err.Error(), "exact original target restored") {
		t.Fatalf("post-verification pathname substitution error = %v, want authenticated rollback", err)
	}
	assertExecutablePreserved(t, target, []byte("old"), 0o751)
	assertUnixOriginalObjectPreserved(t, target, originalInfo)
}

func testUnixCommitPostVerificationInPlaceMutation(t *testing.T, commit unixCommitTestFunc) {
	t.Helper()
	target, install, installPath, digest := newUnixDescriptorCopyCommitFixture(t)
	originalInfo, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	oldHook := unixReplacementTestHook
	t.Cleanup(func() { unixReplacementTestHook = oldHook })
	hookCalled := false
	unixReplacementTestHook = func(phase, _, path string) error {
		if phase != "commit_entry_verified" {
			return nil
		}
		hookCalled = true
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0) //nolint:gosec // adversarial test-owned same-inode mutation
		if err != nil {
			return err
		}
		if _, err := file.Write([]byte("late attacker same inode")); err != nil {
			_ = file.Close()
			return err
		}
		return file.Close()
	}

	err = commit(install, installPath, target, digest, 0o751)
	if !hookCalled {
		t.Fatal("in-place mutation did not reach the post-verification commit seam")
	}
	if err == nil || !strings.Contains(err.Error(), "exact original target restored") {
		t.Fatalf("post-verification in-place mutation error = %v, want authenticated rollback", err)
	}
	assertExecutablePreserved(t, target, []byte("old"), 0o751)
	assertUnixOriginalObjectPreserved(t, target, originalInfo)
}

func assertUnixOriginalObjectPreserved(t *testing.T, target string, original os.FileInfo) {
	t.Helper()
	restored, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(original, restored) {
		t.Fatal("failed replacement did not restore the exact original target object")
	}
}

func newUnixDescriptorCopyCommitFixture(
	t *testing.T,
) (target string, install *os.File, installPath string, digest [sha256.Size]byte) {
	t.Helper()
	directory := t.TempDir()
	target = filepath.Join(directory, "ssm")
	if err := os.WriteFile(target, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable fixture
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o751); err != nil { //nolint:gosec // make asserted fixture mode independent of process umask
		t.Fatal(err)
	}
	var err error
	install, err = os.CreateTemp(directory, ".ssm.*.install")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = install.Close() })
	installPath = install.Name()
	payload := []byte("authenticated replacement")
	if _, err := install.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := install.Chmod(0o751); err != nil {
		t.Fatal(err)
	}
	if err := install.Sync(); err != nil {
		t.Fatal(err)
	}
	return target, install, installPath, sha256.Sum256(payload)
}
