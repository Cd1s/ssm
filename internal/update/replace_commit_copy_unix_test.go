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
}

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
