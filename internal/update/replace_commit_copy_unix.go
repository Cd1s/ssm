//go:build linux || darwin || freebsd || openbsd

package update

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	unixCommitEntry    = "authenticated-replacement"
	unixRollbackEntry  = "original-target"
	unixDiscardedEntry = "discarded-replacement"
)

func sameUnixObject(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino
}

func commitVerifiedUnixEntry(
	source *os.File,
	commitDirectoryDescriptor,
	parentDescriptor int,
	target string,
	expectedDigest [sha256.Size]byte,
	expectedMode os.FileMode,
) error {
	targetName := filepath.Base(target)
	defer func() {
		_ = removeUnixCommitEntry(commitDirectoryDescriptor, unixDiscardedEntry)
	}()
	var original unix.Stat_t
	if err := unix.Fstatat(
		parentDescriptor,
		targetName,
		&original,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fmt.Errorf("inspect original replacement target: %w", err)
	}
	if original.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("original replacement target is not a regular file")
	}
	if err := unix.Linkat(
		parentDescriptor,
		targetName,
		commitDirectoryDescriptor,
		unixRollbackEntry,
		0,
	); err != nil {
		return fmt.Errorf("retain exact original replacement target: %w", err)
	}
	rollbackLinked := true
	defer func() {
		if rollbackLinked {
			_ = unix.Unlinkat(commitDirectoryDescriptor, unixRollbackEntry, 0)
		}
	}()

	var retained unix.Stat_t
	if err := unix.Fstatat(
		commitDirectoryDescriptor,
		unixRollbackEntry,
		&retained,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fmt.Errorf("inspect retained original replacement target: %w", err)
	}
	if !sameUnixObject(original, retained) ||
		retained.Nlink != original.Nlink+1 {
		return fmt.Errorf("retained original replacement target changed before commit")
	}

	if err := unix.Renameat(
		commitDirectoryDescriptor,
		unixCommitEntry,
		parentDescriptor,
		targetName,
	); err != nil {
		return fmt.Errorf("commit authenticated replacement: %w", err)
	}

	authenticationErr := authenticateCanonicalUnixReplacement(
		source,
		parentDescriptor,
		targetName,
		expectedDigest,
		expectedMode,
	)
	if authenticationErr == nil {
		// A portable Unix regular-file descriptor does not deny writes through
		// other descriptors, and renameat does not lock the destination name.
		// The hook deterministically models a change after the former final
		// observation; the second authentication is the strongest testable
		// boundary before success. No finite userspace protocol can prevent an
		// equally authorized writer from acting after its last observation.
		if unixReplacementTestHook != nil {
			if err := unixReplacementTestHook("canonical_replacement_validated", "", target); err != nil {
				authenticationErr = fmt.Errorf("continue after validating canonical replacement: %w", err)
			}
		}
		if authenticationErr == nil {
			authenticationErr = authenticateCanonicalUnixReplacement(
				source,
				parentDescriptor,
				targetName,
				expectedDigest,
				expectedMode,
			)
		}
		if authenticationErr == nil {
			return nil
		}
	}

	restored, rollbackErr := restoreOriginalUnixTarget(
		commitDirectoryDescriptor,
		parentDescriptor,
		target,
	)
	rollbackLinked = false
	if !restored {
		return fmt.Errorf(
			"authenticate canonical replacement after rename: %w; restore exact original target: %v (original evidence retained)",
			authenticationErr,
			rollbackErr,
		)
	}
	return fmt.Errorf(
		"authenticate canonical replacement after rename: %w (exact original target restored)",
		errors.Join(authenticationErr, rollbackErr),
	)
}

func restoreOriginalUnixTarget(
	commitDirectoryDescriptor,
	parentDescriptor int,
	target string,
) (bool, error) {
	targetName := filepath.Base(target)
	var rollbackBoundaryErr error
	if unixReplacementTestHook != nil {
		if err := unixReplacementTestHook("rollback_boundary", "", target); err != nil {
			rollbackBoundaryErr = fmt.Errorf("continue at rollback boundary: %w", err)
		}
	}

	// Moving the current pathname away first makes restoration independent of
	// its type. In particular, renameat cannot replace a directory with the
	// retained regular file directly. Cleanup happens before the restoration so
	// the final canonical-path mutation is the exact-original rename below.
	displaced := false
	displaceErr := unix.Renameat(
		parentDescriptor,
		targetName,
		commitDirectoryDescriptor,
		unixDiscardedEntry,
	)
	if displaceErr == nil {
		displaced = true
	} else if errors.Is(displaceErr, unix.ENOENT) {
		displaceErr = nil
	} else {
		displaceErr = fmt.Errorf("isolate changed canonical replacement: %w", displaceErr)
	}

	var cleanupErr error
	if displaced {
		if err := removeUnixCommitEntry(commitDirectoryDescriptor, unixDiscardedEntry); err != nil {
			cleanupErr = fmt.Errorf("remove isolated canonical replacement: %w", err)
		}
	}

	if err := unix.Renameat(
		commitDirectoryDescriptor,
		unixRollbackEntry,
		parentDescriptor,
		targetName,
	); err != nil {
		return false, errors.Join(rollbackBoundaryErr, displaceErr, cleanupErr, err)
	}
	return true, errors.Join(rollbackBoundaryErr, displaceErr, cleanupErr)
}

func removeUnixCommitEntry(directoryDescriptor int, name string) error {
	var entry unix.Stat_t
	if err := unix.Fstatat(
		directoryDescriptor,
		name,
		&entry,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	flags := 0
	if entry.Mode&unix.S_IFMT == unix.S_IFDIR {
		flags = unix.AT_REMOVEDIR
	}
	return unix.Unlinkat(directoryDescriptor, name, flags)
}

func authenticateCanonicalUnixReplacement(
	source *os.File,
	parentDescriptor int,
	targetName string,
	expectedDigest [sha256.Size]byte,
	expectedMode os.FileMode,
) error {
	if err := authenticateUnixReplacement(source, expectedDigest, expectedMode, 1); err != nil {
		return err
	}

	var canonical unix.Stat_t
	if err := unix.Fstatat(
		parentDescriptor,
		targetName,
		&canonical,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fmt.Errorf("inspect canonical replacement: %w", err)
	}
	var sourceStat unix.Stat_t
	//nolint:gosec // os.File descriptors originate from successful Unix opens and fit the native int descriptor type
	if err := unix.Fstat(int(source.Fd()), &sourceStat); err != nil {
		return fmt.Errorf("inspect authenticated replacement source after rename: %w", err)
	}
	if canonical.Mode&unix.S_IFMT != unix.S_IFREG ||
		!sameUnixObject(sourceStat, canonical) {
		return fmt.Errorf("canonical replacement is not the authenticated source object")
	}
	return nil
}

// commitAuthenticatedUnixReplacementByCopy is the Darwin/BSD commit primitive.
// It copies only from install's already-authenticated descriptor into a new
// entry in an open private sibling directory. The copied object is authenticated
// again, the exact original target is retained as a private hard link, and the
// renamed object is authenticated at its canonical entry before success. A late
// private-entry race therefore restores the retained original.
// This function is built on Linux as a deterministic test seam; Linux production
// keeps the stronger same-inode descriptor-link implementation.
func commitAuthenticatedUnixReplacementByCopy(
	install *os.File,
	installPath,
	target string,
	expectedDigest [sha256.Size]byte,
	expectedMode os.FileMode,
) error {
	parent := filepath.Dir(target)
	if filepath.Dir(installPath) != parent {
		return fmt.Errorf("authenticated replacement is not a target sibling")
	}
	targetName := filepath.Base(target)
	installName := filepath.Base(installPath)
	if targetName == "." || targetName == string(filepath.Separator) ||
		installName == "." || installName == string(filepath.Separator) {
		return fmt.Errorf("authenticated replacement has an invalid sibling name")
	}
	if err := authenticateUnixReplacement(install, expectedDigest, expectedMode, 1); err != nil {
		return fmt.Errorf("authenticate descriptor-copy source: %w", err)
	}

	parentDescriptor, err := unix.Open(
		parent,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return fmt.Errorf("open replacement directory: %w", err)
	}
	//nolint:gosec // successful unix.Open returns a nonnegative descriptor representable as uintptr
	parentFile := os.NewFile(uintptr(parentDescriptor), "replacement directory")
	if parentFile == nil {
		_ = unix.Close(parentDescriptor)
		return fmt.Errorf("open replacement directory: invalid descriptor")
	}
	defer func() { _ = parentFile.Close() }()

	commitDirectoryPath, err := os.MkdirTemp(parent, "."+targetName+".*.commit")
	if err != nil {
		return fmt.Errorf("create private replacement commit directory: %w", err)
	}
	commitDirectoryName := filepath.Base(commitDirectoryPath)
	commitDirectoryDescriptor, err := unix.Openat(
		parentDescriptor,
		commitDirectoryName,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		_ = unix.Unlinkat(parentDescriptor, commitDirectoryName, unix.AT_REMOVEDIR)
		return fmt.Errorf("open private replacement commit directory: %w", err)
	}
	//nolint:gosec // successful unix.Openat returns a nonnegative descriptor representable as uintptr
	commitDirectory := os.NewFile(uintptr(commitDirectoryDescriptor), "replacement commit directory")
	if commitDirectory == nil {
		_ = unix.Close(commitDirectoryDescriptor)
		_ = unix.Unlinkat(parentDescriptor, commitDirectoryName, unix.AT_REMOVEDIR)
		return fmt.Errorf("open private replacement commit directory: invalid descriptor")
	}
	commitCreated := false
	committed := false
	defer func() {
		if commitCreated && !committed {
			_ = unix.Unlinkat(commitDirectoryDescriptor, unixCommitEntry, 0)
		}
		_ = commitDirectory.Close()
		_ = unix.Unlinkat(parentDescriptor, commitDirectoryName, unix.AT_REMOVEDIR)
	}()

	commitDirectoryInfo, err := commitDirectory.Stat()
	if err != nil {
		return fmt.Errorf("inspect private replacement commit directory: %w", err)
	}
	commitDirectoryPathInfo, err := os.Lstat(commitDirectoryPath)
	if err != nil {
		return fmt.Errorf("inspect private replacement commit pathname: %w", err)
	}
	if !commitDirectoryInfo.IsDir() || commitDirectoryInfo.Mode().Perm() != 0o700 ||
		!os.SameFile(commitDirectoryInfo, commitDirectoryPathInfo) {
		return fmt.Errorf("private replacement commit directory changed before binding")
	}

	commitDescriptor, err := unix.Openat(
		commitDirectoryDescriptor,
		unixCommitEntry,
		unix.O_RDWR|unix.O_CLOEXEC|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("create descriptor-copy commit entry: %w", err)
	}
	commitCreated = true
	//nolint:gosec // successful unix.Openat returns a nonnegative descriptor representable as uintptr
	commitFile := os.NewFile(uintptr(commitDescriptor), "descriptor-copy replacement")
	if commitFile == nil {
		_ = unix.Close(commitDescriptor)
		return fmt.Errorf("create descriptor-copy commit entry: invalid descriptor")
	}
	defer func() { _ = commitFile.Close() }()

	if _, err := install.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind descriptor-copy source: %w", err)
	}
	digest := sha256.New()
	written, err := io.Copy(
		io.MultiWriter(commitFile, digest),
		io.LimitReader(install, maxBinary+1),
	)
	if err != nil {
		return fmt.Errorf("copy authenticated replacement descriptor: %w", err)
	}
	if written > maxBinary {
		return fmt.Errorf("authenticated replacement exceeds %d-byte limit", maxBinary)
	}
	if actual := [sha256.Size]byte(digest.Sum(nil)); actual != expectedDigest {
		return fmt.Errorf("descriptor-copy replacement digest changed during copy")
	}
	if err := commitFile.Chmod(expectedMode.Perm()); err != nil {
		return fmt.Errorf("set descriptor-copy replacement permissions: %w", err)
	}
	if err := commitFile.Sync(); err != nil {
		return fmt.Errorf("sync descriptor-copy replacement: %w", err)
	}
	if err := authenticateUnixReplacement(commitFile, expectedDigest, expectedMode, 1); err != nil {
		return fmt.Errorf("authenticate descriptor-copy replacement: %w", err)
	}

	commitEntryPath := filepath.Join(commitDirectoryPath, unixCommitEntry)
	if unixReplacementTestHook != nil {
		if err := unixReplacementTestHook("commit_copy_ready", installPath, commitEntryPath); err != nil {
			return fmt.Errorf("continue after binding descriptor-copy replacement: %w", err)
		}
	}
	installInfo, err := install.Stat()
	if err != nil {
		return fmt.Errorf("inspect descriptor-copy source: %w", err)
	}
	installPathInfo, err := os.Lstat(installPath)
	if err != nil {
		return fmt.Errorf("inspect authenticated replacement pathname at commit: %w", err)
	}
	if !installPathInfo.Mode().IsRegular() || !os.SameFile(installInfo, installPathInfo) {
		return fmt.Errorf("authenticated replacement pathname changed at commit")
	}
	if unixReplacementTestHook != nil {
		if err := unixReplacementTestHook("commit_copy_path_checked", installPath, installPath); err != nil {
			return fmt.Errorf("continue after checking descriptor-copy source pathname: %w", err)
		}
	}
	if err := unix.Unlinkat(parentDescriptor, installName, 0); err != nil {
		return fmt.Errorf("remove authenticated replacement staging name: %w", err)
	}
	if err := authenticateUnixReplacement(install, expectedDigest, expectedMode, 0); err != nil {
		return fmt.Errorf("authenticated replacement staging object changed during commit: %w", err)
	}
	if err := authenticateUnixReplacement(commitFile, expectedDigest, expectedMode, 1); err != nil {
		return fmt.Errorf("reauthenticate descriptor-copy replacement: %w", err)
	}

	entryDescriptor, err := unix.Openat(
		commitDirectoryDescriptor,
		unixCommitEntry,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return fmt.Errorf("open descriptor-copy commit entry: %w", err)
	}
	//nolint:gosec // successful unix.Openat returns a nonnegative descriptor representable as uintptr
	entryFile := os.NewFile(uintptr(entryDescriptor), "descriptor-copy commit entry")
	if entryFile == nil {
		_ = unix.Close(entryDescriptor)
		return fmt.Errorf("open descriptor-copy commit entry: invalid descriptor")
	}
	defer func() { _ = entryFile.Close() }()
	commitInfo, err := commitFile.Stat()
	if err != nil {
		return fmt.Errorf("inspect descriptor-copy replacement: %w", err)
	}
	entryInfo, err := entryFile.Stat()
	if err != nil {
		return fmt.Errorf("inspect descriptor-copy commit entry: %w", err)
	}
	if !entryInfo.Mode().IsRegular() || !os.SameFile(commitInfo, entryInfo) {
		return fmt.Errorf("descriptor-copy commit entry changed before rename")
	}
	if unixReplacementTestHook != nil {
		if err := unixReplacementTestHook("commit_entry_verified", installPath, commitEntryPath); err != nil {
			return fmt.Errorf("continue after verifying descriptor-copy commit entry: %w", err)
		}
	}

	if err := commitVerifiedUnixEntry(
		commitFile,
		commitDirectoryDescriptor,
		parentDescriptor,
		target,
		expectedDigest,
		expectedMode,
	); err != nil {
		return fmt.Errorf("commit descriptor-copy replacement: %w", err)
	}
	committed = true
	return nil
}
