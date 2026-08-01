//go:build linux || darwin || freebsd || openbsd

package update

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const unixCommitEntry = "authenticated-replacement"

// commitAuthenticatedUnixReplacementByCopy is the Darwin/BSD commit primitive.
// It copies only from install's already-authenticated descriptor into a new
// entry in an open private sibling directory. The copied object is authenticated
// again and renameat resolves that exact entry relative to the private directory
// descriptor, so replacing installPath cannot retarget the canonical rename.
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

	if err := unix.Renameat(
		commitDirectoryDescriptor,
		unixCommitEntry,
		parentDescriptor,
		targetName,
	); err != nil {
		return fmt.Errorf("commit descriptor-copy replacement: %w", err)
	}
	committed = true
	return nil
}
