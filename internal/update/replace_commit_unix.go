//go:build linux

package update

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// commitAuthenticatedUnixReplacement binds the commit source to install's
// open object before replacing target. The kernel follows the process-owned
// descriptor link when creating unixCommitEntry inside a newly created 0700
// directory. A private hard link retains the exact original target before
// renameat, and the renamed object is authenticated through install before
// success. A late source race therefore restores the retained original.
func commitAuthenticatedUnixReplacement(
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

	installInfo, err := install.Stat()
	if err != nil {
		return fmt.Errorf("inspect authenticated replacement descriptor: %w", err)
	}
	descriptorInfo, err := os.Stat(unixReplacementDescriptorPath(install))
	if err != nil {
		return fmt.Errorf("resolve authenticated replacement descriptor: %w", err)
	}
	if !os.SameFile(installInfo, descriptorInfo) {
		return fmt.Errorf("replacement descriptor namespace did not resolve the authenticated object")
	}

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
	commitLinked := false
	committed := false
	defer func() {
		if commitLinked && !committed {
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

	if err := unix.Linkat(
		unix.AT_FDCWD,
		unixReplacementDescriptorPath(install),
		commitDirectoryDescriptor,
		unixCommitEntry,
		unix.AT_SYMLINK_FOLLOW,
	); err != nil {
		return fmt.Errorf("bind authenticated replacement descriptor: %w", err)
	}
	commitLinked = true

	linkedInfo, err := install.Stat()
	if err != nil {
		return fmt.Errorf("inspect descriptor-bound replacement: %w", err)
	}
	links, err := replacementLinkCount(linkedInfo)
	if err != nil {
		return err
	}
	if links != 2 {
		return fmt.Errorf("descriptor-bound replacement has %d hard links, want 2 before source removal", links)
	}
	installPathInfo, err := os.Lstat(installPath)
	if err != nil {
		return fmt.Errorf("inspect authenticated replacement pathname at commit: %w", err)
	}
	if !installPathInfo.Mode().IsRegular() || !os.SameFile(linkedInfo, installPathInfo) {
		return fmt.Errorf("authenticated replacement pathname changed at commit")
	}
	if err := unix.Unlinkat(parentDescriptor, installName, 0); err != nil {
		return fmt.Errorf("remove authenticated replacement staging name: %w", err)
	}

	if err := authenticateUnixReplacement(install, expectedDigest, expectedMode, 1); err != nil {
		return fmt.Errorf("authenticate descriptor-bound replacement: %w", err)
	}
	commitDescriptor, err := unix.Openat(
		commitDirectoryDescriptor,
		unixCommitEntry,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return fmt.Errorf("open descriptor-bound replacement entry: %w", err)
	}
	//nolint:gosec // successful unix.Openat returns a nonnegative descriptor representable as uintptr
	commitFile := os.NewFile(uintptr(commitDescriptor), "descriptor-bound replacement")
	if commitFile == nil {
		_ = unix.Close(commitDescriptor)
		return fmt.Errorf("open descriptor-bound replacement entry: invalid descriptor")
	}
	defer func() { _ = commitFile.Close() }()
	commitInfo, err := commitFile.Stat()
	if err != nil {
		return fmt.Errorf("inspect descriptor-bound replacement entry: %w", err)
	}
	installInfo, err = install.Stat()
	if err != nil {
		return fmt.Errorf("reinspect authenticated replacement descriptor: %w", err)
	}
	if !commitInfo.Mode().IsRegular() || !os.SameFile(installInfo, commitInfo) {
		return fmt.Errorf("descriptor-bound replacement entry changed before commit")
	}
	commitEntryPath := filepath.Join(commitDirectoryPath, unixCommitEntry)
	if unixReplacementTestHook != nil {
		if err := unixReplacementTestHook("commit_entry_verified", installPath, commitEntryPath); err != nil {
			return fmt.Errorf("continue after verifying descriptor-bound commit entry: %w", err)
		}
	}

	if err := commitVerifiedUnixEntry(
		install,
		commitDirectoryDescriptor,
		parentDescriptor,
		targetName,
		expectedDigest,
		expectedMode,
	); err != nil {
		return fmt.Errorf("commit descriptor-bound replacement: %w", err)
	}
	committed = true
	return nil
}
