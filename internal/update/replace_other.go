//go:build !windows

package update

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
)

// replaceExecutable copies from one opened staged object into a fresh sibling
// and authenticates that copy immediately before a descriptor-bound commit.
// The open source cannot be changed by replacing staged's pathname during the
// copy; an in-place or hard-link write can only be installed if the resulting
// bytes still match the provenance-authenticated digest. originalMode comes
// from the installed executable inspected before staging and is deliberately
// independent of mutable staging metadata.
func replaceExecutable(
	staged,
	target string,
	expectedDigest [sha256.Size]byte,
	originalMode os.FileMode,
) error {
	source, err := os.Open(staged) //nolint:gosec // caller-owned sibling stage
	if err != nil {
		return fmt.Errorf("open verified replacement: %w", err)
	}
	defer func() { _ = source.Close() }()
	sourceInfo, err := source.Stat()
	if err != nil {
		return fmt.Errorf("inspect verified replacement: %w", err)
	}
	if !sourceInfo.Mode().IsRegular() {
		return fmt.Errorf("verified replacement is not a regular file")
	}
	if unixReplacementTestHook != nil {
		if err := unixReplacementTestHook("source_open", staged, ""); err != nil {
			return fmt.Errorf("continue after opening verified replacement: %w", err)
		}
	}

	install, err := os.CreateTemp(
		filepath.Dir(target),
		"."+filepath.Base(target)+".*.install",
	)
	if err != nil {
		return fmt.Errorf("create authenticated replacement copy: %w", err)
	}
	installPath := install.Name()
	installed := false
	defer func() {
		_ = install.Close()
		if !installed {
			_ = os.Remove(installPath)
		}
	}()
	sourceHash := sha256.New()
	written, err := io.Copy(
		io.MultiWriter(install, sourceHash),
		io.LimitReader(source, maxBinary+1),
	)
	if err != nil {
		return fmt.Errorf("copy verified replacement: %w", err)
	}
	if written > maxBinary {
		return fmt.Errorf("verified replacement exceeds %d-byte limit", maxBinary)
	}
	if actual := [sha256.Size]byte(sourceHash.Sum(nil)); actual != expectedDigest {
		return fmt.Errorf("verified replacement digest does not match authenticated bytes")
	}
	if err := install.Sync(); err != nil {
		return fmt.Errorf("sync authenticated replacement copy: %w", err)
	}
	if unixReplacementTestHook != nil {
		if err := unixReplacementTestHook("copy_ready", staged, installPath); err != nil {
			return fmt.Errorf("continue before authenticating replacement copy: %w", err)
		}
	}
	if _, err := install.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind authenticated replacement copy: %w", err)
	}
	installHash := sha256.New()
	if _, err := io.Copy(installHash, io.LimitReader(install, maxBinary+1)); err != nil {
		return fmt.Errorf("authenticate replacement copy: %w", err)
	}
	if actual := [sha256.Size]byte(installHash.Sum(nil)); actual != expectedDigest {
		return fmt.Errorf("replacement copy digest does not match authenticated bytes")
	}
	installInfo, err := install.Stat()
	if err != nil {
		return fmt.Errorf("inspect authenticated replacement copy: %w", err)
	}
	links, err := replacementLinkCount(installInfo)
	if err != nil {
		return err
	}
	if links != 1 {
		return fmt.Errorf("authenticated replacement copy has %d hard links", links)
	}
	pathInfo, err := os.Lstat(installPath)
	if err != nil {
		return fmt.Errorf("inspect authenticated replacement pathname: %w", err)
	}
	if !pathInfo.Mode().IsRegular() || !os.SameFile(installInfo, pathInfo) {
		return fmt.Errorf("authenticated replacement pathname changed before install")
	}
	if err := install.Chmod(originalMode.Perm()); err != nil {
		return fmt.Errorf("set authenticated replacement permissions: %w", err)
	}
	if err := install.Sync(); err != nil {
		return fmt.Errorf("sync authenticated replacement permissions: %w", err)
	}
	if err := authenticateUnixReplacement(install, expectedDigest, originalMode.Perm(), 1); err != nil {
		return fmt.Errorf("final authentication of replacement copy: %w", err)
	}
	finalInstallInfo, err := install.Stat()
	if err != nil {
		return fmt.Errorf("final inspection of authenticated replacement copy: %w", err)
	}
	finalPathInfo, err := os.Lstat(installPath)
	if err != nil {
		return fmt.Errorf("final inspection of authenticated replacement pathname: %w", err)
	}
	if !finalPathInfo.Mode().IsRegular() || !os.SameFile(finalInstallInfo, finalPathInfo) {
		return fmt.Errorf("authenticated replacement pathname changed before commit")
	}
	if unixReplacementTestHook != nil {
		if err := unixReplacementTestHook("before_commit", staged, installPath); err != nil {
			return fmt.Errorf("continue before committing authenticated replacement: %w", err)
		}
	}
	if err := commitAuthenticatedUnixReplacement(
		install,
		installPath,
		target,
		expectedDigest,
		originalMode.Perm(),
	); err != nil {
		return fmt.Errorf("install authenticated replacement: %w", err)
	}
	installed = true
	return nil
}

func authenticateUnixReplacement(
	file *os.File,
	expectedDigest [sha256.Size]byte,
	expectedMode os.FileMode,
	expectedLinks uint64,
) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind authenticated replacement: %w", err)
	}
	digest := sha256.New()
	read, err := io.Copy(digest, io.LimitReader(file, maxBinary+1))
	if err != nil {
		return fmt.Errorf("hash authenticated replacement: %w", err)
	}
	if read > maxBinary {
		return fmt.Errorf("authenticated replacement exceeds %d-byte limit", maxBinary)
	}
	if actual := [sha256.Size]byte(digest.Sum(nil)); actual != expectedDigest {
		return fmt.Errorf("authenticated replacement digest changed before commit")
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect authenticated replacement: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("authenticated replacement is not a regular file")
	}
	if info.Mode().Perm() != expectedMode.Perm() {
		return fmt.Errorf(
			"authenticated replacement mode changed before commit: got %o want %o",
			info.Mode().Perm(),
			expectedMode.Perm(),
		)
	}
	links, err := replacementLinkCount(info)
	if err != nil {
		return err
	}
	if links != expectedLinks {
		return fmt.Errorf("authenticated replacement has %d hard links, want %d", links, expectedLinks)
	}
	return nil
}

func replacementLinkCount(info os.FileInfo) (uint64, error) {
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0, fmt.Errorf("authenticated replacement link count is unavailable")
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return 0, fmt.Errorf("authenticated replacement link count is unavailable")
	}
	links := value.FieldByName("Nlink")
	if !links.IsValid() {
		return 0, fmt.Errorf("authenticated replacement link count is unavailable")
	}
	switch links.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return links.Uint(), nil
	default:
		return 0, fmt.Errorf("authenticated replacement link count is unavailable")
	}
}

func cleanupPreviousExecutable(string) error {
	return nil
}
