//go:build windows

package update

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func replaceExecutable(staged, target string) error {
	if !strings.EqualFold(filepath.Clean(filepath.Dir(staged)), filepath.Clean(filepath.Dir(target))) {
		return fmt.Errorf("Windows replacement staging is not on the executable filesystem")
	}
	stageInfo, err := os.Lstat(staged)
	if err != nil {
		return fmt.Errorf("inspect verified Windows replacement: %w", err)
	}
	if !stageInfo.Mode().IsRegular() {
		return fmt.Errorf("verified Windows replacement is not a regular file")
	}
	if err := cleanupPreviousExecutable(target); err != nil {
		return fmt.Errorf("clean previous Windows executable: %w", err)
	}

	backup := windowsReplacementBackup(target)
	if err := moveWindowsFile(target, backup, false); err != nil {
		return fmt.Errorf("preserve running Windows executable: %w", err)
	}
	if err := moveWindowsFile(staged, target, false); err != nil {
		if rollbackErr := moveWindowsFile(backup, target, true); rollbackErr != nil {
			return fmt.Errorf("install verified Windows executable: %w (rollback failed: %v)", err, rollbackErr)
		}
		return fmt.Errorf("install verified Windows executable: %w", err)
	}
	return nil
}

func cleanupPreviousExecutable(target string) error {
	backup := windowsReplacementBackup(target)
	info, err := os.Lstat(backup)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", backup)
	}
	return os.Remove(backup)
}

func windowsReplacementBackup(target string) string {
	return filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".old")
}

func moveWindowsFile(source, destination string, replace bool) error {
	sourcePath, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationPath, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(sourcePath, destinationPath, flags)
}
