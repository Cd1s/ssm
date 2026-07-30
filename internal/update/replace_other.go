//go:build !windows

package update

import "os"

func replaceExecutable(staged, target string) error {
	return os.Rename(staged, target)
}

func cleanupPreviousExecutable(string) error {
	return nil
}
