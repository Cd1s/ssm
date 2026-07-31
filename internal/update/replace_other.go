//go:build !windows

package update

import (
	"crypto/sha256"
	"os"
)

func replaceExecutable(staged, target string, _ [sha256.Size]byte) error {
	return os.Rename(staged, target)
}

func cleanupPreviousExecutable(string) error {
	return nil
}
