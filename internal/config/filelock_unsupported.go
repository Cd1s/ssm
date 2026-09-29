//go:build !unix && !windows

package config

import (
	"fmt"
	"os"
)

func tryFileLock(*os.File) (bool, error) {
	return false, fmt.Errorf("file locking is unsupported on this platform")
}

func unlockFile(*os.File) error { return nil }
