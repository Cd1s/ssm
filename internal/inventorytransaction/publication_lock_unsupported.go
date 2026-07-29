//go:build !unix && !windows

package inventorytransaction

import (
	"fmt"
	"os"
)

func tryPublicationFileLock(*os.File) (bool, error) {
	return false, fmt.Errorf("publication locking is unsupported on this platform")
}

func unlockPublicationFile(*os.File) error {
	return nil
}
