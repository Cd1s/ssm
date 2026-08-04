//go:build !windows && !linux && !darwin && !freebsd && !openbsd

package update

import (
	"crypto/sha256"
	"fmt"
	"os"
)

func commitAuthenticatedUnixReplacement(
	_ *os.File,
	_, _ string,
	_ [sha256.Size]byte,
	_ os.FileMode,
) error {
	return fmt.Errorf("authenticated handle-bound replacement is unavailable on this platform")
}
