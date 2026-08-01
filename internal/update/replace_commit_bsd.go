//go:build darwin || freebsd || openbsd

package update

import (
	"crypto/sha256"
	"os"
)

func commitAuthenticatedUnixReplacement(
	install *os.File,
	installPath,
	target string,
	expectedDigest [sha256.Size]byte,
	expectedMode os.FileMode,
) error {
	return commitAuthenticatedUnixReplacementByCopy(
		install,
		installPath,
		target,
		expectedDigest,
		expectedMode,
	)
}
