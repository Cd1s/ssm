//go:build !unix

package ssh

import "os"

// stdinIsNullDevice reports whether local stdin is closed or a character
// device other than a console (NUL on Windows). Console stdin is handled by
// the terminal check before this is consulted.
func stdinIsNullDevice() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return true
	}
	return info.Mode()&os.ModeCharDevice != 0
}
