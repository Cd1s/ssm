//go:build unix

package ssh

import "os"

// stdinIsNullDevice reports whether local stdin is closed or the null device.
// Such a stdin carries no data, so it never warrants a "not forwarded" marker.
func stdinIsNullDevice() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return true
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	null, err := os.Stat(os.DevNull)
	return err == nil && os.SameFile(info, null)
}
