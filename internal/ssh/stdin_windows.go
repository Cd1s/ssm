//go:build windows

package ssh

func stdinHasReadableData() bool {
	return false
}
