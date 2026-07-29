//go:build !unix && !windows

package ssh

func stdinHasReadableData() bool {
	return false
}
