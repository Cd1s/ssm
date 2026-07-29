//go:build windows

package config

import "ssm/internal/privatepath"

func restrictPrivateDirectory(path string) error {
	return privatepath.RestrictDirectory(path)
}

// Windows FlushFileBuffers applies to the temporary file before the atomic
// replacement. Go does not expose a portable durable directory-handle flush.
func syncPrivateDirectory(string) error {
	return nil
}
