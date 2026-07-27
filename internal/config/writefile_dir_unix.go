//go:build unix

package config

import "os"

func restrictPrivateDirectory(path string) error {
	return os.Chmod(path, 0o700) //nolint:gosec // private directories require owner traversal
}
