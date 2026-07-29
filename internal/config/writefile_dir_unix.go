//go:build unix

package config

import "os"

func restrictPrivateDirectory(path string) error {
	return os.Chmod(path, 0o700) //nolint:gosec // private directories require owner traversal
}

func syncPrivateDirectory(path string) error {
	directory, err := os.Open(path) //nolint:gosec // caller supplies the parent of a fixed private persistence path
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
