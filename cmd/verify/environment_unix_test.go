//go:build unix

package main

import "os"

func makeCacheDirectoryPermissive(path string) error {
	//nolint:gosec // adversarial test fixture must be broader than the required private-directory mode
	return os.Chmod(path, 0o755)
}

func makeTestFileUnreadable(path string) (func(), error) {
	if err := os.Chmod(path, 0); err != nil {
		return nil, err
	}
	return func() {
		_ = os.Chmod(path, 0o600)
	}, nil
}
