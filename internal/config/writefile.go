package config

import (
	"os"
	"path/filepath"

	"ssm/internal/privatepath"
)

func EnsurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return restrictPrivateDirectory(path)
}

func WritePrivateFile(path string, data []byte) error {
	if err := EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := privatepath.RestrictFile(tmpPath); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if err := privatepath.RestrictFile(path); err != nil {
		return err
	}
	if err := syncPrivateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	committed = true
	return nil
}

// RemovePrivateFile durably removes one private sidecar. A missing sidecar is
// already the requested state.
func RemovePrivateFile(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncPrivateDirectory(filepath.Dir(path))
}
