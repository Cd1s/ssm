//go:build unix

package privatepath

import (
	"fmt"
	"os"
)

func RestrictDirectory(path string) error {
	if err := requirePathType(path, true); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o700); err != nil { //nolint:gosec // private directories require owner traversal
		return fmt.Errorf("restrict private directory mode: %w", err)
	}
	return VerifyDirectory(path)
}

func VerifyDirectory(path string) error {
	if err := requirePathType(path, true); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private directory mode: %w", err)
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("private directory mode is %o, need 700", info.Mode().Perm())
	}
	return nil
}

func RestrictFile(path string) error {
	if err := requirePathType(path, false); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict private file mode: %w", err)
	}
	return VerifyFile(path)
}

func VerifyFile(path string) error {
	if err := requirePathType(path, false); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private file mode: %w", err)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("private file mode is %o, need 600", info.Mode().Perm())
	}
	return nil
}

func requirePathType(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private path is a symbolic link")
	}
	if directory && !info.IsDir() {
		return fmt.Errorf("private path is not a directory")
	}
	if !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("private path is not a regular file")
	}
	return nil
}
