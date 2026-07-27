package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func validateTrackedWorktreePaths(repoRoot string, environment []string) error {
	command := exec.Command("git", "-C", repoRoot, "ls-files", "-z", "--") //nolint:gosec // fixed read-only Git metadata argv
	command.Env = environment
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("enumerate tracked worktree paths: %w", err)
	}

	seen := make(map[string]struct{})
	for _, encodedPath := range bytes.Split(bytes.TrimSuffix(output, []byte{0}), []byte{0}) {
		if len(encodedPath) == 0 {
			continue
		}
		trackedPath := string(encodedPath)
		if _, ok := seen[trackedPath]; ok {
			continue
		}
		seen[trackedPath] = struct{}{}

		file, openErr := openRegularFileNoFollow(repoRoot, trackedPath)
		if openErr != nil {
			return fmt.Errorf("unsafe tracked worktree path %q: %w", trackedPath, openErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return fmt.Errorf("close tracked worktree path %q: %w", trackedPath, closeErr)
		}
	}
	return nil
}

func validatedRelativePath(slashPath string) (string, error) {
	if slashPath == "" || strings.ContainsRune(slashPath, 0) {
		return "", fmt.Errorf("invalid empty or NUL-containing path")
	}
	if filepath.IsAbs(filepath.FromSlash(slashPath)) {
		return "", fmt.Errorf("absolute path is not allowed")
	}
	components := strings.Split(slashPath, "/")
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return "", fmt.Errorf("unsafe path component %q", component)
		}
	}
	return filepath.FromSlash(slashPath), nil
}

func ensureRegularFile(file *os.File, displayPath string) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened path %s: %w", displayPath, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("opened path %s is not a regular file", displayPath)
	}
	return nil
}

func readRegularFileNoFollow(root, slashPath string) ([]byte, error) {
	file, err := openRegularFileNoFollow(root, slashPath)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read safely opened path %s: %w", slashPath, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close safely opened path %s: %w", slashPath, closeErr)
	}
	return data, nil
}
