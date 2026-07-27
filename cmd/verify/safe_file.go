package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type trackedWorktreeFile struct {
	Path string
	Mode string
}

type actionWorkspaceEntry struct {
	Path          string
	Type          string
	Mode          fs.FileMode
	ModTime       int64
	Tracked       bool
	ContentSize   int
	ContentDigest [sha256.Size]byte
}

type actionWorkspaceState struct {
	Digest  []byte
	Entries []actionWorkspaceEntry
}

func validateTrackedWorktreePaths(ctx context.Context, repoRoot string, environment []string) error {
	_, err := inspectTrackedWorktreeLayout(ctx, repoRoot, environment)
	return err
}

func inspectTrackedWorktreeLayout(
	ctx context.Context,
	repoRoot string,
	environment []string,
) ([]trackedWorktreeFile, error) {
	git, err := newSourceGit(ctx, repoRoot, environment)
	if err != nil {
		return nil, err
	}
	for _, key := range []string{"core.sparseCheckout", "index.sparse"} {
		output, err := git.output("config", "--no-includes", "--bool", "--get", key)
		if err == nil && strings.TrimSpace(string(output)) == "true" {
			return nil, fmt.Errorf("unsupported sparse checkout/index layout: %s is enabled", key)
		}
		var exitErr interface{ ExitCode() int }
		if err != nil && (!errors.As(err, &exitErr) || exitErr.ExitCode() != 1) {
			return nil, fmt.Errorf("inspect sparse checkout/index setting %s: %w", key, err)
		}
	}

	flags, err := git.output("ls-files", "-v", "-z", "--")
	if err != nil {
		return nil, fmt.Errorf("enumerate tracked index flags: %w", err)
	}
	for _, encodedEntry := range bytes.Split(bytes.TrimSuffix(flags, []byte{0}), []byte{0}) {
		if len(encodedEntry) == 0 {
			continue
		}
		if len(encodedEntry) < 3 || encodedEntry[1] != ' ' {
			return nil, fmt.Errorf("invalid tracked index flag entry")
		}
		if encodedEntry[0] == 'S' || encodedEntry[0] == 's' {
			return nil, fmt.Errorf(
				"unsupported sparse skip-worktree index state for tracked path %q",
				string(encodedEntry[2:]),
			)
		}
	}

	output, err := git.output("ls-files", "--stage", "-z", "--")
	if err != nil {
		return nil, fmt.Errorf("enumerate tracked worktree index entries: %w", err)
	}

	seen := make(map[string]struct{})
	files := make([]trackedWorktreeFile, 0)
	for _, encodedEntry := range bytes.Split(bytes.TrimSuffix(output, []byte{0}), []byte{0}) {
		if len(encodedEntry) == 0 {
			continue
		}
		metadata, encodedPath, ok := bytes.Cut(encodedEntry, []byte{'\t'})
		if !ok {
			return nil, fmt.Errorf("invalid tracked index entry metadata")
		}
		fields := bytes.Fields(metadata)
		if len(fields) != 3 {
			return nil, fmt.Errorf("invalid tracked index entry metadata")
		}
		mode, stage := string(fields[0]), string(fields[2])
		trackedPath := string(encodedPath)
		if stage != "0" {
			return nil, fmt.Errorf("unsupported unmerged index stage %s for tracked path %q", stage, trackedPath)
		}
		switch mode {
		case "100644", "100755":
		case "120000":
			return nil, fmt.Errorf("unsupported tracked symlink mode 120000 for path %q", trackedPath)
		case "160000":
			return nil, fmt.Errorf("unsupported tracked gitlink mode 160000 for path %q", trackedPath)
		default:
			return nil, fmt.Errorf("unsupported tracked index mode %s for path %q", mode, trackedPath)
		}
		relative, pathErr := validatedRelativePath(trackedPath)
		if pathErr != nil {
			return nil, fmt.Errorf("unsafe tracked path %q: %w", trackedPath, pathErr)
		}
		for _, component := range strings.Split(relative, string(filepath.Separator)) {
			if strings.EqualFold(component, ".git") {
				return nil, fmt.Errorf("unsupported tracked .git path component in %q", trackedPath)
			}
		}
		if _, ok := seen[trackedPath]; ok {
			return nil, fmt.Errorf("duplicate stage-0 tracked path %q", trackedPath)
		}
		seen[trackedPath] = struct{}{}

		file, openErr := openRegularFileNoFollow(repoRoot, trackedPath)
		if openErr != nil {
			if errors.Is(openErr, fs.ErrNotExist) {
				return nil, fmt.Errorf("missing tracked path %q in fully populated worktree: %w", trackedPath, openErr)
			}
			return nil, fmt.Errorf("unsafe tracked worktree path %q: %w", trackedPath, openErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return nil, fmt.Errorf("close tracked worktree path %q: %w", trackedPath, closeErr)
		}
		files = append(files, trackedWorktreeFile{Path: trackedPath, Mode: mode})
	}
	return files, nil
}

func materializeActionWorkspace(
	ctx context.Context,
	repoRoot string,
	workspaceRoot string,
	environment []string,
) ([]trackedWorktreeFile, error) {
	files, err := inspectTrackedWorktreeLayout(ctx, repoRoot, environment)
	if err != nil {
		return nil, err
	}
	//nolint:gosec // workspaceRoot is a verifier-created child of the private profile temporary directory
	if err := os.Mkdir(workspaceRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create action workspace: %w", err)
	}
	for _, tracked := range files {
		if err := copyTrackedFile(repoRoot, workspaceRoot, tracked); err != nil {
			return nil, err
		}
	}
	return files, nil
}

func copyTrackedFile(repoRoot, workspaceRoot string, tracked trackedWorktreeFile) error {
	relative, err := validatedRelativePath(tracked.Path)
	if err != nil {
		return fmt.Errorf("validate tracked copy path %q: %w", tracked.Path, err)
	}
	source, err := openRegularFileNoFollow(repoRoot, tracked.Path)
	if err != nil {
		return fmt.Errorf("open tracked copy source %q: %w", tracked.Path, err)
	}
	sourceInfo, statErr := source.Stat()
	if statErr != nil {
		return errors.Join(
			fmt.Errorf("inspect tracked copy source %q: %w", tracked.Path, statErr),
			wrapCloseError("close tracked copy source "+tracked.Path, source.Close()),
		)
	}

	parent := filepath.Dir(filepath.Join(workspaceRoot, relative))
	//nolint:gosec // relative is a validated tracked path beneath the private action workspace
	if mkdirErr := os.MkdirAll(parent, 0o700); mkdirErr != nil {
		return errors.Join(
			fmt.Errorf("create action workspace parent for %q: %w", tracked.Path, mkdirErr),
			wrapCloseError("close tracked copy source "+tracked.Path, source.Close()),
		)
	}
	mode := workspaceFileMode(sourceInfo.Mode())
	targetPath := filepath.Join(workspaceRoot, relative)
	target, createErr := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // target is beneath the verifier-created private action workspace
	if createErr != nil {
		return errors.Join(
			fmt.Errorf("create action workspace file %q: %w", tracked.Path, createErr),
			wrapCloseError("close tracked copy source "+tracked.Path, source.Close()),
		)
	}
	_, copyErr := io.Copy(target, source)
	targetCloseErr := target.Close()
	sourceCloseErr := source.Close()
	if copyErr != nil || targetCloseErr != nil || sourceCloseErr != nil {
		return errors.Join(
			wrapError("copy tracked action workspace file "+tracked.Path, copyErr),
			wrapCloseError("close action workspace file "+tracked.Path, targetCloseErr),
			wrapCloseError("close tracked copy source "+tracked.Path, sourceCloseErr),
		)
	}
	return nil
}

func actionWorkspaceSnapshot(workspaceRoot string, tracked []trackedWorktreeFile) (actionWorkspaceState, error) {
	digest := sha256.New()
	entries := make([]actionWorkspaceEntry, 0, len(tracked))
	entryIndex := make(map[string]int, len(tracked))
	//nolint:gosec // workspaceRoot is the verifier-created private action workspace
	err := filepath.WalkDir(workspaceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(workspaceRoot, path)
		if err != nil {
			return err
		}
		if relative == "." {
			relative = ""
		}
		relative = filepath.ToSlash(relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		entryIndex[relative] = len(entries)
		entries = append(entries, actionWorkspaceEntry{
			Path:    relative,
			Type:    info.Mode().Type().String(),
			Mode:    info.Mode().Perm(),
			ModTime: info.ModTime().UnixNano(),
		})
		_, _ = fmt.Fprintf(
			digest,
			"path\x00%s\x00type\x00%s\x00mode\x00%o\x00mtime\x00%d\x00",
			relative,
			info.Mode().Type().String(),
			info.Mode().Perm(),
			info.ModTime().UnixNano(),
		)
		return nil
	})
	if err != nil {
		return actionWorkspaceState{}, fmt.Errorf("enumerate action workspace: %w", err)
	}
	for _, file := range tracked {
		data, err := readRegularFileNoFollow(workspaceRoot, file.Path)
		if err != nil {
			return actionWorkspaceState{}, fmt.Errorf("snapshot action workspace tracked path %q: %w", file.Path, err)
		}
		path := filepath.ToSlash(file.Path)
		index, ok := entryIndex[path]
		if !ok {
			return actionWorkspaceState{}, fmt.Errorf("tracked action workspace path %q was not enumerated", file.Path)
		}
		entries[index].Tracked = true
		entries[index].ContentSize = len(data)
		entries[index].ContentDigest = sha256.Sum256(data)
		_, _ = fmt.Fprintf(digest, "tracked\x00%s\x00%d\x00", file.Path, len(data))
		_, _ = digest.Write(data)
	}
	return actionWorkspaceState{Digest: digest.Sum(nil), Entries: entries}, nil
}

func describeActionWorkspaceDifference(before, after actionWorkspaceState) string {
	beforeByPath := make(map[string]actionWorkspaceEntry, len(before.Entries))
	for _, entry := range before.Entries {
		beforeByPath[entry.Path] = entry
	}
	for _, current := range after.Entries {
		original, ok := beforeByPath[current.Path]
		if !ok {
			return fmt.Sprintf("path %q was added", current.Path)
		}
		delete(beforeByPath, current.Path)
		switch {
		case original.Type != current.Type:
			return fmt.Sprintf("path %q type changed from %q to %q", current.Path, original.Type, current.Type)
		case original.Mode != current.Mode:
			return fmt.Sprintf("path %q mode changed from %o to %o", current.Path, original.Mode, current.Mode)
		case original.ModTime != current.ModTime:
			return fmt.Sprintf("path %q mtime changed from %d to %d", current.Path, original.ModTime, current.ModTime)
		case original.Tracked != current.Tracked:
			return fmt.Sprintf("path %q tracked snapshot membership changed", current.Path)
		case original.ContentSize != current.ContentSize:
			return fmt.Sprintf(
				"path %q content size changed from %d to %d",
				current.Path,
				original.ContentSize,
				current.ContentSize,
			)
		case original.ContentDigest != current.ContentDigest:
			return fmt.Sprintf("path %q content changed", current.Path)
		}
	}
	for path := range beforeByPath {
		return fmt.Sprintf("path %q was removed", path)
	}
	return "snapshot digest changed without an entry-level difference"
}

func wrapError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func wrapCloseError(operation string, err error) error {
	return wrapError(operation, err)
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
	return readAndCloseRegularFile(file, slashPath)
}

func readAndCloseRegularFile(file io.ReadCloser, displayPath string) ([]byte, error) {
	data, readErr := io.ReadAll(file)
	closeErr := file.Close()
	err := errors.Join(
		wrapError("read safely opened path "+displayPath, readErr),
		wrapCloseError("close safely opened path "+displayPath, closeErr),
	)
	if err != nil {
		return nil, err
	}
	return data, nil
}
