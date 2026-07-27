//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func openRegularFileNoFollow(root, slashPath string) (*os.File, error) {
	relative, err := validatedRelativePath(slashPath)
	if err != nil {
		return nil, err
	}
	rootDescriptor, err := unix.Open(
		root,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open root without following links: %w", err)
	}

	currentDescriptor := rootDescriptor
	components := strings.Split(relative, string(filepath.Separator))
	for index, component := range components {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if index != len(components)-1 {
			flags |= unix.O_DIRECTORY
		}
		nextDescriptor, openErr := unix.Openat(currentDescriptor, component, flags, 0)
		closeErr := unix.Close(currentDescriptor)
		if openErr != nil {
			return nil, errors.Join(
				fmt.Errorf("open component %q without following links: %w", component, openErr),
				wrapCloseError("close parent of component "+component, closeErr),
			)
		}
		if closeErr != nil {
			nextCloseErr := unix.Close(nextDescriptor)
			return nil, errors.Join(
				fmt.Errorf("close parent of component %q: %w", component, closeErr),
				wrapCloseError("close opened component "+component, nextCloseErr),
			)
		}
		currentDescriptor = nextDescriptor
	}

	file := os.NewFile(uintptr(currentDescriptor), filepath.Join(root, relative)) //nolint:gosec // successful unix.Openat returns a nonnegative descriptor representable as uintptr
	if file == nil {
		return nil, errors.Join(
			fmt.Errorf("adopt safely opened file descriptor"),
			wrapCloseError("close unadopted file descriptor", unix.Close(currentDescriptor)),
		)
	}
	if err := ensureRegularFile(file, slashPath); err != nil {
		return nil, errors.Join(err, wrapCloseError("close nonregular path "+slashPath, file.Close()))
	}
	return file, nil
}

func workspaceFileMode(sourceMode os.FileMode) os.FileMode {
	if sourceMode.Perm()&0o111 != 0 {
		return 0o700
	}
	return 0o600
}
