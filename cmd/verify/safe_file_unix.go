//go:build unix

package main

import (
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
			return nil, fmt.Errorf("open component %q without following links: %w", component, openErr)
		}
		if closeErr != nil {
			_ = unix.Close(nextDescriptor)
			return nil, fmt.Errorf("close parent of component %q: %w", component, closeErr)
		}
		currentDescriptor = nextDescriptor
	}

	file := os.NewFile(uintptr(currentDescriptor), filepath.Join(root, relative)) //nolint:gosec // successful unix.Openat returns a nonnegative descriptor representable as uintptr
	if file == nil {
		_ = unix.Close(currentDescriptor)
		return nil, fmt.Errorf("adopt safely opened file descriptor")
	}
	if err := ensureRegularFile(file, slashPath); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
