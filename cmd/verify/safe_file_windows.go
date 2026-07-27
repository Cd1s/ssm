//go:build windows

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openRegularFileNoFollow(root, slashPath string) (*os.File, error) {
	relative, err := validatedRelativePath(slashPath)
	if err != nil {
		return nil, err
	}
	fullPath, err := filepath.Abs(filepath.Join(root, relative))
	if err != nil {
		return nil, fmt.Errorf("make path absolute: %w", err)
	}
	ntPath := `\??\` + fullPath
	if strings.HasPrefix(fullPath, `\\`) {
		ntPath = `\??\UNC\` + strings.TrimPrefix(fullPath, `\\`)
	}
	objectName, err := windows.NewNTUnicodeString(ntPath)
	if err != nil {
		return nil, fmt.Errorf("encode path for no-reparse open: %w", err)
	}
	attributes := &windows.OBJECT_ATTRIBUTES{
		ObjectName: objectName,
		Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	attributes.Length = uint32(unsafe.Sizeof(*attributes))

	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.FILE_GENERIC_READ|windows.SYNCHRONIZE,
		attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|
			windows.FILE_SYNCHRONOUS_IO_NONALERT|
			windows.FILE_OPEN_REPARSE_POINT,
		0,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) ||
			errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND) {
			return nil, errors.Join(
				fs.ErrNotExist,
				fmt.Errorf("open path without traversing reparse points: %w", err),
			)
		}
		return nil, fmt.Errorf("open path without traversing reparse points: %w", err)
	}
	file := os.NewFile(uintptr(handle), fullPath)
	if file == nil {
		return nil, errors.Join(
			fmt.Errorf("adopt safely opened Windows handle"),
			wrapCloseError("close unadopted Windows handle", windows.CloseHandle(handle)),
		)
	}
	if err := ensureRegularFile(file, slashPath); err != nil {
		return nil, errors.Join(err, wrapCloseError("close nonregular path "+slashPath, file.Close()))
	}
	return file, nil
}

func workspaceFileMode(os.FileMode) os.FileMode {
	// Windows working-tree files do not expose a Unix executable bit.
	return 0o600
}

func workspaceGitMode(indexMode string, _ os.FileMode) string {
	return indexMode
}
