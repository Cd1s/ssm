package ssh

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"ssm/internal/machinecontract"
)

type fileDownloadPublishOperations struct {
	chmod  func(string, os.FileMode) error
	rename func(string, string) error
}

func systemFileDownloadPublishOperations() fileDownloadPublishOperations {
	return fileDownloadPublishOperations{
		chmod:  os.Chmod,
		rename: os.Rename,
	}
}

type fileDownloadStaging struct {
	file      *os.File
	path      string
	published bool
}

func newFileDownloadStaging(localPath string) (*fileDownloadStaging, error) {
	parent := filepath.Dir(localPath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, transferError(machinecontract.TransferDownloadLocalWrite, 0, fmt.Errorf("create local parent dir: %w", err))
	}
	file, err := os.CreateTemp(parent, ".ssm-get-*")
	if err != nil {
		return nil, transferError(machinecontract.TransferDownloadLocalWrite, 0, err)
	}
	return &fileDownloadStaging{file: file, path: file.Name()}, nil
}

func (staging *fileDownloadStaging) cleanup() {
	if staging == nil {
		return
	}
	_ = staging.file.Close()
	if !staging.published {
		_ = os.Remove(staging.path)
	}
}

func (staging *fileDownloadStaging) publish(localPath string, operations fileDownloadPublishOperations) (int64, error) {
	info, err := staging.file.Stat()
	if err != nil {
		return 0, transferError(machinecontract.TransferDownloadLocalWrite, 0, err)
	}
	received := info.Size()
	if err := staging.file.Close(); err != nil {
		return received, transferError(machinecontract.TransferDownloadLocalWrite, 0, err)
	}
	if err := operations.chmod(staging.path, 0o600); err != nil {
		return received, transferError(machinecontract.TransferDownloadLocalWrite, 0, err)
	}
	if err := operations.rename(staging.path, localPath); err != nil {
		return received, transferError(machinecontract.TransferDownloadPublish, 0, err)
	}
	staging.published = true
	return received, nil
}

type directoryDownloadPublishOperations struct {
	rename func(string, string) error
}

func systemDirectoryDownloadPublishOperations() directoryDownloadPublishOperations {
	return directoryDownloadPublishOperations{rename: os.Rename}
}

type directoryDownloadStaging struct {
	path              string
	destinationExists bool
	published         bool
}

func newDirectoryDownloadStaging(localPath string) (*directoryDownloadStaging, error) {
	parent := filepath.Dir(localPath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, transferError(machinecontract.TransferDownloadLocalWrite, 0, err)
	}
	path, err := os.MkdirTemp(parent, ".ssm-get-dir-*")
	if err != nil {
		return nil, transferError(machinecontract.TransferDownloadLocalWrite, 0, err)
	}
	staging := &directoryDownloadStaging{path: path}
	info, statErr := os.Stat(localPath)
	switch {
	case statErr == nil && !info.IsDir():
		staging.cleanup()
		return nil, transferError(machinecontract.TransferDownloadLocalWrite, 0, fmt.Errorf("local destination is not a directory"))
	case statErr == nil:
		staging.destinationExists = true
		if err := os.CopyFS(path, os.DirFS(localPath)); err != nil {
			staging.cleanup()
			return nil, transferError(machinecontract.TransferDownloadLocalWrite, 0, fmt.Errorf("stage existing local directory: %w", err))
		}
	case !os.IsNotExist(statErr):
		staging.cleanup()
		return nil, transferError(machinecontract.TransferDownloadLocalWrite, 0, statErr)
	}
	return staging, nil
}

func (staging *directoryDownloadStaging) cleanup() {
	if staging == nil || staging.published {
		return
	}
	_ = os.RemoveAll(staging.path)
}

func (staging *directoryDownloadStaging) publish(localPath string, operations directoryDownloadPublishOperations) error {
	parent := filepath.Dir(localPath)
	backup := ""
	var err error
	if staging.destinationExists {
		backup, err = os.MkdirTemp(parent, ".ssm-get-backup-*")
		if err != nil {
			return transferError(machinecontract.TransferDownloadPublish, 0, err)
		}
		if err := os.Remove(backup); err != nil {
			_ = os.RemoveAll(backup)
			return transferError(machinecontract.TransferDownloadPublish, 0, err)
		}
		if err := operations.rename(localPath, backup); err != nil {
			return transferError(machinecontract.TransferDownloadPublish, 0, fmt.Errorf("preserve local directory before publish: %w", err))
		}
	}
	if err := operations.rename(staging.path, localPath); err != nil {
		if backup != "" {
			if restoreErr := operations.rename(backup, localPath); restoreErr != nil {
				return transferError(machinecontract.TransferDownloadRestoreFailed, 0, errors.Join(
					fmt.Errorf("publish local directory: %w", err),
					fmt.Errorf("restore preserved local directory from %s: %w", backup, restoreErr),
				))
			}
		}
		return transferError(machinecontract.TransferDownloadPublish, 0, fmt.Errorf("publish local directory: %w", err))
	}
	staging.published = true
	if backup != "" {
		_ = os.RemoveAll(backup)
	}
	return nil
}
