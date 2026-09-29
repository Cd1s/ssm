package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ssm/internal/privatepath"
)

// ErrLockBusy reports that a cross-process lock stayed held past the caller's
// bounded wait.
var ErrLockBusy = errors.New("lock is busy")

// VaultWriteLockName is the coordination file of the short vault write lock.
// It serialises every operation that replaces or rewrites the local vault after
// deciding from its current identity: a local mutation's check-and-save, a
// publication's local finalization, and every pull's compare-and-replace. It is
// never held across network I/O.
const VaultWriteLockName = "vault-write.lock"

const fileLockRetry = 10 * time.Millisecond

// FileLock is an exclusive kernel-level advisory lock on a private file in the
// configuration directory (flock on Unix, LockFileEx on Windows). The OS
// releases it if the holder crashes, so it never goes stale.
type FileLock struct {
	file *os.File
}

// AcquireFileLock takes the named lock, waiting at most timeout, and returns
// ErrLockBusy if it is still held.
func AcquireFileLock(name string, timeout time.Duration) (*FileLock, error) {
	if err := EnsurePrivateDir(Dir()); err != nil {
		return nil, fmt.Errorf("prepare lock directory: %w", err)
	}
	path := filepath.Join(Dir(), name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // fixed private coordination path
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := privatepath.RestrictFile(path); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("restrict lock file: %w", err)
	}
	deadline := time.Now().Add(timeout)
	for {
		acquired, lockErr := tryFileLock(file)
		if lockErr != nil {
			_ = file.Close()
			return nil, fmt.Errorf("acquire lock: %w", lockErr)
		}
		if acquired {
			return &FileLock{file: file}, nil
		}
		if !time.Now().Before(deadline) {
			_ = file.Close()
			return nil, ErrLockBusy
		}
		time.Sleep(fileLockRetry)
	}
}

// Close releases the lock. It is safe to call more than once.
func (l *FileLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	file := l.file
	l.file = nil
	unlockErr := unlockFile(file)
	closeErr := file.Close()
	return errors.Join(unlockErr, closeErr)
}

// PublishingIntentPath is the durable publication recovery record. Only the
// existence of the file is consulted outside the inventory transaction.
func PublishingIntentPath() string { return filepath.Join(Dir(), "publishing-intent.json") }
