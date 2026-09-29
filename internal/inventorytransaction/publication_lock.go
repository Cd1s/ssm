package inventorytransaction

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ssm/internal/config"
	"ssm/internal/privatepath"
)

const (
	publicationLockTimeout = 5 * time.Second
	publicationLockRetry   = 25 * time.Millisecond
)

// ErrPublicationBusy reports bounded contention for the cross-process
// publication critical section.
var ErrPublicationBusy = errors.New("publication is busy")

// PublicationSession is the capability proving that one process exclusively
// owns publishing-intent reconciliation and publication sequencing.
type PublicationSession struct {
	file *os.File
}

// BeginPublication acquires the private cross-process publication lock. The
// bounded wait prevents status and publication commands from deadlocking.
func BeginPublication() (*PublicationSession, error) {
	return beginLockWithin("publication.lock", publicationLockTimeout)
}

// BeginVaultWrite acquires the short-lived cross-process vault write lock. It
// serialises the few operations that replace or rewrite the local vault after
// deciding from its current identity: a local mutation's identity check and
// save, a publication's local finalization, and a background pull's compare
// and replace. Unlike the publication lock it is never held across network
// I/O, so a mutation is not blocked by an in-flight publication.
func BeginVaultWrite() (*PublicationSession, error) {
	return beginVaultWriteWithin(publicationLockTimeout)
}

func beginVaultWriteWithin(timeout time.Duration) (*PublicationSession, error) {
	return beginLockWithin("vault-write.lock", timeout)
}

func beginLockWithin(name string, timeout time.Duration) (*PublicationSession, error) {
	if err := config.EnsurePrivateDir(config.Dir()); err != nil {
		return nil, fmt.Errorf("prepare publication lock directory: %w", err)
	}
	path := filepath.Join(config.Dir(), name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // fixed private coordination path
	if err != nil {
		return nil, fmt.Errorf("open publication lock: %w", err)
	}
	if err := privatepath.RestrictFile(path); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("restrict publication lock: %w", err)
	}

	deadline := time.Now().Add(timeout)
	for {
		acquired, lockErr := tryPublicationFileLock(file)
		if lockErr != nil {
			_ = file.Close()
			return nil, fmt.Errorf("acquire publication lock: %w", lockErr)
		}
		if acquired {
			return &PublicationSession{file: file}, nil
		}
		if !time.Now().Before(deadline) {
			_ = file.Close()
			return nil, fmt.Errorf("%w: another process still owns the publication lock", ErrPublicationBusy)
		}
		time.Sleep(publicationLockRetry)
	}
}

// Close releases the advisory lock and closes its file. Process exit also
// releases the OS-owned lock if a command crashes before Close runs.
func (s *PublicationSession) Close() error {
	if s == nil || s.file == nil {
		return nil
	}
	file := s.file
	s.file = nil
	unlockErr := unlockPublicationFile(file)
	closeErr := file.Close()
	return errors.Join(unlockErr, closeErr)
}

func (s *PublicationSession) active() bool {
	return s != nil && s.file != nil
}
