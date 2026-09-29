package inventorytransaction

import (
	"errors"
	"fmt"
	"time"

	"ssm/internal/config"
)

const (
	publicationLockTimeout = 5 * time.Second
)

// ErrPublicationBusy reports bounded contention for the cross-process
// publication critical section.
var ErrPublicationBusy = errors.New("publication is busy")

// PublicationSession is the capability proving that one process exclusively
// owns publishing-intent reconciliation and publication sequencing.
type PublicationSession struct {
	lock *config.FileLock
}

// BeginPublication acquires the private cross-process publication lock. The
// bounded wait prevents status and publication commands from deadlocking.
func BeginPublication() (*PublicationSession, error) {
	lock, err := config.AcquireFileLock("publication.lock", publicationLockTimeout)
	if err != nil {
		if errors.Is(err, config.ErrLockBusy) {
			return nil, fmt.Errorf("%w: another process still owns the publication lock", ErrPublicationBusy)
		}
		return nil, fmt.Errorf("acquire publication lock: %w", err)
	}
	return &PublicationSession{lock: lock}, nil
}

// lockVaultWrite takes the short vault write lock (see config.VaultWriteLockName)
// for a bounded wait. Unlike the publication lock it is never held across
// network I/O, so a mutation is not blocked by an in-flight publication.
func lockVaultWrite(wait time.Duration) (*config.FileLock, error) {
	lock, err := config.AcquireFileLock(config.VaultWriteLockName, wait)
	if errors.Is(err, config.ErrLockBusy) {
		return nil, ErrVaultBusy
	}
	return lock, err
}

// Close releases the advisory lock and closes its file. Process exit also
// releases the OS-owned lock if a command crashes before Close runs.
func (s *PublicationSession) Close() error {
	if s == nil || s.lock == nil {
		return nil
	}
	lock := s.lock
	s.lock = nil
	return lock.Close()
}

func (s *PublicationSession) active() bool {
	return s != nil && s.lock != nil
}
