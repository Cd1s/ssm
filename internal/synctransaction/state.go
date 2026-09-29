package synctransaction

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ssm/internal/cloud"
	"ssm/internal/config"
)

// Background sync scheduling constants. The claim time-to-live must exceed the
// longest a healthy background process can run (publication lock wait plus two
// bounded HTTP requests) so an abandoned claim, for example from a killed
// process, expires without letting a healthy one be double-started.
const (
	BackgroundRequestTimeout = 5 * time.Second
	backoffBase              = 30 * time.Second
	backoffCap               = time.Hour
	claimTTL                 = 2 * time.Minute
	maxScheduleHorizon       = 30 * 24 * time.Hour
	skippedRetryDelay        = 30 * time.Second
	maxErrorMessageBytes     = 300

	stateLockStaleAfter = 10 * time.Second
	stateLockTimeout    = time.Second
)

// Failure causes recorded by this package itself. Transport and HTTP causes
// come from the classifier supplied through Options.DescribeFailure.
const (
	CauseConflict      = "conflict"
	CauseConfiguration = "configuration"
	CauseUnknown       = "unknown"
)

// SyncError is the redacted, address-free description of the last failed sync
// attempt.
type SyncError struct {
	Cause   string `json:"cause"`
	Message string `json:"message"`
	At      string `json:"at"`
}

// SyncState is the durable scheduling and outcome record of automatic and
// explicit synchronization. It contains no inventory, credentials or server
// address.
type SyncState struct {
	LastAttemptAt       string     `json:"last_attempt_at,omitempty"`
	LastSuccessAt       string     `json:"last_success_at,omitempty"`
	NextAttemptAt       string     `json:"next_attempt_at,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	LastError           *SyncError `json:"last_error,omitempty"`
	// InFlightUntil is the atomic claim that keeps concurrent commands from
	// each spawning a background sync.
	InFlightUntil string `json:"in_flight_until,omitempty"`
}

func syncStatePath() string { return filepath.Join(config.Dir(), "sync-state.json") }

func syncStateLockPath() string { return filepath.Join(config.Dir(), "sync-state.lock") }

// LoadSyncState reads the state file. A missing or unreadable file is the zero
// state: it never blocks a command.
func LoadSyncState() SyncState {
	data, err := os.ReadFile(syncStatePath()) //nolint:gosec // fixed private state path under the SSM config directory
	if err != nil {
		return SyncState{}
	}
	var state SyncState
	if err := json.Unmarshal(data, &state); err != nil {
		return SyncState{}
	}
	return state
}

func saveSyncState(state SyncState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return config.WritePrivateFile(syncStatePath(), append(data, '\n'))
}

var errStateLockBusy = errors.New("sync state lock is busy")

// withStateLock serializes read-modify-write of the state file across
// processes with an exclusive-create lock file. The critical section is a few
// local file operations, so a lock older than stateLockStaleAfter belongs to a
// crashed process and is taken over.
func withStateLock(fn func() error) error {
	if err := config.EnsurePrivateDir(config.Dir()); err != nil {
		return err
	}
	path := syncStateLockPath()
	deadline := time.Now().Add(stateLockTimeout)
	for {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // fixed private coordination path
		if err == nil {
			_ = file.Close()
			defer func() { _ = os.Remove(path) }()
			return fn()
		}
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > stateLockStaleAfter {
			_ = os.Remove(path)
			continue
		}
		if !time.Now().Before(deadline) {
			return errStateLockBusy
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func parseStateTime(raw string) time.Time {
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

// due reports whether an automatic attempt may start at now. A schedule or
// claim further in the future than it could legitimately be set (a clock that
// jumped backwards, or a corrupted file) is ignored so sync cannot be disabled
// indefinitely.
func (s SyncState) due(now time.Time) bool {
	if next := parseStateTime(s.NextAttemptAt); !next.IsZero() && now.Before(next) && next.Sub(now) <= maxScheduleHorizon {
		return false
	}
	if inFlight := parseStateTime(s.InFlightUntil); !inFlight.IsZero() && now.Before(inFlight) && inFlight.Sub(now) <= claimTTL {
		return false
	}
	return true
}

// backoffDelay is 30s for the first consecutive failure, doubling up to one
// hour.
func backoffDelay(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	delay := backoffBase
	for i := 1; i < failures; i++ {
		delay *= 2
		if delay >= backoffCap {
			return backoffCap
		}
	}
	return delay
}

// claimBackground atomically reserves the next automatic attempt. It returns
// false when another process holds a live claim, the schedule is not due, or
// the state cannot be locked; a foreground command then simply does not spawn.
func (t *Transaction) claimBackground(now time.Time) bool {
	claimed := false
	err := withStateLock(func() error {
		state := LoadSyncState()
		if !state.due(now) {
			return nil
		}
		state.InFlightUntil = now.Add(claimTTL).UTC().Format(time.RFC3339)
		if err := saveSyncState(state); err != nil {
			return err
		}
		claimed = true
		return nil
	})
	return err == nil && claimed
}

// releaseClaim clears an unused claim after a failed spawn so the next command
// may try again.
func (t *Transaction) releaseClaim() {
	_ = withStateLock(func() error {
		state := LoadSyncState()
		state.InFlightUntil = ""
		return saveSyncState(state)
	})
}

// recordSuccess stores a confirmed sync outcome and schedules the next
// automatic attempt one sync_interval later.
func (t *Transaction) recordSuccess() {
	now := t.now()
	interval := config.LoadSettings().EffectiveSyncInterval()
	_ = withStateLock(func() error {
		state := LoadSyncState()
		stamp := now.UTC().Format(time.RFC3339)
		state.LastAttemptAt = stamp
		state.LastSuccessAt = stamp
		state.NextAttemptAt = now.Add(interval).UTC().Format(time.RFC3339)
		state.ConsecutiveFailures = 0
		state.LastError = nil
		state.InFlightUntil = ""
		return saveSyncState(state)
	})
}

// recordFailure stores a failed sync outcome with exponential backoff.
func (t *Transaction) recordFailure(err error) {
	if err == nil {
		return
	}
	now := t.now()
	cause, message := t.describeFailure(err)
	_ = withStateLock(func() error {
		state := LoadSyncState()
		stamp := now.UTC().Format(time.RFC3339)
		state.LastAttemptAt = stamp
		state.ConsecutiveFailures++
		state.NextAttemptAt = now.Add(backoffDelay(state.ConsecutiveFailures)).UTC().Format(time.RFC3339)
		state.LastError = &SyncError{Cause: cause, Message: message, At: stamp}
		state.InFlightUntil = ""
		return saveSyncState(state)
	})
}

// RecordSkipped ends a background attempt that could not run for a local
// reason (publication in progress). It is not a sync failure: nothing is
// counted, but the next attempt is delayed so commands do not respawn at once.
func (t *Transaction) RecordSkipped() {
	now := t.now()
	_ = withStateLock(func() error {
		state := LoadSyncState()
		state.NextAttemptAt = now.Add(skippedRetryDelay).UTC().Format(time.RFC3339)
		state.InFlightUntil = ""
		return saveSyncState(state)
	})
}

func (t *Transaction) describeFailure(err error) (cause, message string) {
	cause, message = CauseUnknown, err.Error()
	if t.describe != nil {
		if described, text := t.describe(err); described != "" {
			cause, message = described, text
		}
	}
	switch {
	case errors.Is(err, ErrConflict), errors.Is(err, ErrEmptyLedgerDivergence):
		cause = CauseConflict
	case errors.Is(err, ErrConfiguration):
		cause = CauseConfiguration
	}
	if len(message) > maxErrorMessageBytes {
		message = message[:maxErrorMessageBytes]
	}
	return cause, message
}

// recordOutcome records the result of an explicit or background sync
// operation. A nil error is a confirmed success.
func (t *Transaction) recordOutcome(err error) {
	if t.offline {
		return
	}
	if err == nil {
		t.recordSuccess()
		return
	}
	// Only failures of the sync exchange or its safety checks describe the
	// remote; missing configuration is a usage error, not a sync outcome.
	if errors.Is(err, ErrUnconfigured) {
		return
	}
	t.recordFailure(err)
}

// remoteStateFromState maps the last recorded outcome to the reported remote
// state for local-first reads. A conflict proves the service was reached.
func remoteStateFromState(state SyncState) RemoteState {
	switch {
	case state.LastError != nil && state.LastError.Cause != CauseConflict:
		return RemoteUnreachable
	case state.LastSuccessAt != "" || state.LastError != nil:
		return RemoteChecked
	default:
		return RemoteNotChecked
	}
}

// ErrBackgroundSkipped is returned by a BackgroundSync lock callback to end the
// attempt without recording a sync failure (for example while a publication is
// in progress).
var ErrBackgroundSkipped = errors.New("background sync skipped")

// BackgroundSync performs one detached sync attempt: observe the remote
// identity (bounded by the caller's request timeout), then, only when it
// changed, take exclusive ownership through lock and refresh. It never
// publishes and never overwrites divergent local state. lock returns a release
// function, or ErrBackgroundSkipped when local state must not be touched now.
// The outcome, success or failure, is recorded in the sync state.
func (t *Transaction) BackgroundSync(lock func() (release func(), err error)) error {
	if t.offline {
		return nil
	}
	cfg, state, err := t.configuration()
	if err != nil {
		t.recordFailure(err)
		return err
	}
	if state != ConfigurationConfigured || !config.LoadSettings().AutoSync {
		t.recordSkippedNotConfigured()
		return nil
	}
	remote, err := cloud.RemoteETag(cfg)
	if err != nil {
		err = fmt.Errorf("%w: remote refresh did not commit: %w", ErrRefresh, err)
		t.recordFailure(err)
		return err
	}
	release, err := lock()
	if err != nil {
		t.RecordSkipped()
		return nil
	}
	defer release()
	facts := t.localFacts()
	facts.Configuration = state
	if _, err := t.applyRemoteIdentity(cfg, facts, remote, false); err != nil {
		t.recordFailure(err)
		return err
	}
	t.recordSuccess()
	return nil
}

// recordSkippedNotConfigured clears a claim when sync stopped being applicable
// between the claim and the attempt (for example logout).
func (t *Transaction) recordSkippedNotConfigured() {
	_ = withStateLock(func() error {
		state := LoadSyncState()
		state.InFlightUntil = ""
		return saveSyncState(state)
	})
}

// ResetSyncState forgets the recorded outcome and schedule. Login, register
// and logout call it because the state described the previous service.
func ResetSyncState() {
	if _, err := os.Lstat(syncStatePath()); err != nil {
		return
	}
	_ = withStateLock(func() error {
		if err := os.Remove(syncStatePath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	})
}
