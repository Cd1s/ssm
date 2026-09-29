package synctransaction

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

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

	stateLockTimeout = time.Second
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
	// ClaimToken identifies the claim a background process was started for. A
	// process whose token no longer matches (login, logout or register reset
	// the state, or a newer claim replaced it) records nothing and installs
	// nothing.
	ClaimToken string `json:"claim_token,omitempty"`
}

func syncStatePath() string { return filepath.Join(config.Dir(), "sync-state.json") }

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

// syncStateLockName is the kernel-level lock (flock/LockFileEx) that
// serialises read-modify-write of the state file. The OS drops it when its
// holder dies, so a crash never leaves a stale lock and never delays a command.
const syncStateLockName = "sync-state.lock"

func withStateLock(fn func() error) error {
	lock, err := config.AcquireFileLock(syncStateLockName, stateLockTimeout)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	return fn()
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

// claimBackground atomically reserves the next automatic attempt and returns
// the claim token to hand to the background process. ok is false when another
// process holds a live claim, the schedule is not due, or the state cannot be
// locked; a foreground command then simply does not spawn.
func (t *Transaction) claimBackground(now time.Time) (token string, ok bool) {
	err := withStateLock(func() error {
		state := LoadSyncState()
		if !state.due(now) {
			return nil
		}
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		state.InFlightUntil = now.Add(claimTTL).UTC().Format(time.RFC3339)
		state.ClaimToken = hex.EncodeToString(raw)
		if err := saveSyncState(state); err != nil {
			return err
		}
		token, ok = state.ClaimToken, true
		return nil
	})
	if err != nil {
		return "", false
	}
	return token, ok
}

// claimStillValid reports whether this transaction may still act for its
// background claim. Foreground transactions carry no claim and always may.
func (t *Transaction) claimStillValid() bool {
	return t.claim == "" || LoadSyncState().ClaimToken == t.claim
}

// mutateState applies fn to the state under the state lock, unless this is a
// background process whose claim was invalidated in the meantime.
func (t *Transaction) mutateState(fn func(*SyncState)) {
	_ = withStateLock(func() error {
		state := LoadSyncState()
		if t.claim != "" && state.ClaimToken != t.claim {
			return nil
		}
		fn(&state)
		return saveSyncState(state)
	})
}

// releaseClaim clears an unused claim after a failed spawn so the next command
// may try again.
func (t *Transaction) releaseClaim() {
	t.mutateState(func(state *SyncState) {
		state.InFlightUntil, state.ClaimToken = "", ""
	})
}

// recordSuccess stores a confirmed sync outcome and schedules the next
// automatic attempt one sync_interval later.
func (t *Transaction) recordSuccess() {
	now := t.now()
	interval := config.LoadSettings().EffectiveSyncInterval()
	t.mutateState(func(state *SyncState) {
		stamp := now.UTC().Format(time.RFC3339)
		state.LastAttemptAt = stamp
		state.LastSuccessAt = stamp
		state.NextAttemptAt = now.Add(interval).UTC().Format(time.RFC3339)
		state.ConsecutiveFailures = 0
		state.LastError = nil
		state.InFlightUntil, state.ClaimToken = "", ""
	})
}

// recordFailure stores a failed sync outcome with exponential backoff.
func (t *Transaction) recordFailure(err error) {
	if err == nil {
		return
	}
	now := t.now()
	cause, message := t.describeFailure(err)
	t.mutateState(func(state *SyncState) {
		stamp := now.UTC().Format(time.RFC3339)
		state.LastAttemptAt = stamp
		state.ConsecutiveFailures++
		state.NextAttemptAt = now.Add(backoffDelay(state.ConsecutiveFailures)).UTC().Format(time.RFC3339)
		state.LastError = &SyncError{Cause: cause, Message: message, At: stamp}
		state.InFlightUntil, state.ClaimToken = "", ""
	})
}

// RecordSkipped ends a background attempt that could not run for a local
// reason (publication in progress). It is not a sync failure: nothing is
// counted, but the next attempt is delayed so commands do not respawn at once.
func (t *Transaction) RecordSkipped() {
	now := t.now()
	t.mutateState(func(state *SyncState) {
		state.NextAttemptAt = now.Add(skippedRetryDelay).UTC().Format(time.RFC3339)
		state.InFlightUntil, state.ClaimToken = "", ""
	})
}

// describeFailure returns the stored cause and a short message. The message is
// never raw error text: server-supplied bodies and local paths must not be
// persisted verbatim, so it comes from the injected sanitizing classifier or,
// failing that, a fixed phrase.
func (t *Transaction) describeFailure(err error) (cause, message string) {
	cause, message = CauseUnknown, "sync failed"
	if t.describe != nil {
		if described, text := t.describe(err); described != "" {
			cause, message = described, text
		}
	}
	switch {
	case errors.Is(err, ErrConflict), errors.Is(err, ErrEmptyLedgerDivergence):
		cause, message = CauseConflict, "local and remote vaults diverged"
	case errors.Is(err, ErrConfiguration):
		cause, message = CauseConfiguration, "sync configuration is invalid"
	}
	return cause, truncateUTF8(message, maxErrorMessageBytes)
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

// errBackgroundSkipped ends a background attempt that must leave local state
// alone for a local reason (vault lock busy, or a publication awaiting
// reconciliation).
var errBackgroundSkipped = errors.New("background sync skipped")

// BackgroundSync performs one detached sync attempt: observe the remote
// identity (bounded by the caller's request timeout), then, only when it
// changed, download it and replace the local vault. It never publishes and
// never overwrites divergent local state, refuses a malformed download, and
// leaves local state alone while a publication awaits reconciliation. The
// download happens outside any lock; the vault write lock is held only to
// re-read local identity and replace the file (see applyRemoteIdentity). The
// outcome, success or failure, is recorded in the sync state, but only while
// claim (the token the parent stored when it started this process) is still the
// live claim; after a reset or a newer claim the process changes nothing.
func (t *Transaction) BackgroundSync(claim string) error {
	if t.offline {
		return nil
	}
	t.claim = claim
	if !t.claimStillValid() {
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
	facts := t.localFacts()
	facts.Configuration = state
	if _, err := t.applyRemoteIdentity(cfg, facts, remote, false, pullBackground); err != nil {
		if errors.Is(err, errBackgroundSkipped) {
			t.RecordSkipped()
			return nil
		}
		t.recordFailure(err)
		return err
	}
	t.recordSuccess()
	return nil
}

// recordSkippedNotConfigured clears a claim when sync stopped being applicable
// between the claim and the attempt (for example logout).
func (t *Transaction) recordSkippedNotConfigured() {
	t.mutateState(func(state *SyncState) {
		state.InFlightUntil, state.ClaimToken = "", ""
	})
}

// resetLockWait bounds the wait for the state lock when resetting.
var resetLockWait = 5 * time.Second

// ResetSyncState forgets the recorded outcome, schedule and claim. Login,
// register and logout call it because the state described the previous
// service; removing the claim also stops any background process still running
// for that service from recording or installing anything. A failure to reset
// is returned so the caller can tell the user.
func ResetSyncState() error {
	if _, err := os.Lstat(syncStatePath()); err != nil {
		return nil
	}
	// Lock order everywhere is vault write lock, then state lock. Holding the
	// vault lock means a background process cannot be between its claim check
	// and its install while the state is removed.
	vaultLock, err := config.AcquireFileLock(config.VaultWriteLockName, resetLockWait)
	if err != nil {
		return fmt.Errorf("reset sync state: %w", err)
	}
	defer func() { _ = vaultLock.Close() }()
	lock, err := config.AcquireFileLock(syncStateLockName, resetLockWait)
	if err != nil {
		return fmt.Errorf("reset sync state: %w", err)
	}
	defer func() { _ = lock.Close() }()
	if err := os.Remove(syncStatePath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reset sync state: %w", err)
	}
	return nil
}

// truncateUTF8 shortens s to at most max bytes without splitting a character.
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
