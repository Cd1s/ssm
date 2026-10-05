// Package synctransaction owns synchronization state and sequencing for
// inventory consumers. It deliberately operates only on opaque encrypted
// vault blobs; decrypted inventory belongs to callers.
package synctransaction

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"ssm/internal/cloud"
	"ssm/internal/config"
)

type ConfigurationState string

const (
	ConfigurationOffline      ConfigurationState = "offline"
	ConfigurationUnconfigured ConfigurationState = "unconfigured"
	ConfigurationConfigured   ConfigurationState = "configured"
	ConfigurationInvalid      ConfigurationState = "invalid"
)

type Freshness string

const (
	FreshnessUnknown    Freshness = "unknown"
	FreshnessFresh      Freshness = "fresh"
	FreshnessCached     Freshness = "cached"
	FreshnessLocalAhead Freshness = "local_ahead"
)

type RemoteState string

const (
	RemoteChecked          RemoteState = "checked"
	RemoteNotChecked       RemoteState = "not_checked"
	RemoteUnreachable      RemoteState = "unreachable"
	RemoteNotConfigured    RemoteState = "not_configured"
	RemoteAutoSyncDisabled RemoteState = "auto_sync_disabled"
)

// SyncConflict preserves only opaque encrypted-blob identities. It never
// contains decrypted inventory, configuration, or credentials.
type SyncConflict struct {
	DetectedAt string `json:"detected_at"`
	LocalETag  string `json:"local_etag"`
	RemoteETag string `json:"remote_etag"`
	CachedETag string `json:"cached_etag"`
}

var (
	ErrConfiguration         = errors.New("sync configuration is invalid")
	ErrUnconfigured          = errors.New("not logged in (run: ssm login)")
	ErrRefresh               = errors.New("sync refresh failed")
	ErrConflict              = errors.New("sync conflict")
	ErrEmptyLedgerDivergence = errors.New("empty-ledger sync divergence")
	ErrPushNotSent           = errors.New("publication request was not sent")
	ErrPushRejected          = errors.New("publication request was explicitly rejected")
	ErrPushAmbiguous         = errors.New("publication commit is ambiguous")
	ErrStreamRefresh         = errors.New("--refresh=0 requires explicit global --offline")
	errStreamNotInitialized  = errors.New("stream synchronization is not initialized")
)

// BlobIdentity is a secret-free opaque identity observation. Exists makes a
// missing first-push prerequisite an exact state rather than an empty string.
type BlobIdentity struct {
	Exists bool
	Value  string
}

func (identity BlobIdentity) equal(other BlobIdentity) bool {
	return identity.Exists == other.Exists && (!identity.Exists || identity.Value == other.Value)
}

// PreparedPublication binds the exact remote prerequisite observed after the
// preliminary intent to the locally known encrypted target identity. Callers
// persist this confirmed plan before PUT.
type PreparedPublication struct {
	Prerequisite BlobIdentity
	Target       string
}

var publicationIdentityPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// PublicationTargetIdentity computes the safe identity of exact encrypted
// bytes before any network access.
func PublicationTargetIdentity(blob []byte) string {
	return opaqueIdentity(blob)
}

// CachedPublicationPrerequisite returns the last confirmed remote identity
// without configuration parsing or network access. An empty cache represents
// the compatible first-push prerequisite state.
func (t *Transaction) CachedPublicationPrerequisite() (BlobIdentity, error) {
	cached := cachedRemoteIdentity()
	if cached != "" && !publicationIdentityPattern.MatchString(cached) {
		return BlobIdentity{}, fmt.Errorf("%w: cached remote identity is unsupported", ErrRefresh)
	}
	return BlobIdentity{Exists: cached != "", Value: cached}, nil
}

// VerifyEmptyPublication compares the exact local encrypted blob, last
// confirmed remote identity, and current remote identity for an empty
// publication scope. It never sends or retrieves a blob. A mismatch persists
// only opaque identity evidence so recovery can be reviewed without exposing
// inventory or overwriting either side.
func (t *Transaction) VerifyEmptyPublication() error {
	local, err := localOpaqueIdentity()
	if err != nil {
		return fmt.Errorf("%w: local encrypted blob identity was not read", ErrRefresh)
	}
	cached, err := t.CachedPublicationPrerequisite()
	if err != nil {
		return err
	}
	remote, err := t.ObservePublicationIdentity()
	if err != nil {
		return err
	}
	if cached.Exists && remote.Exists &&
		local == cached.Value && local == remote.Value {
		return nil
	}

	remoteValue := ""
	if remote.Exists {
		remoteValue = remote.Value
	}
	cachedValue := ""
	if cached.Exists {
		cachedValue = cached.Value
	}
	conflict := SyncConflict{
		DetectedAt: t.now().UTC().Format(time.RFC3339),
		LocalETag:  local,
		RemoteETag: remoteValue,
		CachedETag: cachedValue,
	}
	if err := preserveConflict(conflict); err != nil {
		return fmt.Errorf("%w: empty-ledger conflict evidence could not be preserved", ErrRefresh)
	}
	return fmt.Errorf(
		"%w: local, cached, and remote encrypted blob identities are not identical",
		ErrEmptyLedgerDivergence,
	)
}

type Facts struct {
	Configuration ConfigurationState
	Offline       bool
	Freshness     Freshness
	Remote        RemoteState
	CacheAge      int64
	LastPull      string
	LastPush      string
	LastSync      string
	LocalETag     string
	RemoteETag    string
	Conflict      *SyncConflict
	Changed       bool

	// Local-first facts. They describe the last background or explicit sync
	// outcome recorded in sync-state.json; they are empty in strict mode.
	LastSuccess string
	NextAttempt string
	LastError   *SyncError
	Stale       bool
	// Unsynced is set when sync is configured but no pull, push or background
	// check has ever confirmed the local inventory.
	Unsynced bool
}

type Options struct {
	Offline    bool
	Invalidate func()
	Now        func() time.Time
	// SpawnBackground starts the detached background sync process. It is
	// called only in local-first mode, only when an automatic attempt is due
	// and this process won the atomic claim. Nil disables background sync.
	SpawnBackground func(claimToken string) error
	// DescribeFailure classifies a sync failure into a stable cause and a
	// redacted, address-free message for the recorded last_error.
	DescribeFailure func(error) (cause, message string)
	// Observe receives the facts of every successful inventory-read Refresh.
	Observe func(Facts)
}

type Transaction struct {
	offline    bool
	invalidate func()
	now        func() time.Time
	spawn      func(claimToken string) error
	describe   func(error) (string, string)
	observe    func(Facts)
	// claim is the background claim token this process acts for ("" in the
	// foreground).
	claim string
}

// Stream owns synchronization policy for one run --stream process lifetime.
// Offline streams never inspect cloud configuration or refresh after startup.
// Online streams refresh at the configured positive cadence and stop on the
// first refresh failure.
type Stream struct {
	transaction *Transaction
	interval    time.Duration
	nextRefresh time.Time
	initialized bool
	// baseline is the local encrypted-blob identity the stream last observed
	// in local-first mode; a change means a background pull (or another
	// process) replaced the vault and the caller must reload its snapshot.
	baseline    string
	baselineSet bool
}

func New(opts Options) *Transaction {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Transaction{
		offline: opts.Offline, invalidate: opts.Invalidate, now: now,
		spawn: opts.SpawnBackground, describe: opts.DescribeFailure, observe: opts.Observe,
	}
}

// LocalFirst reports whether inventory reads use the local vault without
// waiting for the sync service. strict restores refresh-before-read.
func (t *Transaction) LocalFirst() bool {
	return config.LoadSettings().EffectiveSyncMode() == config.SyncModeLocalFirst
}

// Offline reports whether this transaction is forbidden from consulting sync
// configuration or transport.
func (t *Transaction) Offline() bool {
	return t.offline
}

// BeginStream validates the online/offline refresh contract before any stream
// input or SSH execution. Zero is reserved for explicit offline streams.
func (t *Transaction) BeginStream(interval time.Duration) (*Stream, error) {
	if t == nil || interval < 0 || (!t.offline && interval == 0) {
		return nil, ErrStreamRefresh
	}
	return &Stream{transaction: t, interval: interval}, nil
}

// Initialize establishes the stream's first inventory state. Explicit offline
// mode deliberately returns without configuration parsing, settings reads, or
// cloud transport so the caller can hold its already-unlocked fixed snapshot.
func (s *Stream) Initialize() (Facts, error) {
	if s == nil || s.transaction == nil {
		return Facts{}, errStreamNotInitialized
	}
	if s.initialized {
		return Facts{}, errStreamNotInitialized
	}
	s.initialized = true
	if s.transaction.offline {
		return Facts{
			Configuration: ConfigurationOffline,
			Offline:       true,
			Freshness:     FreshnessCached,
			Remote:        RemoteNotChecked,
		}, nil
	}
	return s.refresh()
}

// BeforeLine refreshes only when an online stream's positive interval is due.
// A changed refresh invokes the transaction invalidation callback before this
// method returns, allowing callers to load the replacement snapshot safely.
func (s *Stream) BeforeLine() (Facts, error) {
	if s == nil || s.transaction == nil || !s.initialized {
		return Facts{}, errStreamNotInitialized
	}
	if s.transaction.offline || s.transaction.now().Before(s.nextRefresh) {
		return Facts{}, nil
	}
	return s.refresh()
}

func (s *Stream) refresh() (Facts, error) {
	facts, err := s.transaction.Refresh()
	if err != nil {
		return facts, err
	}
	if s.transaction.LocalFirst() {
		if identity, identityErr := localOpaqueIdentity(); identityErr == nil {
			if s.baselineSet && identity != s.baseline && !facts.Changed {
				facts.Changed = true
				if s.transaction.invalidate != nil {
					s.transaction.invalidate()
				}
			}
			s.baseline, s.baselineSet = identity, true
		}
	}
	s.nextRefresh = s.transaction.now().Add(s.interval)
	return facts, nil
}

func (t *Transaction) configuration() (*cloud.CloudConfig, ConfigurationState, error) {
	if t.offline {
		return nil, ConfigurationOffline, nil
	}
	path := filepath.Join(config.Dir(), "cloud.json")
	data, err := os.ReadFile(path) //nolint:gosec // fixed sync configuration path under the private config directory
	if err != nil {
		if os.IsNotExist(err) {
			if _, linkErr := os.Lstat(path); os.IsNotExist(linkErr) {
				return nil, ConfigurationUnconfigured, nil
			}
		}
		return nil, ConfigurationInvalid, fmt.Errorf("%w: configuration cannot be read", ErrConfiguration)
	}
	var cfg cloud.CloudConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, ConfigurationInvalid, fmt.Errorf("%w: configuration cannot be parsed", ErrConfiguration)
	}
	server, parseErr := url.Parse(strings.TrimSpace(cfg.Server))
	if parseErr != nil || (server.Scheme != "http" && server.Scheme != "https") || server.Host == "" || strings.TrimSpace(cfg.Token) == "" {
		return nil, ConfigurationInvalid, fmt.Errorf("%w: required fields are invalid", ErrConfiguration)
	}
	return &cfg, ConfigurationConfigured, nil
}

// InspectLocal reports locally observable synchronization facts without
// contacting the configured service or changing local state.
func (t *Transaction) InspectLocal() (Facts, error) {
	facts := t.localFacts()
	_, state, err := t.configuration()
	facts.Configuration = state
	facts.Offline = t.offline
	facts.Remote = RemoteNotChecked
	switch state {
	case ConfigurationOffline:
		facts = markOffline(facts)
	case ConfigurationUnconfigured:
		facts.Remote = RemoteNotConfigured
	}
	return facts, err
}

// Refresh applies the inventory-read policy. Offline returns before touching
// cloud configuration or transport. Missing configuration retains the
// unconfigured behavior; every present invalid configuration is fatal.
func (t *Transaction) Refresh() (Facts, error) {
	facts, err := t.refresh(false)
	if err == nil && t.observe != nil {
		t.observe(facts)
	}
	return facts, err
}

// Sync performs an explicit refresh even when automatic sync is disabled.
func (t *Transaction) Sync() (Facts, error) {
	facts, err := t.refresh(true)
	t.recordExplicitOutcome(err)
	return facts, err
}

// recordExplicitOutcome updates sync-state.json after an explicit sync, pull,
// or publication step in local-first mode. strict mode does not use the state
// file, so its behavior (including clock reads) is exactly v2.0.2.
func (t *Transaction) recordExplicitOutcome(err error) {
	if t.offline || !t.LocalFirst() {
		return
	}
	t.recordOutcome(err)
}

func (t *Transaction) refresh(explicit bool) (Facts, error) {
	facts := t.localFacts()
	cfg, state, err := t.configuration()
	facts.Configuration = state
	facts.Offline = t.offline
	if err != nil {
		return facts, err
	}
	switch state {
	case ConfigurationOffline:
		return markOffline(facts), nil
	case ConfigurationUnconfigured:
		facts.Remote = RemoteNotConfigured
		if explicit {
			return facts, ErrUnconfigured
		}
		return facts, nil
	}
	settings := config.LoadSettings()
	if !explicit && !settings.AutoSync {
		facts.Remote = RemoteAutoSyncDisabled
		return facts, nil
	}
	if !explicit && settings.EffectiveSyncMode() == config.SyncModeLocalFirst {
		return t.refreshLocalFirst(facts, settings), nil
	}
	return t.refreshConfigured(cfg, facts, false)
}

// refreshLocalFirst answers from local facts only: it never contacts the sync
// service. When an automatic attempt is due it claims that attempt atomically
// in sync-state.json and starts one detached background process. Failure to
// claim or spawn never affects the calling command.
func (t *Transaction) refreshLocalFirst(facts Facts, settings *config.Settings) Facts {
	now := t.now()
	state := LoadSyncState()
	if t.spawn == nil || !state.due(now) {
		return t.decorateLocalFirst(facts, settings, state)
	}
	if token, claimed := t.claimBackground(now); claimed {
		if err := t.spawn(token); err != nil {
			config.Debug("background sync: spawn failed")
			t.releaseClaim()
		}
	}
	return t.decorateLocalFirst(facts, settings, LoadSyncState())
}

// decorateLocalFirst adds the recorded sync outcome and staleness to facts for
// a configured, auto-sync-enabled local-first inventory read.
func (t *Transaction) decorateLocalFirst(facts Facts, settings *config.Settings, state SyncState) Facts {
	facts.Remote = remoteStateFromState(state)
	facts.LastSuccess = state.LastSuccessAt
	facts.NextAttempt = state.NextAttemptAt
	facts.LastError = state.LastError
	facts.LastSync, facts.CacheAge = cacheAge(settings, t.now(), state.LastSuccessAt)
	facts.Unsynced = facts.LastSync == ""
	facts.Stale = facts.LastSync != "" &&
		time.Duration(facts.CacheAge)*time.Second > settings.EffectiveStaleAfter()
	return facts
}

func (t *Transaction) refreshConfigured(cfg *cloud.CloudConfig, facts Facts, forcePull bool) (Facts, error) {
	remote, err := cloud.RemoteETag(cfg)
	if err != nil {
		return facts, fmt.Errorf("%w: remote refresh did not commit: %w", ErrRefresh, err)
	}
	return t.applyRemoteIdentity(cfg, facts, remote, forcePull, pullRefresh)
}

// pullMode selects how a downloaded vault is installed.
type pullMode int

const (
	// pullRefresh is ordinary refresh, sync and pull: divergence fails closed.
	pullRefresh pullMode = iota
	// pullBackground is the detached background sync: additionally it leaves
	// local state alone while a publication awaits reconciliation, waits for
	// no one, and refuses a malformed download.
	pullBackground
	// pullAdopt is reviewed recovery: the caller already verified the exact
	// identity and deliberately replaces divergent local state.
	pullAdopt
)

// vaultLockWait bounds every wait for the vault write lock. Holders keep it
// only for identity comparison and file replacement.
var vaultLockWait = 5 * time.Second

// beforeVaultLock is a test hook invoked just before a vault write lock
// acquisition, with the stage ("decision" or "install"), to inject a
// concurrent local change at exactly that point.
var beforeVaultLock func(stage string)

func (t *Transaction) lockVault(stage string, mode pullMode) (*config.FileLock, error) {
	if beforeVaultLock != nil {
		beforeVaultLock(stage)
	}
	lock, err := config.AcquireFileLock(config.VaultWriteLockName, vaultLockWait)
	if err != nil {
		if mode == pullBackground {
			return nil, errBackgroundSkipped
		}
		if errors.Is(err, config.ErrLockBusy) {
			return nil, fmt.Errorf("%w: vault is busy: another ssm process holds the vault write lock; retry", ErrRefresh)
		}
		return nil, fmt.Errorf("%w: vault write lock unavailable: %w", ErrRefresh, err)
	}
	if mode == pullBackground && (publishingIntentPending() || !t.claimStillValid()) {
		_ = lock.Close()
		return nil, errBackgroundSkipped
	}
	return lock, nil
}

func publishingIntentPending() bool {
	_, err := os.Lstat(config.PublishingIntentPath())
	return err == nil
}

// conflictError records divergence evidence and returns the conflict error.
func (t *Transaction) conflictError(facts Facts, remote string) (Facts, error) {
	conflict := SyncConflict{
		DetectedAt: t.now().UTC().Format(time.RFC3339),
		LocalETag:  facts.LocalETag, RemoteETag: remote, CachedETag: facts.RemoteETag,
	}
	if err := preserveConflict(conflict); err != nil {
		return facts, fmt.Errorf("%w: conflict evidence could not be preserved", ErrRefresh)
	}
	facts.Conflict = &conflict
	return facts, fmt.Errorf("%w: local and remote opaque blobs diverged", ErrConflict)
}

// applyRemoteIdentity decides between no-op, conflict and pull for an already
// observed remote identity. Every path that replaces the local vault shares one
// shape: download outside any lock, then take the vault write lock, re-read
// local identity, fail closed on divergence, and only then write the vault and
// the cached remote identity.
func (t *Transaction) applyRemoteIdentity(cfg *cloud.CloudConfig, facts Facts, remote string, forcePull bool, mode pullMode) (Facts, error) {
	facts.Remote = RemoteChecked
	if !forcePull && remote != "" && remote == facts.RemoteETag {
		return facts, nil
	}
	if divergedFor(mode, facts, remote) {
		// Decide divergence before downloading, under the lock so the
		// evidence reflects the vault as it is now.
		lock, err := t.lockVault("decision", mode)
		if err != nil {
			return facts, err
		}
		current := identityFacts()
		current.Configuration = facts.Configuration
		if divergedFor(mode, current, remote) {
			result, err := t.conflictError(current, remote)
			_ = lock.Close()
			return result, err
		}
		_ = lock.Close()
	}
	data, etag, err := cloud.Fetch(cfg)
	if err != nil {
		return facts, fmt.Errorf("%w: remote refresh did not commit: %w", ErrRefresh, err)
	}
	return t.installFetched(data, etag, mode)
}

// installFetched replaces the local vault with an already downloaded blob under
// the vault write lock. Local facts are re-read after acquiring the lock, so a
// local mutation saved at any earlier moment is seen as divergence and kept.
func (t *Transaction) installFetched(data []byte, etag string, mode pullMode) (Facts, error) {
	lock, err := t.lockVault("install", mode)
	if err != nil {
		return Facts{}, err
	}
	defer func() { _ = lock.Close() }()
	facts := identityFacts()
	facts.Configuration = ConfigurationConfigured
	if mode == pullBackground && !config.ValidVaultBlob(data) {
		return facts, fmt.Errorf("%w: downloaded vault has an invalid format and was not installed", ErrRefresh)
	}
	if mode == pullAdopt {
		// The adoption was reviewed against specific evidence. If the local
		// vault changed after that evidence was recorded, the review no longer
		// covers it: fail closed and keep the newer local state.
		if facts.Conflict == nil || facts.LocalETag != facts.Conflict.LocalETag {
			return facts, fmt.Errorf("%w: local vault changed after the conflict was recorded; nothing was replaced, re-check with sshctl --offline --json doctor before adopting", ErrConflict)
		}
	} else if divergedFor(mode, facts, etag) {
		return t.conflictError(facts, etag)
	}
	if err := config.WritePrivateFile(config.Path(), data); err != nil {
		return facts, fmt.Errorf("%w: remote refresh did not commit: %w", ErrRefresh, err)
	}
	if t.invalidate != nil {
		t.invalidate()
	}
	t.commitSuccess("pull", etag)
	facts = t.localFacts()
	facts.Configuration = ConfigurationConfigured
	facts.Changed = true
	facts.Remote = RemoteChecked
	return facts, nil
}

// identityFacts reads only the local and cached remote identities, without the
// clock or settings, for decisions taken under the vault write lock.
func identityFacts() Facts {
	facts := Facts{RemoteETag: cachedRemoteIdentity(), Conflict: loadConflict()}
	if local, err := localOpaqueIdentity(); err == nil {
		facts.LocalETag = local
	}
	return facts
}

// divergedFor is diverged plus, for the unattended background sync only, the
// case where no remote identity was ever confirmed (sync was configured after
// the local vault existed, or the state was reset) yet a different local vault
// exists: replacing it would silently discard hosts nobody has published. That
// first pull is left to an explicit sync.
func divergedFor(mode pullMode, facts Facts, remote string) bool {
	if diverged(facts, remote) {
		return true
	}
	return mode == pullBackground && facts.RemoteETag == "" && remote != "" &&
		facts.LocalETag != "" && facts.LocalETag != remote
}

// diverged reports that both the remote and the local vault moved away from the
// last confirmed remote identity.
func diverged(facts Facts, remote string) bool {
	return facts.RemoteETag != "" && remote != "" && remote != facts.RemoteETag &&
		facts.LocalETag != "" && facts.LocalETag != facts.RemoteETag && facts.LocalETag != remote
}

func (t *Transaction) Pull() (Facts, error) {
	facts, err := t.pull()
	t.recordExplicitOutcome(err)
	return facts, err
}

func (t *Transaction) pull() (Facts, error) {
	facts := t.localFacts()
	cfg, state, err := t.configuration()
	facts.Configuration = state
	facts.Offline = t.offline
	if err != nil {
		return facts, err
	}
	switch state {
	case ConfigurationOffline:
		return markOffline(facts), ErrUnconfigured
	case ConfigurationUnconfigured:
		facts.Remote = RemoteNotConfigured
		return facts, ErrUnconfigured
	}
	return t.refreshConfigured(cfg, facts, true)
}

// AdoptRemote performs the explicit reviewed recovery path for a preserved
// divergence (typically an empty-ledger one). It replaces the local vault only
// if, under the vault write lock, the local vault is still the one the conflict
// evidence was recorded for; a later local change makes it fail closed. Ordinary Pull never calls this
// method and therefore retains its no-silent-overwrite behavior.
func (t *Transaction) AdoptRemote(expected BlobIdentity) (Facts, error) {
	facts := t.localFacts()
	cfg, state, err := t.configuration()
	facts.Configuration = state
	facts.Offline = t.offline
	if err != nil {
		return facts, err
	}
	if state != ConfigurationConfigured || !expected.Exists || !publicationIdentityPattern.MatchString(expected.Value) {
		return facts, fmt.Errorf("%w: reviewed remote identity is invalid", ErrConflict)
	}
	conflict := loadConflict()
	if conflict == nil || conflict.RemoteETag != expected.Value {
		return facts, fmt.Errorf("%w: reviewed remote identity does not match preserved evidence", ErrConflict)
	}
	observed, err := t.ObservePublicationIdentity()
	if err != nil {
		return facts, fmt.Errorf("%w: reviewed remote identity was not confirmed", ErrConflict)
	}
	if !observed.equal(expected) {
		return facts, fmt.Errorf("%w: reviewed remote identity changed", ErrConflict)
	}
	data, committed, err := cloud.FetchExpected(cfg, expected.Value)
	if err != nil {
		return facts, fmt.Errorf("%w: reviewed remote identity changed during pull", ErrConflict)
	}
	return t.installFetched(data, committed, pullAdopt)
}

func (t *Transaction) RemoteIdentity() (string, error) {
	cfg, state, err := t.configuration()
	if err != nil {
		return "", err
	}
	if state != ConfigurationConfigured {
		return "", ErrUnconfigured
	}
	etag, err := cloud.RemoteETag(cfg)
	if err != nil {
		return "", fmt.Errorf("%w: remote identity was not read: %w", ErrRefresh, err)
	}
	return etag, nil
}

// PreparePublication performs push preflight and returns only safe opaque
// identities. Callers must durably persist their exact scope and this plan
// before SendPublication.
func (t *Transaction) PreparePublication(blob []byte) (_ PreparedPublication, err error) {
	defer func() {
		if err != nil && !errors.Is(err, ErrUnconfigured) {
			t.recordExplicitOutcome(err)
		}
	}()
	facts := t.localFacts()
	cfg, state, err := t.configuration()
	if err != nil {
		return PreparedPublication{}, err
	}
	if state != ConfigurationConfigured {
		return PreparedPublication{}, ErrUnconfigured
	}
	target := opaqueIdentity(blob)
	remote, err := cloud.InspectRemoteBlob(cfg)
	if err != nil {
		return PreparedPublication{}, fmt.Errorf("%w: remote push preflight did not complete: %w", ErrRefresh, err)
	}
	prerequisite := BlobIdentity{Exists: remote.Exists, Value: remote.Value}
	if prerequisite.Exists && !publicationIdentityPattern.MatchString(prerequisite.Value) {
		return PreparedPublication{}, fmt.Errorf("%w: remote identity is unsupported", ErrRefresh)
	}
	if facts.RemoteETag != "" && !publicationIdentityPattern.MatchString(facts.RemoteETag) {
		return PreparedPublication{}, fmt.Errorf("%w: cached remote identity is unsupported", ErrRefresh)
	}
	if facts.RemoteETag != "" {
		if !prerequisite.Exists {
			return PreparedPublication{}, fmt.Errorf("%w: remote push prerequisite disappeared", ErrRefresh)
		}
		if prerequisite.Value != facts.RemoteETag && target != facts.RemoteETag {
			conflict := SyncConflict{
				DetectedAt: t.now().UTC().Format(time.RFC3339),
				LocalETag:  target, RemoteETag: prerequisite.Value, CachedETag: facts.RemoteETag,
			}
			if err := preserveConflict(conflict); err != nil {
				return PreparedPublication{}, fmt.Errorf("%w: conflict evidence could not be preserved", ErrRefresh)
			}
			return PreparedPublication{}, fmt.Errorf("%w: local and remote opaque blobs diverged", ErrConflict)
		}
	}
	return PreparedPublication{Prerequisite: prerequisite, Target: target}, nil
}

// ObservePublicationIdentity returns the exact current remote identity state
// used by publishing-intent reconciliation.
func (t *Transaction) ObservePublicationIdentity() (BlobIdentity, error) {
	cfg, state, err := t.configuration()
	if err != nil {
		return BlobIdentity{}, err
	}
	if state != ConfigurationConfigured {
		return BlobIdentity{}, ErrUnconfigured
	}
	remote, err := cloud.InspectRemoteBlob(cfg)
	if err != nil {
		return BlobIdentity{}, fmt.Errorf("%w: remote publication identity was not read: %w", ErrRefresh, err)
	}
	identity := BlobIdentity{Exists: remote.Exists, Value: remote.Value}
	if identity.Exists && !publicationIdentityPattern.MatchString(identity.Value) {
		return BlobIdentity{}, fmt.Errorf("%w: remote identity is unsupported", ErrRefresh)
	}
	return identity, nil
}

// SendPublication verifies that the prerequisite has not changed, then sends
// the exact opaque target. It does not commit sync metadata; the inventory
// owner does that only after target equality and local finalization.
func (t *Transaction) SendPublication(blob []byte, prepared PreparedPublication) (_ BlobIdentity, err error) {
	defer func() {
		if err != nil {
			t.recordExplicitOutcome(err)
		}
	}()
	if opaqueIdentity(blob) != prepared.Target {
		return BlobIdentity{}, fmt.Errorf("%w: prepared target identity changed", ErrPushNotSent)
	}
	current, err := t.ObservePublicationIdentity()
	if err != nil {
		return BlobIdentity{}, fmt.Errorf("%w: %w", ErrPushNotSent, err)
	}
	target := BlobIdentity{Exists: true, Value: prepared.Target}
	if current.equal(target) {
		return current, nil
	}
	if !current.equal(prepared.Prerequisite) {
		_ = t.preservePublicationConflict(prepared, current)
		return current, fmt.Errorf("%w: remote publication identity diverged", ErrConflict)
	}

	cfg, state, err := t.configuration()
	if err != nil {
		return BlobIdentity{}, fmt.Errorf("%w: %v", ErrPushNotSent, err)
	}
	if state != ConfigurationConfigured {
		return BlobIdentity{}, fmt.Errorf("%w: %v", ErrPushNotSent, ErrUnconfigured)
	}
	identity, observed, err := cloud.PushBlobObserved(cfg, blob)
	if err != nil {
		switch {
		case cloud.PushFailureIsExplicit(err):
			return BlobIdentity{}, fmt.Errorf("%w: %w", ErrPushRejected, err)
		case cloud.PushFailureIsAmbiguous(err):
			return BlobIdentity{}, fmt.Errorf("%w: %w", ErrPushAmbiguous, err)
		default:
			return BlobIdentity{}, fmt.Errorf("%w: %w", ErrPushNotSent, err)
		}
	}
	committed := BlobIdentity{Exists: true, Value: identity}
	if !observed || !publicationIdentityPattern.MatchString(identity) {
		committed, err = t.ObservePublicationIdentity()
		if err != nil {
			return BlobIdentity{}, fmt.Errorf("%w: response identity could not be reconciled", ErrPushAmbiguous)
		}
	}
	if !committed.equal(target) {
		_ = t.preservePublicationConflict(prepared, committed)
		return committed, fmt.Errorf("%w: remote publication identity diverged", ErrConflict)
	}
	return committed, nil
}

func (t *Transaction) preservePublicationConflict(prepared PreparedPublication, remote BlobIdentity) error {
	cached := ""
	if prepared.Prerequisite.Exists {
		cached = prepared.Prerequisite.Value
	}
	observed := ""
	if remote.Exists {
		observed = remote.Value
	}
	return preserveConflict(SyncConflict{
		DetectedAt: t.now().UTC().Format(time.RFC3339),
		LocalETag:  prepared.Target, RemoteETag: observed, CachedETag: cached,
	})
}

// ConfirmPublication records best-effort sync metadata after the inventory
// owner has confirmed target equality and finalized the exact local IDs.
func (t *Transaction) ConfirmPublication(target string) {
	t.commitSuccess("push", target)
	t.recordExplicitOutcome(nil)
}

func (t *Transaction) PushBlob(blob []byte) (Facts, error) {
	facts := t.localFacts()
	cfg, state, err := t.configuration()
	facts.Configuration = state
	facts.Offline = t.offline
	if err != nil {
		return facts, err
	}
	switch state {
	case ConfigurationOffline:
		return markOffline(facts), ErrUnconfigured
	case ConfigurationUnconfigured:
		facts.Remote = RemoteNotConfigured
		return facts, ErrUnconfigured
	}
	candidateIdentity := opaqueIdentity(blob)
	if facts.RemoteETag != "" {
		remote, headErr := cloud.RemoteETag(cfg)
		if headErr != nil {
			return facts, fmt.Errorf("%w: remote push preflight did not complete: %w", ErrRefresh, headErr)
		}
		facts.Remote = RemoteChecked
		if remote != "" && remote != facts.RemoteETag && candidateIdentity != facts.RemoteETag {
			conflict := SyncConflict{
				DetectedAt: t.now().UTC().Format(time.RFC3339),
				LocalETag:  candidateIdentity, RemoteETag: remote, CachedETag: facts.RemoteETag,
			}
			if err := preserveConflict(conflict); err != nil {
				return facts, fmt.Errorf("%w: conflict evidence could not be preserved", ErrRefresh)
			}
			facts.Conflict = &conflict
			return facts, fmt.Errorf("%w: local and remote opaque blobs diverged", ErrConflict)
		}
	}
	committedIdentity, err := cloud.PushBlob(cfg, blob)
	if err != nil {
		return facts, fmt.Errorf("%w: remote push did not commit: %w", ErrRefresh, err)
	}
	t.commitSuccess("push", committedIdentity)
	facts = t.localFacts()
	facts.Configuration, facts.Remote = state, RemoteChecked
	return facts, nil
}

func opaqueIdentity(blob []byte) string {
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}

func (t *Transaction) Facts() Facts {
	facts := t.localFacts()
	_, state, _ := t.configuration()
	facts.Configuration = state
	facts.Offline = t.offline
	switch state {
	case ConfigurationOffline:
		facts = markOffline(facts)
	case ConfigurationUnconfigured:
		facts.Remote = RemoteNotConfigured
	case ConfigurationConfigured:
		settings := config.LoadSettings()
		switch {
		case !settings.AutoSync:
			facts.Remote = RemoteAutoSyncDisabled
			if settings.EffectiveSyncMode() == config.SyncModeLocalFirst {
				facts = t.decorateLocalFirst(facts, settings, LoadSyncState())
				facts.Remote = RemoteAutoSyncDisabled
			}
		case settings.EffectiveSyncMode() == config.SyncModeLocalFirst:
			facts = t.decorateLocalFirst(facts, settings, LoadSyncState())
		default:
			facts.Remote = RemoteChecked
		}
	case ConfigurationInvalid:
		facts.Remote = RemoteNotChecked
	}
	return facts
}

func markOffline(facts Facts) Facts {
	facts.Configuration = ConfigurationOffline
	facts.Offline = true
	facts.Remote = RemoteNotChecked
	if facts.Freshness == FreshnessFresh {
		facts.Freshness = FreshnessCached
	}
	return facts
}

func (t *Transaction) localFacts() Facts {
	settings := config.LoadSettings()
	facts := Facts{
		Freshness: FreshnessUnknown, LastPull: settings.LastPull, LastPush: settings.LastPush,
		RemoteETag: cachedRemoteIdentity(), Conflict: loadConflict(),
	}
	facts.LastSync, facts.CacheAge = cacheAge(settings, t.now())
	if local, err := localOpaqueIdentity(); err == nil {
		facts.LocalETag = local
		if facts.RemoteETag != "" {
			if local == facts.RemoteETag {
				facts.Freshness = FreshnessFresh
			} else {
				facts.Freshness = FreshnessLocalAhead
			}
		}
	}
	return facts
}

// commitSuccess records best-effort metadata only after the remote or local
// opaque-blob commit has been confirmed. Metadata failures must not make that
// confirmed operation ambiguous to callers.
func (t *Transaction) commitSuccess(operation, remoteIdentity string) {
	failed := remoteIdentity == ""
	if remoteIdentity != "" {
		if err := config.WritePrivateFile(remoteIdentityPath(), []byte(remoteIdentity+"\n")); err != nil {
			failed = true
		}
	}
	if err := clearConflict(); err != nil {
		failed = true
	}
	settings := config.LoadSettings()
	timestamp := t.now().Format(time.RFC3339)
	switch operation {
	case "pull":
		settings.LastPull = timestamp
	case "push":
		settings.LastPush = timestamp
	default:
		failed = true
	}
	if err := config.SaveSettings(settings); err != nil {
		failed = true
	}
	if failed {
		config.Debug("%s: sync metadata update failed", operation)
	}
}

func remoteIdentityPath() string { return filepath.Join(config.Dir(), "remote.etag") }

func cachedRemoteIdentity() string {
	data, err := os.ReadFile(remoteIdentityPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func localOpaqueIdentity() (string, error) {
	data, err := os.ReadFile(config.Path())
	if err != nil {
		return "", err
	}
	return opaqueIdentity(data), nil
}

func conflictPath() string { return filepath.Join(config.Dir(), "sync-conflict.json") }

func preserveConflict(conflict SyncConflict) error {
	data, err := json.MarshalIndent(conflict, "", "  ")
	if err != nil {
		return err
	}
	return config.WritePrivateFile(conflictPath(), append(data, '\n'))
}

func loadConflict() *SyncConflict {
	data, err := os.ReadFile(conflictPath())
	if err != nil {
		return nil
	}
	var conflict SyncConflict
	if err := json.Unmarshal(data, &conflict); err != nil {
		return nil
	}
	return &conflict
}

func clearConflict() error {
	err := os.Remove(conflictPath())
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func cacheAge(settings *config.Settings, now time.Time, confirmations ...string) (string, int64) {
	var latest time.Time
	for _, raw := range append([]string{settings.LastPull, settings.LastPush}, confirmations...) {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil && parsed.After(latest) {
			latest = parsed
		}
	}
	if latest.IsZero() {
		return "", 0
	}
	age := now.Sub(latest)
	if age < 0 {
		age = 0
	}
	return latest.Format(time.RFC3339), int64(age / time.Second)
}
