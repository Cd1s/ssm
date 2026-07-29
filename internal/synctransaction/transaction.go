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
	ErrConfiguration        = errors.New("sync configuration is invalid")
	ErrUnconfigured         = errors.New("not logged in (run: ssm login)")
	ErrRefresh              = errors.New("sync refresh failed")
	ErrConflict             = errors.New("sync conflict")
	ErrPushNotSent          = errors.New("publication request was not sent")
	ErrPushRejected         = errors.New("publication request was explicitly rejected")
	ErrPushAmbiguous        = errors.New("publication commit is ambiguous")
	ErrStreamRefresh        = errors.New("--refresh=0 requires explicit global --offline")
	errStreamNotInitialized = errors.New("stream synchronization is not initialized")
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
}

type Options struct {
	Offline    bool
	Invalidate func()
	Now        func() time.Time
}

type Transaction struct {
	offline    bool
	invalidate func()
	now        func() time.Time
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
}

func New(opts Options) *Transaction {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Transaction{offline: opts.Offline, invalidate: opts.Invalidate, now: now}
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
	return t.refresh(false)
}

// Sync performs an explicit refresh even when automatic sync is disabled.
func (t *Transaction) Sync() (Facts, error) {
	return t.refresh(true)
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
	if !explicit && !config.LoadSettings().AutoSync {
		facts.Remote = RemoteAutoSyncDisabled
		return facts, nil
	}
	return t.refreshConfigured(cfg, facts, false)
}

func (t *Transaction) refreshConfigured(cfg *cloud.CloudConfig, facts Facts, forcePull bool) (Facts, error) {
	remote, err := cloud.RemoteETag(cfg)
	if err != nil {
		return facts, fmt.Errorf("%w: remote refresh did not commit", ErrRefresh)
	}
	facts.Remote = RemoteChecked
	if !forcePull && remote != "" && remote == facts.RemoteETag {
		facts.Remote = RemoteChecked
		return facts, nil
	}
	if facts.RemoteETag != "" && remote != "" && remote != facts.RemoteETag &&
		facts.LocalETag != "" && facts.LocalETag != facts.RemoteETag {
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
	committedIdentity, err := cloud.Pull(cfg)
	if err != nil {
		return facts, fmt.Errorf("%w: remote refresh did not commit", ErrRefresh)
	}
	facts.Changed = true
	if t.invalidate != nil {
		t.invalidate()
	}
	t.commitSuccess("pull", committedIdentity)
	facts = t.localFacts()
	facts.Configuration = ConfigurationConfigured
	facts.Changed = true
	facts.Remote = RemoteChecked
	return facts, nil
}

func (t *Transaction) Pull() (Facts, error) {
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
		return "", fmt.Errorf("%w: remote identity was not read", ErrRefresh)
	}
	return etag, nil
}

// PreparePublication performs push preflight and returns only safe opaque
// identities. Callers must durably persist their exact scope and this plan
// before SendPublication.
func (t *Transaction) PreparePublication(blob []byte) (PreparedPublication, error) {
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
		return PreparedPublication{}, fmt.Errorf("%w: remote push preflight did not complete", ErrRefresh)
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
		return BlobIdentity{}, fmt.Errorf("%w: remote publication identity was not read", ErrRefresh)
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
func (t *Transaction) SendPublication(blob []byte, prepared PreparedPublication) (BlobIdentity, error) {
	if opaqueIdentity(blob) != prepared.Target {
		return BlobIdentity{}, fmt.Errorf("%w: prepared target identity changed", ErrPushNotSent)
	}
	current, err := t.ObservePublicationIdentity()
	if err != nil {
		return BlobIdentity{}, fmt.Errorf("%w: %v", ErrPushNotSent, err)
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
			return BlobIdentity{}, fmt.Errorf("%w: %v", ErrPushRejected, err)
		case cloud.PushFailureIsAmbiguous(err):
			return BlobIdentity{}, fmt.Errorf("%w: %v", ErrPushAmbiguous, err)
		default:
			return BlobIdentity{}, fmt.Errorf("%w: %v", ErrPushNotSent, err)
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
			return facts, fmt.Errorf("%w: remote push preflight did not complete", ErrRefresh)
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
		return facts, fmt.Errorf("%w: remote push did not commit", ErrRefresh)
	}
	t.commitSuccess("push", committedIdentity)
	facts = t.localFacts()
	facts.Configuration, facts.Remote = state, RemoteChecked
	return facts, nil
}

// AutoPushBlob preserves the legacy automatic-publication switch while
// keeping the decision inside the transaction. Explicit PushBlob ignores that
// switch.
func (t *Transaction) AutoPushBlob(blob []byte) (Facts, error) {
	if !config.LoadSettings().AutoSync {
		facts := t.localFacts()
		_, state, err := t.configuration()
		facts.Configuration = state
		facts.Offline = t.offline
		if err != nil {
			return facts, err
		}
		switch state {
		case ConfigurationOffline:
			facts = markOffline(facts)
		case ConfigurationUnconfigured:
			facts.Remote = RemoteNotConfigured
		case ConfigurationConfigured:
			facts.Remote = RemoteAutoSyncDisabled
		}
		return facts, nil
	}
	return t.PushBlob(blob)
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
		if config.LoadSettings().AutoSync {
			facts.Remote = RemoteChecked
		} else {
			facts.Remote = RemoteAutoSyncDisabled
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

func cacheAge(settings *config.Settings, now time.Time) (string, int64) {
	var latest time.Time
	for _, raw := range []string{settings.LastPull, settings.LastPush} {
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
