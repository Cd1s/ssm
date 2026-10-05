package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Settings struct {
	AutoUpdate bool   `json:"auto_update"`
	AutoSync   bool   `json:"auto_sync"`
	UpdateRepo string `json:"update_repo,omitempty"`
	LastPush   string `json:"last_push,omitempty"`
	LastPull   string `json:"last_pull,omitempty"`
	// SyncMode, SyncInterval and StaleAfter are stored exactly as configured
	// so saving unrelated settings never rewrites defaults. Read them through
	// EffectiveSyncMode, EffectiveSyncInterval and EffectiveStaleAfter.
	SyncMode     string `json:"sync_mode,omitempty"`
	SyncInterval string `json:"sync_interval,omitempty"`
	StaleAfter   string `json:"stale_after,omitempty"`
}

// Sync modes. local_first is the default: inventory reads never wait for the
// sync service and a detached background process keeps the cache current.
// strict keeps the v2.0.2 behavior of refreshing online before every read.
const (
	SyncModeLocalFirst = "local_first"
	SyncModeStrict     = "strict"

	DefaultSyncInterval = 10 * time.Minute
	DefaultStaleAfter   = 7 * 24 * time.Hour
)

// SyncModeEnv overrides settings.json sync_mode for one process. It accepts
// the same values; an empty or unrecognized value defers to the settings.
const SyncModeEnv = "SSM_SYNC_MODE"

// EffectiveSyncMode returns the configured mode. The environment override wins
// over settings.json, and an empty or unrecognized value is local_first.
func (s *Settings) EffectiveSyncMode() string {
	for _, candidate := range []string{os.Getenv(SyncModeEnv), s.SyncMode} {
		switch strings.TrimSpace(candidate) {
		case SyncModeStrict:
			return SyncModeStrict
		case SyncModeLocalFirst:
			return SyncModeLocalFirst
		}
	}
	return SyncModeLocalFirst
}

// InvalidSyncMode reports a configured sync mode that is not recognized, from
// the environment override or settings.json, so callers can tell the user that
// the default local_first is in effect instead of what they typed.
func (s *Settings) InvalidSyncMode() (source, value string) {
	for _, candidate := range []struct{ source, value string }{
		{SyncModeEnv, os.Getenv(SyncModeEnv)},
		{"settings.json sync_mode", s.SyncMode},
	} {
		switch strings.TrimSpace(candidate.value) {
		case "", SyncModeStrict, SyncModeLocalFirst:
		default:
			return candidate.source, candidate.value
		}
	}
	return "", ""
}

// EffectiveSyncInterval is the minimum spacing between successful background
// sync attempts.
func (s *Settings) EffectiveSyncInterval() time.Duration {
	return parseSettingsDuration(s.SyncInterval, DefaultSyncInterval)
}

// EffectiveStaleAfter is the cache age beyond which inventory is reported as
// stale.
func (s *Settings) EffectiveStaleAfter() time.Duration {
	return parseSettingsDuration(s.StaleAfter, DefaultStaleAfter)
}

// parseSettingsDuration accepts Go durations plus a whole-number "d" (days)
// suffix. Empty, malformed and non-positive values use the fallback.
func parseSettingsDuration(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if strings.HasSuffix(raw, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(raw, "d"))
		if err != nil || days <= 0 || days > 3650 {
			return fallback
		}
		return time.Duration(days) * 24 * time.Hour
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func DefaultSettings() *Settings {
	return &Settings{AutoUpdate: true, AutoSync: true}
}

func settingsPath() string {
	return filepath.Join(Dir(), "settings.json")
}

func LoadSettings() *Settings {
	data, err := os.ReadFile(settingsPath())
	if err != nil {
		return DefaultSettings()
	}
	var raw struct {
		AutoUpdate   *bool   `json:"auto_update"`
		AutoSync     *bool   `json:"auto_sync"`
		UpdateRepo   *string `json:"update_repo"`
		LastPush     *string `json:"last_push"`
		LastPull     *string `json:"last_pull"`
		SyncMode     *string `json:"sync_mode"`
		SyncInterval *string `json:"sync_interval"`
		StaleAfter   *string `json:"stale_after"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return DefaultSettings()
	}
	s := DefaultSettings()
	if raw.AutoUpdate != nil {
		s.AutoUpdate = *raw.AutoUpdate
	}
	if raw.AutoSync != nil {
		s.AutoSync = *raw.AutoSync
	}
	if raw.UpdateRepo != nil {
		s.UpdateRepo = *raw.UpdateRepo
	}
	if raw.LastPush != nil {
		s.LastPush = *raw.LastPush
	}
	if raw.LastPull != nil {
		s.LastPull = *raw.LastPull
	}
	if raw.SyncMode != nil {
		s.SyncMode = *raw.SyncMode
	}
	if raw.SyncInterval != nil {
		s.SyncInterval = *raw.SyncInterval
	}
	if raw.StaleAfter != nil {
		s.StaleAfter = *raw.StaleAfter
	}
	return s
}

func SaveSettings(s *Settings) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return WritePrivateFile(settingsPath(), data)
}
