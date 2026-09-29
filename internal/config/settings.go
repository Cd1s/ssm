package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ssm/internal/vault"
)

type Settings struct {
	PasswordCache string `json:"password_cache"`
	VimKeys       bool   `json:"vim_keys"`
	AutoUpdate    bool   `json:"auto_update"`
	AutoSync      bool   `json:"auto_sync"`
	UpdateRepo    string `json:"update_repo,omitempty"`
	LastPush      string `json:"last_push,omitempty"`
	LastPull      string `json:"last_pull,omitempty"`
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
	return &Settings{PasswordCache: "always", VimKeys: true, AutoUpdate: true, AutoSync: true}
}

func settingsPath() string {
	return filepath.Join(Dir(), "settings.json")
}

func cachePath() string {
	return filepath.Join(os.TempDir(), "ssm", fmt.Sprintf("cache-%s", userID()))
}

func LoadSettings() *Settings {
	data, err := os.ReadFile(settingsPath())
	if err != nil {
		return DefaultSettings()
	}
	var raw struct {
		PasswordCache *string `json:"password_cache"`
		VimKeys       *bool   `json:"vim_keys"`
		AutoUpdate    *bool   `json:"auto_update"`
		AutoSync      *bool   `json:"auto_sync"`
		UpdateRepo    *string `json:"update_repo"`
		LastPush      *string `json:"last_push"`
		LastPull      *string `json:"last_pull"`
		SyncMode      *string `json:"sync_mode"`
		SyncInterval  *string `json:"sync_interval"`
		StaleAfter    *string `json:"stale_after"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return DefaultSettings()
	}
	s := DefaultSettings()
	if raw.PasswordCache != nil && *raw.PasswordCache != "" {
		s.PasswordCache = *raw.PasswordCache
	}
	if raw.VimKeys != nil {
		s.VimKeys = *raw.VimKeys
	}
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

func cacheKey() string {
	mid := machineID()
	if len(mid) == 0 {
		mid = []byte("fallback")
	}
	uid := userID()
	window := strconv.FormatInt(time.Now().Unix()/1800, 10)
	h := sha256.Sum256([]byte(string(mid) + uid + window))
	return hex.EncodeToString(h[:])
}

func CachePassword(password string) {
	key := cacheKey()
	encrypted, err := vault.Encrypt([]byte(password), key)
	if err != nil {
		return
	}
	_ = WritePrivateFile(cachePath(), encrypted)
}

func GetCachedPassword() string {
	data, err := os.ReadFile(cachePath())
	if err != nil {
		return ""
	}

	info, err := os.Stat(cachePath())
	if err != nil || time.Since(info.ModTime()) > 30*time.Minute {
		ClearPasswordCache()
		return ""
	}

	key := cacheKey()
	decrypted, err := vault.Decrypt(data, key)
	if err != nil {
		ClearPasswordCache()
		return ""
	}

	return string(decrypted)
}

func ClearPasswordCache() {
	os.Remove(cachePath())
}
