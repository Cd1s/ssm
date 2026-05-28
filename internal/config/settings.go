package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return DefaultSettings()
	}
	if s.PasswordCache == "" {
		s.PasswordCache = "always"
	}
	return &s
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

func RecordSync(syncType string) {
	s := LoadSettings()
	ts := time.Now().Format(time.RFC3339)
	switch syncType {
	case "push":
		s.LastPush = ts
	case "pull":
		s.LastPull = ts
	}
	_ = SaveSettings(s)
}
