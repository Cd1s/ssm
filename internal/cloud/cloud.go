package cloud

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ssm/internal/config"
)

type CloudConfig struct {
	Server string `json:"server"`
	Token  string `json:"token"`
	Email  string `json:"email,omitempty"`
}

type SyncConflict struct {
	DetectedAt string `json:"detected_at"`
	LocalETag  string `json:"local_etag"`
	RemoteETag string `json:"remote_etag"`
	CachedETag string `json:"cached_etag"`
}

type SyncConflictError struct{ Conflict SyncConflict }

func (e *SyncConflictError) Error() string {
	return "local and remote encrypted vaults both changed since the last successful sync"
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

var maxPullBlobBytes int64 = 64 << 20

func cloudPath() string {
	return filepath.Join(config.Dir(), "cloud.json")
}

func LoadCloud() (*CloudConfig, error) {
	data, err := os.ReadFile(cloudPath())
	if err != nil {
		return nil, fmt.Errorf("not logged in (run: ssm login)")
	}
	var cfg CloudConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func SaveCloud(cfg *CloudConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return config.WritePrivateFile(cloudPath(), data)
}

func DeleteCloud() error {
	return os.Remove(cloudPath())
}

func Register(server, email, password string) (string, error) {
	server = strings.TrimRight(server, "/")
	body, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})

	resp, err := postJSON(server+"/auth/register", body)
	if err != nil {
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	return parseTokenResponse(resp)
}

func Login(server, email, password string) (string, error) {
	server = strings.TrimRight(server, "/")
	body, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})

	resp, err := postJSON(server+"/auth/login", body)
	if err != nil {
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	return parseTokenResponse(resp)
}

func Push(cfg *CloudConfig) error {
	data, err := os.ReadFile(config.Path())
	if err != nil {
		config.Debug("push: no local vault: %v", err)
		return fmt.Errorf("no local vault found")
	}
	return PushBlob(cfg, data)
}

// PushBlob publishes an already-encrypted vault blob. The sync service never
// receives plaintext inventory or local transaction metadata.
func PushBlob(cfg *CloudConfig, data []byte) error {
	if err := requireToken(cfg); err != nil {
		return err
	}
	server := strings.TrimRight(cfg.Server, "/")

	req, err := http.NewRequest("PUT", server+"/sync", bytes.NewReader(data))
	if err != nil {
		config.Debug("push: request error: %v", err)
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := httpClient.Do(req)
	if err != nil {
		config.Debug("push: connection failed: %v", err)
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		config.Debug("push: server error %d", resp.StatusCode)
		return parseError(resp)
	}
	etag := strings.Trim(resp.Header.Get("ETag"), `"`)
	if etag == "" {
		etag = hashBytes(data)
	}
	_ = saveRemoteETag(etag)
	_ = os.Remove(syncConflictPath())
	config.Debug("push: success")
	config.RecordSync("push")
	return nil
}

func Pull(cfg *CloudConfig) error {
	if err := requireToken(cfg); err != nil {
		return err
	}
	server := strings.TrimRight(cfg.Server, "/")
	req, err := http.NewRequest("GET", server+"/sync", nil)
	if err != nil {
		config.Debug("pull: request error: %v", err)
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := httpClient.Do(req)
	if err != nil {
		config.Debug("pull: connection failed: %v", err)
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		config.Debug("pull: no vault on server (404)")
		return fmt.Errorf("no vault found on server (run: ssm push)")
	}
	if resp.StatusCode != 200 {
		config.Debug("pull: server error %d", resp.StatusCode)
		return parseError(resp)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPullBlobBytes+1))
	if err != nil {
		config.Debug("pull: read body error: %v", err)
		return err
	}
	if int64(len(data)) > maxPullBlobBytes {
		config.Debug("pull: sync blob too large")
		return fmt.Errorf("sync blob too large")
	}
	if len(data) == 0 {
		config.Debug("pull: empty sync blob")
		return fmt.Errorf("sync blob is empty")
	}

	if err := config.WritePrivateFile(config.Path(), data); err != nil {
		config.Debug("pull: write vault error: %v", err)
		return err
	}
	if etag := strings.Trim(resp.Header.Get("ETag"), `"`); etag != "" {
		_ = saveRemoteETag(etag)
	}
	_ = os.Remove(syncConflictPath())
	config.Debug("pull: success")
	config.RecordSync("pull")
	return nil
}

func RemoteETag(cfg *CloudConfig) (string, error) {
	if err := requireToken(cfg); err != nil {
		return "", err
	}
	server := strings.TrimRight(cfg.Server, "/")
	req, err := http.NewRequest("HEAD", server+"/sync", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return "", fmt.Errorf("no vault found on server (run: ssm push)")
	}
	if resp.StatusCode != 200 {
		return "", parseError(resp)
	}
	return strings.Trim(resp.Header.Get("ETag"), `"`), nil
}

func PullIfChanged(cfg *CloudConfig) (bool, error) {
	remote, err := RemoteETag(cfg)
	if err != nil {
		return false, err
	}
	local := loadRemoteETag()
	if remote != "" && remote == local {
		return false, nil
	}
	if local != "" && remote != "" {
		localVault, hashErr := LocalVaultETag()
		if hashErr == nil && localVault != local {
			conflict := SyncConflict{DetectedAt: time.Now().UTC().Format(time.RFC3339), LocalETag: localVault, RemoteETag: remote, CachedETag: local}
			_ = saveSyncConflict(conflict)
			return false, &SyncConflictError{Conflict: conflict}
		}
	}
	if err := Pull(cfg); err != nil {
		return false, err
	}
	if remote != "" {
		_ = saveRemoteETag(remote)
	}
	return true, nil
}

func parseTokenResponse(resp *http.Response) (string, error) {
	if resp.StatusCode >= 400 {
		return "", parseError(resp)
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Token, nil
}

func CheckVerified(cfg *CloudConfig) bool {
	if err := requireToken(cfg); err != nil {
		return false
	}
	server := strings.TrimRight(cfg.Server, "/")
	req, err := http.NewRequest("GET", server+"/auth/status", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false
	}
	var result struct {
		Verified bool `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}
	return result.Verified
}

func postJSON(url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return httpClient.Do(req)
}

func AutoPush() {
	settings := config.LoadSettings()
	if !settings.AutoSync {
		config.Debug("auto-push: skipped (auto_sync disabled)")
		return
	}
	cfg, err := LoadCloud()
	if err != nil {
		config.Debug("auto-push: skipped (%v)", err)
		return
	}
	if err := Push(cfg); err != nil {
		config.Debug("auto-push: %v", err)
	}
}

func AutoPull() {
	settings := config.LoadSettings()
	if !settings.AutoSync {
		config.Debug("auto-pull: skipped (auto_sync disabled)")
		return
	}
	cfg, err := LoadCloud()
	if err != nil {
		config.Debug("auto-pull: skipped (%v)", err)
		return
	}
	if err := Pull(cfg); err != nil {
		config.Debug("auto-pull: %v", err)
	}
}

func parseError(resp *http.Response) error {
	var result struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("server error (%d)", resp.StatusCode)
	}
	msg := strings.TrimSpace(result.Error)
	if msg == "" {
		return fmt.Errorf("server error (%d)", resp.StatusCode)
	}
	return fmt.Errorf("%s", msg)
}

func requireToken(cfg *CloudConfig) error {
	if cfg == nil || strings.TrimSpace(cfg.Token) == "" {
		return fmt.Errorf("cloud token is not configured (run: ssm login)")
	}
	return nil
}

func remoteETagPath() string {
	return filepath.Join(config.Dir(), "remote.etag")
}

func loadRemoteETag() string {
	data, err := os.ReadFile(remoteETagPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func saveRemoteETag(etag string) error {
	if etag == "" {
		return nil
	}
	return config.WritePrivateFile(remoteETagPath(), []byte(etag+"\n"))
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func syncConflictPath() string { return filepath.Join(config.Dir(), "sync-conflict.json") }

func saveSyncConflict(conflict SyncConflict) error {
	data, err := json.MarshalIndent(conflict, "", "  ")
	if err != nil {
		return err
	}
	return config.WritePrivateFile(syncConflictPath(), append(data, '\n'))
}

func LoadSyncConflict() *SyncConflict {
	data, err := os.ReadFile(syncConflictPath())
	if err != nil {
		return nil
	}
	var conflict SyncConflict
	if err := json.Unmarshal(data, &conflict); err != nil {
		return nil
	}
	return &conflict
}

// CachedRemoteETag returns the last successfully observed remote encrypted
// blob identifier. It contains no vault plaintext or credentials.
func CachedRemoteETag() string { return loadRemoteETag() }

// LocalVaultETag hashes the encrypted on-disk blob for freshness comparison.
func LocalVaultETag() (string, error) {
	data, err := os.ReadFile(config.Path())
	if err != nil {
		return "", err
	}
	return hashBytes(data), nil
}
