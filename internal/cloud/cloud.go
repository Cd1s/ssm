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

var httpClient = &http.Client{Timeout: 15 * time.Second}

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
	if err := os.MkdirAll(config.Dir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(cloudPath(), data, 0600)
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
	server := strings.TrimRight(cfg.Server, "/")
	data, err := os.ReadFile(config.Path())
	if err != nil {
		config.Debug("push: no local vault: %v", err)
		return fmt.Errorf("no local vault found")
	}

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
	config.Debug("push: success")
	config.RecordSync("push")
	return nil
}

func Pull(cfg *CloudConfig) error {
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

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		config.Debug("pull: read body error: %v", err)
		return err
	}

	_ = os.MkdirAll(config.Dir(), 0700)
	if err := os.WriteFile(config.Path(), data, 0600); err != nil {
		config.Debug("pull: write vault error: %v", err)
		return err
	}
	if etag := strings.Trim(resp.Header.Get("ETag"), `"`); etag != "" {
		_ = saveRemoteETag(etag)
	}
	config.Debug("pull: success")
	config.RecordSync("pull")
	return nil
}

func RemoteETag(cfg *CloudConfig) (string, error) {
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
	return fmt.Errorf("%s", result.Error)
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
	_ = os.MkdirAll(config.Dir(), 0700)
	return os.WriteFile(remoteETagPath(), []byte(etag+"\n"), 0600)
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
