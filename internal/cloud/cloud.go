package cloud

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// RemoteBlobIdentity is an opaque service observation. Exists distinguishes an
// absent remote blob from a service-provided empty identity.
type RemoteBlobIdentity struct {
	Exists bool
	Value  string
}

type pushFailure struct {
	err       error
	explicit  bool
	ambiguous bool
}

func (e *pushFailure) Error() string { return e.err.Error() }
func (e *pushFailure) Unwrap() error { return e.err }

// PushFailureIsExplicit reports that the service returned a rejection and
// therefore the attempted PUT did not commit.
func PushFailureIsExplicit(err error) bool {
	var failure *pushFailure
	return errors.As(err, &failure) && failure.explicit
}

// PushFailureIsAmbiguous reports that request transmission may have reached
// the service but no definitive response was received.
func PushFailureIsAmbiguous(err error) bool {
	var failure *pushFailure
	return errors.As(err, &failure) && failure.ambiguous
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

var maxPullBlobBytes int64 = 64 << 20

func cloudPath() string {
	return filepath.Join(config.Dir(), "cloud.json")
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

// PushBlob publishes an already-encrypted vault blob and returns the identity
// confirmed by the PUT. The sync service never receives plaintext inventory
// or local transaction metadata; sync metadata commits belong to
// internal/synctransaction.
func PushBlob(cfg *CloudConfig, data []byte) (string, error) {
	etag, observed, err := PushBlobObserved(cfg, data)
	if err != nil {
		return "", err
	}
	if !observed {
		etag = hashBytes(data)
	}
	return etag, nil
}

// PushBlobObserved publishes opaque bytes and distinguishes a service-provided
// remote identity from the legacy local-hash fallback used by PushBlob.
func PushBlobObserved(cfg *CloudConfig, data []byte) (string, bool, error) {
	if err := requireToken(cfg); err != nil {
		return "", false, err
	}
	server := strings.TrimRight(cfg.Server, "/")

	req, err := http.NewRequest("PUT", server+"/sync", bytes.NewReader(data))
	if err != nil {
		config.Debug("push: request error: %v", err)
		return "", false, &pushFailure{err: err}
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := httpClient.Do(req)
	if err != nil {
		config.Debug("push: connection failed: %v", err)
		return "", false, &pushFailure{
			err:       fmt.Errorf("connection failed: %w", err),
			ambiguous: true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		config.Debug("push: server error %d", resp.StatusCode)
		return "", false, &pushFailure{err: parseError(resp), explicit: true}
	}
	etag := strings.Trim(resp.Header.Get("ETag"), `"`)
	config.Debug("push: success")
	return etag, etag != "", nil
}

// Pull atomically replaces the local encrypted vault with opaque response
// bytes and returns the identity confirmed by that GET. Sync policy and
// metadata commits belong to internal/synctransaction.
func Pull(cfg *CloudConfig) (string, error) {
	if err := requireToken(cfg); err != nil {
		return "", err
	}
	server := strings.TrimRight(cfg.Server, "/")
	req, err := http.NewRequest("GET", server+"/sync", nil)
	if err != nil {
		config.Debug("pull: request error: %v", err)
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := httpClient.Do(req)
	if err != nil {
		config.Debug("pull: connection failed: %v", err)
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		config.Debug("pull: no vault on server (404)")
		return "", fmt.Errorf("no vault found on server; review pending mutations, then choose ssm push --only <transaction-id> or ssm push --all")
	}
	if resp.StatusCode != 200 {
		config.Debug("pull: server error %d", resp.StatusCode)
		return "", parseError(resp)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPullBlobBytes+1))
	if err != nil {
		config.Debug("pull: read body error: %v", err)
		return "", err
	}
	if int64(len(data)) > maxPullBlobBytes {
		config.Debug("pull: sync blob too large")
		return "", fmt.Errorf("sync blob too large")
	}
	if len(data) == 0 {
		config.Debug("pull: empty sync blob")
		return "", fmt.Errorf("sync blob is empty")
	}

	if err := config.WritePrivateFile(config.Path(), data); err != nil {
		config.Debug("pull: write vault error: %v", err)
		return "", err
	}
	etag := strings.Trim(resp.Header.Get("ETag"), `"`)
	if etag == "" {
		etag = hashBytes(data)
	}
	config.Debug("pull: success")
	return etag, nil
}

func RemoteETag(cfg *CloudConfig) (string, error) {
	identity, err := InspectRemoteBlob(cfg)
	if err != nil {
		return "", err
	}
	if !identity.Exists {
		return "", fmt.Errorf("no vault found on server; review pending mutations, then choose ssm push --only <transaction-id> or ssm push --all")
	}
	return identity.Value, nil
}

// InspectRemoteBlob observes the current opaque remote identity without
// treating a missing first-push target as a transport failure.
func InspectRemoteBlob(cfg *CloudConfig) (RemoteBlobIdentity, error) {
	if err := requireToken(cfg); err != nil {
		return RemoteBlobIdentity{}, err
	}
	server := strings.TrimRight(cfg.Server, "/")
	req, err := http.NewRequest("HEAD", server+"/sync", nil)
	if err != nil {
		return RemoteBlobIdentity{}, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return RemoteBlobIdentity{}, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return RemoteBlobIdentity{}, nil
	}
	if resp.StatusCode != 200 {
		return RemoteBlobIdentity{}, parseError(resp)
	}
	return RemoteBlobIdentity{
		Exists: true,
		Value:  strings.Trim(resp.Header.Get("ETag"), `"`),
	}, nil
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

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
