package cloud

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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

// ErrNoVaultOnServer reports that the account has no published vault yet (for
// example a freshly registered one). It is not a transport failure.
var ErrNoVaultOnServer = errors.New("no vault found on server; review pending mutations, then choose sshctl --json push --only <transaction-id> or sshctl --json push --all")

var httpClient = &http.Client{
	Timeout:       15 * time.Second,
	CheckRedirect: checkRedirect,
}

func checkRedirect(request *http.Request, via []*http.Request) error {
	if request.URL.Host != via[0].URL.Host ||
		(via[len(via)-1].URL.Scheme == "https" && request.URL.Scheme == "http") {
		return errors.New("refusing to follow a redirect to a different host or to plain http")
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

// SetRequestTimeout bounds every later sync-service request in this process.
// The detached background sync uses a shorter bound than interactive commands.
func SetRequestTimeout(timeout time.Duration) {
	if timeout > 0 {
		httpClient.Timeout = timeout
	}
}

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
		return "", &TransportError{Err: err}
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
		return "", &TransportError{Err: err}
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
		return "", false, &pushFailure{err: &RequestError{}}
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := httpClient.Do(req)
	if err != nil {
		config.Debug("push: connection failed: %v", err)
		return "", false, &pushFailure{
			err:       &TransportError{Err: err},
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

// Fetch downloads the opaque encrypted vault and its confirmed identity
// without touching local state. There is deliberately no function here that
// writes the vault: every pull is installed by the sync transaction, which
// takes the vault write lock, re-reads local identity, and fails closed on
// divergence.
func Fetch(cfg *CloudConfig) ([]byte, string, error) {
	if err := requireToken(cfg); err != nil {
		return nil, "", err
	}
	server := strings.TrimRight(cfg.Server, "/")
	req, err := http.NewRequest("GET", server+"/sync", nil)
	if err != nil {
		config.Debug("pull: request error: %v", err)
		return nil, "", &RequestError{}
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := httpClient.Do(req)
	if err != nil {
		config.Debug("pull: connection failed: %v", err)
		return nil, "", &TransportError{Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		config.Debug("pull: no vault on server (404)")
		return nil, "", ErrNoVaultOnServer
	}
	if resp.StatusCode != 200 {
		config.Debug("pull: server error %d", resp.StatusCode)
		return nil, "", parseError(resp)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPullBlobBytes+1))
	if err != nil {
		config.Debug("pull: read body error: %v", err)
		return nil, "", &TransportError{Err: err}
	}
	if int64(len(data)) > maxPullBlobBytes {
		config.Debug("pull: sync blob too large")
		return nil, "", fmt.Errorf("sync blob too large")
	}
	if len(data) == 0 {
		config.Debug("pull: empty sync blob")
		return nil, "", fmt.Errorf("sync blob is empty")
	}
	etag := strings.Trim(resp.Header.Get("ETag"), `"`)
	if etag == "" {
		etag = hashBytes(data)
	}
	return data, etag, nil
}

// FetchExpected downloads the vault and verifies that both the response
// identity and the body match expected, without touching local state. It is
// used by explicit reviewed recovery, never by ordinary pull.
func FetchExpected(cfg *CloudConfig, expected string) ([]byte, string, error) {
	if err := requireToken(cfg); err != nil {
		return nil, "", err
	}
	server := strings.TrimRight(cfg.Server, "/")
	req, err := http.NewRequest("GET", server+"/sync", nil)
	if err != nil {
		return nil, "", &RequestError{}
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", &TransportError{Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", parseError(resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPullBlobBytes+1))
	if err != nil {
		return nil, "", &TransportError{Err: err}
	}
	if int64(len(data)) > maxPullBlobBytes || len(data) == 0 {
		return nil, "", fmt.Errorf("sync blob is invalid")
	}
	bodyIdentity := hashBytes(data)
	responseIdentity := strings.Trim(resp.Header.Get("ETag"), `"`)
	if responseIdentity == "" {
		responseIdentity = bodyIdentity
	}
	if responseIdentity != expected || bodyIdentity != expected {
		return nil, "", fmt.Errorf("remote identity changed during reviewed pull")
	}
	return data, expected, nil
}

func RemoteETag(cfg *CloudConfig) (string, error) {
	identity, err := InspectRemoteBlob(cfg)
	if err != nil {
		return "", err
	}
	if !identity.Exists {
		return "", ErrNoVaultOnServer
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
		return RemoteBlobIdentity{}, &RequestError{}
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return RemoteBlobIdentity{}, &TransportError{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

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
		return nil, &RequestError{}
	}
	req.Header.Set("Content-Type", "application/json")
	return httpClient.Do(req)
}

// HTTPStatusError is returned when the sync service answers with a non-success
// HTTP status. Callers classify it with errors.As instead of matching text.
type HTTPStatusError struct {
	StatusCode int
	// Message is the service-provided error text, when the body carried one.
	Message string
}

func (e *HTTPStatusError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("server error (%d)", e.StatusCode)
}

// TransportError wraps a failure to complete an HTTP exchange with the sync
// service. Error() renders only address-free detail (the sync server address
// belongs to cloud.json and must not reach diagnostics), while Unwrap keeps
// the full chain for errors.As classification.
type TransportError struct{ Err error }

func (e *TransportError) Error() string { return transportDetail(e.Err) }
func (e *TransportError) Unwrap() error { return e.Err }

// transportDetail describes a transport error without URLs, hosts, ports or
// resolver addresses. Its TLS branches must cover the same types as
// IsTLSFailure.
func transportDetail(err error) string {
	for err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
			continue
		}
		break
	}
	if err == nil {
		return "request failed"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		detail := strings.TrimSpace(dns.Err)
		if detail == "" {
			detail = "lookup failed"
		}
		return "dns lookup failed: " + detail
	}
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		return "tls: failed to verify certificate: " + transportDetail(verification.Err)
	}
	var authority x509.UnknownAuthorityError
	if errors.As(err, &authority) {
		return "certificate signed by unknown authority"
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return "certificate is not valid for the requested host"
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return "certificate is not valid"
	}
	var record tls.RecordHeaderError
	if errors.As(err, &record) {
		return "server did not speak TLS"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return transportDetail(opErr.Err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "request timed out"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "request timed out"
	}
	return err.Error()
}

// RequestError is returned when an HTTP request cannot be constructed, which
// happens only for an unusable configured server address. Its text is fixed
// because the underlying url.Error would echo that address; it has no
// classifiable cause, so it deliberately does not unwrap.
type RequestError struct{}

func (*RequestError) Error() string { return "could not build the sync request" }

// IsTLSFailure reports whether err is a TLS or certificate verification
// failure. It is the single owner of that classification; machinecontract
// reuses it through synctransaction.
func IsTLSFailure(err error) bool {
	var verification *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var record tls.RecordHeaderError
	return errors.As(err, &verification) ||
		errors.As(err, &authority) ||
		errors.As(err, &hostname) ||
		errors.As(err, &invalid) ||
		errors.As(err, &record)
}

// MissingTokenError is returned when cloud.json has no usable sync token.
type MissingTokenError struct{}

func (*MissingTokenError) Error() string {
	return "cloud token is not configured (run: ssm login)"
}

func parseError(resp *http.Response) error {
	var result struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return &HTTPStatusError{StatusCode: resp.StatusCode}
	}
	return &HTTPStatusError{StatusCode: resp.StatusCode, Message: strings.TrimSpace(result.Error)}
}

func requireToken(cfg *CloudConfig) error {
	if cfg == nil || strings.TrimSpace(cfg.Token) == "" {
		return &MissingTokenError{}
	}
	return nil
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
