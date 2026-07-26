package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssm/internal/cloud"
	"ssm/internal/config"
)

var compiledUpdateServer *compiledUpdateFixture

type compiledSyncFixture struct {
	server *httptest.Server

	mu           sync.Mutex
	remoteBlob   []byte
	remoteETag   string
	methodStatus map[string]int
	statusAfter  map[string]compiledSyncStatusAfter
	methodCounts map[string]int
	uploadedBlob []byte
}

type compiledSyncStatusAfter struct {
	count  int
	status int
}

func newCompiledSyncFixture(t *testing.T) *compiledSyncFixture {
	t.Helper()
	fixture := &compiledSyncFixture{
		methodStatus: map[string]int{},
		statusAfter:  map[string]compiledSyncStatusAfter{},
		methodCounts: map[string]int{},
	}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *compiledSyncFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/sync" {
		http.NotFound(w, r)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.methodCounts[r.Method]++
	status := f.methodStatus[r.Method]
	if status == 0 {
		status = http.StatusOK
	}
	if after, ok := f.statusAfter[r.Method]; ok && f.methodCounts[r.Method] > after.count {
		status = after.status
	}

	switch r.Method {
	case http.MethodHead:
		if f.remoteETag != "" {
			w.Header().Set("ETag", `"`+f.remoteETag+`"`)
		}
		w.WriteHeader(status)
	case http.MethodGet:
		if f.remoteETag != "" {
			w.Header().Set("ETag", `"`+f.remoteETag+`"`)
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write(f.remoteBlob)
		}
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
		if err != nil {
			http.Error(w, `{"error":"fixture read failed"}`, http.StatusInternalServerError)
			return
		}
		f.uploadedBlob = append([]byte(nil), body...)
		if f.remoteETag != "" {
			w.Header().Set("ETag", `"`+f.remoteETag+`"`)
		}
		w.WriteHeader(status)
	default:
		http.Error(w, `{"error":"fixture method rejected"}`, http.StatusMethodNotAllowed)
	}
}

func (f *compiledSyncFixture) URL() string {
	return f.server.URL
}

func (f *compiledSyncFixture) SetRemote(t *testing.T, blob []byte, etag string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.remoteBlob = append([]byte(nil), blob...)
	f.remoteETag = etag
}

func (f *compiledSyncFixture) SetStatus(t *testing.T, method string, status int) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.methodStatus[method] = status
}

func (f *compiledSyncFixture) SetStatusAfter(t *testing.T, method string, successfulCount, status int) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusAfter[method] = compiledSyncStatusAfter{count: successfulCount, status: status}
}

func (f *compiledSyncFixture) MethodCount(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.methodCounts[method]
}

func (f *compiledSyncFixture) UploadedBlob() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.uploadedBlob...)
}

func (h *compiledCLIHarness) SaveCloud(t *testing.T, server, token string) {
	t.Helper()
	data, err := json.MarshalIndent(&cloud.CloudConfig{Server: server, Token: token}, "", "  ")
	if err != nil {
		t.Fatalf("marshal isolated compiled CLI cloud fixture: %v", err)
	}
	h.writeConfigFile(t, "cloud.json", data)
}

func (h *compiledCLIHarness) SaveRemoteETag(t *testing.T, etag string) {
	t.Helper()
	h.writeConfigFile(t, "remote.etag", []byte(etag+"\n"))
}

func (h *compiledCLIHarness) writeConfigFile(t *testing.T, name string, data []byte) {
	t.Helper()
	path := filepath.Join(h.home, ".config", "ssm", name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write isolated compiled CLI config fixture %s: %v", name, err)
	}
}

type compiledSSHFixtureOptions struct {
	Password       string
	RejectSessions bool
}

type compiledSSHFixture struct {
	listener net.Listener
	signer   gossh.Signer
	options  compiledSSHFixtureOptions

	connections atomic.Int64
	sessions    atomic.Int64
}

func newCompiledSSHFixture(t *testing.T, options compiledSSHFixtureOptions) *compiledSSHFixture {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Fatal("sh is required for the compiled CLI SSH fixture")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate compiled CLI fixture host key: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatalf("create compiled CLI fixture host signer: %v", err)
	}
	serverConfig := &gossh.ServerConfig{
		PasswordCallback: func(_ gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			if string(password) != options.Password {
				return nil, fmt.Errorf("authentication failed")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for compiled CLI SSH fixture: %v", err)
	}
	fixture := &compiledSSHFixture{listener: listener, signer: signer, options: options}
	t.Cleanup(func() { _ = listener.Close() })
	go fixture.serve(serverConfig)
	return fixture
}

func (f *compiledSSHFixture) Connection(alias, password string) config.Connection {
	host, portText, _ := net.SplitHostPort(f.listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	return config.Connection{Name: alias, Host: host, Port: port, User: "fixture", Password: password}
}

func (f *compiledSSHFixture) Address() string {
	return f.listener.Addr().String()
}

func (f *compiledSSHFixture) ConnectionCount() int64 {
	return f.connections.Load()
}

func (f *compiledSSHFixture) SessionCount() int64 {
	return f.sessions.Load()
}

func (f *compiledSSHFixture) serve(serverConfig *gossh.ServerConfig) {
	for {
		raw, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.serveConnection(raw, serverConfig)
	}
}

func (f *compiledSSHFixture) serveConnection(raw net.Conn, serverConfig *gossh.ServerConfig) {
	serverConn, channels, requests, err := gossh.NewServerConn(raw, serverConfig)
	if err != nil {
		_ = raw.Close()
		return
	}
	f.connections.Add(1)
	defer func() { _ = serverConn.Close() }()
	go gossh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(gossh.UnknownChannelType, "session only")
			continue
		}
		if f.options.RejectSessions {
			_ = newChannel.Reject(gossh.ResourceShortage, "fixture session rejected")
			continue
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		f.sessions.Add(1)
		go serveCompiledSSHSession(channel, channelRequests)
	}
}

func serveCompiledSSHSession(channel gossh.Channel, requests <-chan *gossh.Request) {
	defer func() { _ = channel.Close() }()
	for request := range requests {
		if request.Type != "exec" {
			_ = request.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if err := gossh.Unmarshal(request.Payload, &payload); err != nil {
			_ = request.Reply(false, nil)
			return
		}
		_ = request.Reply(true, nil)
		command := exec.Command("sh", "-c", payload.Command) //nolint:gosec // deliberate test-owned SSH execution fixture
		command.Stdin = channel
		command.Stdout = channel
		command.Stderr = channel.Stderr()
		status := 0
		if err := command.Run(); err != nil {
			status = 255
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				status = exitErr.ExitCode()
			}
		}
		_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{uint32(status)}))
		return
	}
}

func (h *compiledCLIHarness) TrustSSHHost(t *testing.T, server *compiledSSHFixture) {
	t.Helper()
	directory := filepath.Join(h.home, ".ssh")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatalf("create compiled CLI known_hosts directory: %v", err)
	}
	path := filepath.Join(directory, "known_hosts")
	line := knownhosts.Line([]string{knownhosts.Normalize(server.Address())}, server.signer.PublicKey()) + "\n"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open compiled CLI known_hosts fixture: %v", err)
	}
	if _, err := file.WriteString(line); err != nil {
		_ = file.Close()
		t.Fatalf("write compiled CLI known_hosts fixture: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close compiled CLI known_hosts fixture: %v", err)
	}
}

func closedCompiledTCPPort(t *testing.T) (string, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve compiled CLI closed TCP port: %v", err)
	}
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatalf("split compiled CLI closed TCP address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("parse compiled CLI closed TCP port: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close compiled CLI reserved TCP port: %v", err)
	}
	return host, port
}

type compiledUpdateFixture struct {
	server *httptest.Server

	mu          sync.Mutex
	version     string
	replacement []byte
	paths       []string
}

func newCompiledUpdateFixture() *compiledUpdateFixture {
	fixture := &compiledUpdateFixture{}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	return fixture
}

func (f *compiledUpdateFixture) Close() {
	f.server.Close()
}

func (f *compiledUpdateFixture) URL() string {
	return f.server.URL
}

func (f *compiledUpdateFixture) ConfigureRelease(version string, replacement []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version = version
	f.replacement = append([]byte(nil), replacement...)
	f.paths = nil
}

func (f *compiledUpdateFixture) RequestPaths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func (f *compiledUpdateFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.URL.Path)

	latestPath := "/repos/fixture/repo/releases/latest"
	releasePrefix := "/fixture/repo/releases/download/" + f.version + "/"
	switch {
	case r.URL.Path == latestPath:
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"tag_name":%q}`, f.version)
	case strings.HasPrefix(r.URL.Path, releasePrefix) && strings.HasSuffix(r.URL.Path, "/checksums.txt"):
		digest := sha256.Sum256(f.replacement)
		_, _ = fmt.Fprintf(w, "%x  %s\n", digest, compiledUpdateAssetName())
	case r.URL.Path == releasePrefix+compiledUpdateAssetName():
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(f.replacement)
	default:
		http.NotFound(w, r)
	}
}

func compiledUpdateAssetName() string {
	name := fmt.Sprintf("ssm-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}
