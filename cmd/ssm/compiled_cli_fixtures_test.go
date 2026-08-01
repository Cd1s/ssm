package main

import (
	"archive/tar"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssm/internal/cloud"
	"ssm/internal/config"
	"ssm/internal/provenancefixture"
	"ssm/internal/releaseasset"
)

var compiledUpdateServer *compiledUpdateFixture

const compiledTestClockPath = "/test-clock"

type compiledSyncFixture struct {
	server *httptest.Server

	mu           sync.Mutex
	remoteBlob   []byte
	remoteETag   string
	methodStatus map[string]int
	statusAfter  map[string]compiledSyncStatusAfter
	methodCounts map[string]int
	uploadedBlob []byte
	clock        time.Time
	clockReads   []time.Time

	clockRequestCount int
	clockBarrierAt    int
	clockBarrierReady chan struct{}
	clockBarrierDone  chan struct{}
	clockReleaseOnce  sync.Once
}

type compiledSyncStatusAfter struct {
	count  int
	status int
}

func newCompiledSyncFixture(t *testing.T) *compiledSyncFixture {
	t.Helper()
	fixture := &compiledSyncFixture{
		methodStatus:      map[string]int{},
		statusAfter:       map[string]compiledSyncStatusAfter{},
		methodCounts:      map[string]int{},
		clockBarrierReady: make(chan struct{}),
		clockBarrierDone:  make(chan struct{}),
	}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(func() {
		fixture.ReleaseClockBarrier()
		fixture.server.Close()
	})
	return fixture
}

func (f *compiledSyncFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == compiledTestClockPath {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"fixture method rejected"}`, http.StatusMethodNotAllowed)
			return
		}
		f.mu.Lock()
		f.clockRequestCount++
		requestCount := f.clockRequestCount
		barrierAt := f.clockBarrierAt
		f.mu.Unlock()
		if requestCount == barrierAt {
			close(f.clockBarrierReady)
			<-f.clockBarrierDone
		}
		f.mu.Lock()
		now := f.clock
		f.clockReads = append(f.clockReads, now)
		f.mu.Unlock()
		_, _ = io.WriteString(w, strconv.FormatInt(now.UnixNano(), 10))
		return
	}
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
		if status == http.StatusOK && len(f.remoteBlob) == 0 && f.remoteETag == "" {
			http.NotFound(w, r)
			return
		}
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
		if status == http.StatusOK {
			f.remoteBlob = append([]byte(nil), body...)
			f.remoteETag = compiledOpaqueIdentity(body)
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

func (f *compiledSyncFixture) ClockURL() string {
	return f.server.URL + compiledTestClockPath
}

func (f *compiledSyncFixture) SetClock(t *testing.T, now time.Time) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clock = now
}

func (f *compiledSyncFixture) BlockClockRequest(t *testing.T, requestCount int) {
	t.Helper()
	if requestCount <= 0 {
		t.Fatalf("compiled clock barrier request count = %d, want positive", requestCount)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clockBarrierAt = requestCount
}

func (f *compiledSyncFixture) WaitForClockBarrier() error {
	select {
	case <-f.clockBarrierReady:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("compiled child did not reach the clock barrier")
	}
}

func (f *compiledSyncFixture) ReleaseClockBarrier() {
	f.clockReleaseOnce.Do(func() { close(f.clockBarrierDone) })
}

func (f *compiledSyncFixture) ClockReads() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.clockReads...)
}

func (f *compiledSyncFixture) SetRemote(t *testing.T, blob []byte, etag string) {
	t.Helper()
	f.setRemote(blob, etag)
}

func (f *compiledSyncFixture) setRemote(blob []byte, etag string) {
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
	Password                  string
	RejectSessions            bool
	UploadTarSuccessStdout    string
	UploadTarSuccessStderr    string
	DownloadTarSuccessStderr  string
	DownloadFileSuccessStderr string
	RunCommandContains        string
	RunStdoutFragments        []string
	RunStderrFragments        []string
	RunExitStatus             uint32
	RunDrainStdin             bool
}

type compiledSSHFixture struct {
	listener net.Listener
	signer   gossh.Signer
	options  compiledSSHFixtureOptions

	connections atomic.Int64
	sessions    atomic.Int64

	serveDone chan struct{}
	activeMu  sync.Mutex
	active    map[net.Conn]struct{}
	connWG    sync.WaitGroup
	closeOnce sync.Once
}

func newCompiledSSHFixture(t *testing.T, options compiledSSHFixtureOptions) *compiledSSHFixture {
	t.Helper()
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
	fixture := &compiledSSHFixture{
		listener:  listener,
		signer:    signer,
		options:   options,
		serveDone: make(chan struct{}),
		active:    map[net.Conn]struct{}{},
	}
	t.Cleanup(func() { fixture.Close(t) })
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

func (f *compiledSSHFixture) Close(t *testing.T) {
	t.Helper()
	f.closeOnce.Do(func() {
		_ = f.listener.Close()
		select {
		case <-f.serveDone:
		case <-time.After(5 * time.Second):
			t.Fatal("compiled CLI SSH fixture accept loop did not stop")
		}

		f.activeMu.Lock()
		for connection := range f.active {
			_ = connection.Close()
		}
		f.activeMu.Unlock()

		closed := make(chan struct{})
		go func() {
			f.connWG.Wait()
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatal("compiled CLI SSH fixture connection goroutines did not stop")
		}
	})
}

func (f *compiledSSHFixture) serve(serverConfig *gossh.ServerConfig) {
	defer close(f.serveDone)
	for {
		raw, err := f.listener.Accept()
		if err != nil {
			return
		}
		f.activeMu.Lock()
		f.active[raw] = struct{}{}
		f.activeMu.Unlock()
		f.connWG.Add(1)
		go func() {
			defer f.connWG.Done()
			defer func() {
				f.activeMu.Lock()
				delete(f.active, raw)
				f.activeMu.Unlock()
			}()
			f.serveConnection(raw, serverConfig)
		}()
	}
}

func (f *compiledSSHFixture) serveConnection(raw net.Conn, serverConfig *gossh.ServerConfig) {
	serverConn, channels, requests, err := gossh.NewServerConn(raw, serverConfig)
	if err != nil {
		_ = raw.Close()
		return
	}
	f.connections.Add(1)
	requestsDone := make(chan struct{})
	go func() {
		gossh.DiscardRequests(requests)
		close(requestsDone)
	}()
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
		serveCompiledSSHSession(channel, channelRequests, f.options)
	}
	_ = serverConn.Close()
	<-requestsDone
}

func serveCompiledSSHSession(channel gossh.Channel, requests <-chan *gossh.Request, options compiledSSHFixtureOptions) {
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
		status, configured := executeConfiguredCompiledSSHRun(channel, channel.Stderr(), payload.Command, options)
		if !configured {
			status = executeCompiledSSHCommand(channel, channel.Stderr(), payload.Command)
		}
		if status == 0 {
			_, _ = io.WriteString(channel, compiledSSHSuccessStdout(options, payload.Command))
			_, _ = io.WriteString(channel.Stderr(), compiledSSHSuccessDiagnostic(options, payload.Command))
		}
		_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{status}))
		return
	}
}

func executeConfiguredCompiledSSHRun(stdout io.ReadWriter, stderr io.Writer, command string, options compiledSSHFixtureOptions) (uint32, bool) {
	if options.RunCommandContains == "" || !strings.Contains(command, options.RunCommandContains) {
		return 0, false
	}
	if options.RunDrainStdin {
		_, _ = io.Copy(io.Discard, stdout)
	}
	for _, fragment := range options.RunStdoutFragments {
		_, _ = io.WriteString(stdout, fragment)
	}
	for _, fragment := range options.RunStderrFragments {
		_, _ = io.WriteString(stderr, fragment)
	}
	return options.RunExitStatus, true
}

func compiledSSHSuccessStdout(options compiledSSHFixtureOptions, command string) string {
	if strings.Contains(command, "tar -C ") && strings.Contains(command, " -xf -") {
		return options.UploadTarSuccessStdout
	}
	return ""
}

func compiledSSHSuccessDiagnostic(options compiledSSHFixtureOptions, command string) string {
	switch {
	case strings.Contains(command, "tar -C ") && strings.Contains(command, " -xf -"):
		return options.UploadTarSuccessStderr
	case strings.Contains(command, "tar -C ") && strings.Contains(command, " -cf - ."):
		return options.DownloadTarSuccessStderr
	case strings.HasPrefix(strings.TrimSpace(command), "cat -- "):
		return options.DownloadFileSuccessStderr
	default:
		return ""
	}
}

func executeCompiledSSHCommand(stdinStdout io.ReadWriter, stderr io.Writer, command string) uint32 {
	switch {
	case strings.Contains(command, "printf 'SSM_RESUME %s %s\\n'"):
		emptyDigest := sha256.Sum256(nil)
		_, _ = fmt.Fprintf(stdinStdout, "SSM_RESUME 0 %x\n", emptyDigest)
		return 0
	case strings.Contains(command, "cat >>") && strings.Contains(command, "printf 'SSM_TRANSFER %s %s\\n'"):
		paths := compiledShellQuotedWords(command[strings.LastIndex(command, "mv -f -- "):])
		if len(paths) < 2 {
			return compiledSSHFixtureCommandError(stderr)
		}
		return receiveCompiledSSHFile(stdinStdout, stderr, paths[1])
	case strings.Contains(command, "cat > \"$tmp\"") && strings.Contains(command, "printf 'SSM_TRANSFER %s %s\\n'"):
		paths := compiledShellQuotedWords(command[strings.LastIndex(command, "mv -f -- "):])
		if len(paths) < 1 {
			return compiledSSHFixtureCommandError(stderr)
		}
		return receiveCompiledSSHFile(stdinStdout, stderr, paths[0])
	case strings.Contains(command, "tar -C ") && strings.Contains(command, " -xf -"):
		path, ok := compiledShellQuotedWordAfter(command, "tar -C ")
		if !ok {
			return compiledSSHFixtureCommandError(stderr)
		}
		return receiveCompiledSSHTar(stdinStdout, stderr, path)
	case strings.Contains(command, "tar -C ") && strings.Contains(command, " -cf - ."):
		path, ok := compiledShellQuotedWordAfter(command, "tar -C ")
		if !ok {
			return compiledSSHFixtureCommandError(stderr)
		}
		return sendCompiledSSHTar(stdinStdout, stderr, path)
	case strings.HasPrefix(command, "if [ -d "):
		path, ok := compiledShellQuotedWordAfter(command, "if [ -d ")
		if !ok {
			return compiledSSHFixtureCommandError(stderr)
		}
		info, err := os.Stat(path)
		switch {
		case err != nil:
			_, _ = io.WriteString(stdinStdout, "MISSING\n")
		case info.IsDir():
			_, _ = io.WriteString(stdinStdout, "DIR\n")
		default:
			_, _ = io.WriteString(stdinStdout, "FILE\n")
		}
		return 0
	case strings.HasPrefix(command, "cat -- "):
		path, ok := compiledShellQuotedWordAfter(command, "cat -- ")
		if !ok {
			return compiledSSHFixtureCommandError(stderr)
		}
		file, err := os.Open(path) //nolint:gosec // path is parsed from a compiled CLI command using only test-owned remote fixture paths
		if err != nil {
			_, _ = io.WriteString(stderr, "compiled fixture remote file unavailable\n")
			return 1
		}
		defer func() { _ = file.Close() }()
		if _, err := io.Copy(stdinStdout, file); err != nil {
			return 1
		}
		return 0
	}

	argv := compiledShellQuotedWords(command)
	if len(argv) == 1 && argv[0] == "true" {
		return 0
	}
	if len(argv) == 3 && argv[0] == "sh" && argv[1] == "-c" && argv[2] == "exit 255" {
		return 255
	}
	return compiledSSHFixtureCommandError(stderr)
}

func receiveCompiledSSHFile(source io.ReadWriter, stderr io.Writer, path string) uint32 {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		_, _ = io.Copy(io.Discard, source)
		_, _ = io.WriteString(stderr, "permission denied: compiled fixture remote parent unavailable\n")
		return 1
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".compiled-ssh-upload-*")
	if err != nil {
		_, _ = io.Copy(io.Discard, source)
		_, _ = io.WriteString(stderr, "compiled fixture remote temporary file unavailable\n")
		return 1
	}
	tempPath := file.Name()
	defer func() { _ = os.Remove(tempPath) }()
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(file, hash), source)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		_, _ = io.WriteString(stderr, "compiled fixture remote write failed\n")
		return 1
	}
	if err := os.Chmod(tempPath, 0o600); err != nil {
		return 1
	}
	if err := os.Rename(tempPath, path); err != nil {
		_, _ = io.WriteString(stderr, "compiled fixture remote publish failed\n")
		return 1
	}
	_, _ = fmt.Fprintf(source, "SSM_TRANSFER %d %x\n", size, hash.Sum(nil))
	return 0
}

func receiveCompiledSSHTar(source io.Reader, stderr io.Writer, root string) uint32 {
	if err := os.MkdirAll(root, 0o700); err != nil {
		_, _ = io.WriteString(stderr, "compiled fixture remote directory unavailable\n")
		return 1
	}
	reader := tar.NewReader(source)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			// Native tar writers may pad the archive beyond the two zero
			// blocks that archive/tar treats as EOF. Drain through SSH EOF so
			// the producer never sees a premature channel close.
			_, _ = io.Copy(io.Discard, source)
			return 0
		}
		if err != nil {
			_, _ = io.WriteString(stderr, "compiled fixture tar stream invalid\n")
			return 1
		}
		relative := filepath.Clean(filepath.FromSlash(header.Name))
		if relative == "." {
			continue
		}
		if filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			_, _ = io.WriteString(stderr, "compiled fixture tar path rejected\n")
			return 1
		}
		destination := filepath.Join(root, relative)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destination, 0o700); err != nil {
				return 1
			}
		case tar.TypeReg, 0: // POSIX permits a NUL alternate marker for regular files.
			if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
				return 1
			}
			file, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // destination joins a test-owned root with a validated relative tar path
			if err != nil {
				return 1
			}
			_, copyErr := io.CopyN(file, reader, header.Size)
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil {
				return 1
			}
		}
	}
}

func sendCompiledSSHTar(destination io.Writer, stderr io.Writer, root string) uint32 {
	writer := tar.NewWriter(destination)
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := "."
		if relative != "." {
			name = "./" + filepath.ToSlash(relative)
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = name
		header.ModTime = time.Unix(info.ModTime().Unix()-1, 0)
		header.AccessTime = time.Time{}
		header.ChangeTime = time.Time{}
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		file, err := os.Open(path) //nolint:gosec // filepath.Walk yields paths constrained beneath the test-owned remote root
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	closeErr := writer.Close()
	if err != nil || closeErr != nil {
		_, _ = io.WriteString(stderr, "compiled fixture tar creation failed\n")
		return 1
	}
	return 0
}

func compiledShellQuotedWordAfter(command, marker string) (string, bool) {
	index := strings.Index(command, marker)
	if index < 0 {
		return "", false
	}
	words := compiledShellQuotedWords(command[index+len(marker):])
	if len(words) == 0 {
		return "", false
	}
	return words[0], true
}

func compiledShellQuotedWords(command string) []string {
	var words []string
	for offset := 0; offset < len(command); {
		start := strings.IndexByte(command[offset:], '\'')
		if start < 0 {
			break
		}
		start += offset
		end := strings.IndexByte(command[start+1:], '\'')
		if end < 0 {
			break
		}
		end += start + 1
		words = append(words, command[start+1:end])
		offset = end + 1
	}
	return words
}

func compiledSSHFixtureCommandError(stderr io.Writer) uint32 {
	_, _ = io.WriteString(stderr, "unsupported compiled SSH fixture command\n")
	return 127
}

func (h *compiledCLIHarness) TrustSSHHost(t *testing.T, server *compiledSSHFixture) {
	t.Helper()
	directory := filepath.Join(h.home, ".ssh")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatalf("create compiled CLI known_hosts directory: %v", err)
	}
	path := filepath.Join(directory, "known_hosts")
	line := knownhosts.Line([]string{knownhosts.Normalize(server.Address())}, server.signer.PublicKey()) + "\n"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // path is fixed beneath the harness's isolated t.TempDir home
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

type compiledRefusedTCPPort struct {
	host string
	port int
}

func newCompiledRefusedTCPPort(t *testing.T) compiledRefusedTCPPort {
	t.Helper()
	host, port, closeSocket, err := reserveCompiledRefusedTCPPort()
	if err != nil {
		t.Fatalf("reserve deterministic compiled CLI refused TCP port: %v", err)
	}
	t.Cleanup(func() {
		if err := closeSocket(); err != nil {
			t.Errorf("close deterministic compiled CLI refused TCP port: %v", err)
		}
	})
	return compiledRefusedTCPPort{host: host, port: port}
}

type compiledUpdateFixture struct {
	server *httptest.Server

	mu          sync.Mutex
	version     string
	replacement []byte
	provenance  []byte
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
	f.provenance = nil
	f.paths = nil
}

func (f *compiledUpdateFixture) ConfigureAuthenticatedRelease(
	version string,
	replacement []byte,
) ([]byte, error) {
	claims, err := provenancefixture.DefaultClaims(
		compiledUpdateAssetName(),
		version,
		replacement,
	)
	if err != nil {
		return nil, err
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version = version
	f.replacement = append([]byte(nil), replacement...)
	f.provenance = append([]byte(nil), fixture.Bundle...)
	f.paths = nil
	return append([]byte(nil), fixture.TrustedRootDER...), nil
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

	releasesPath := "/repos/fixture/repo/releases"
	releasePrefix := "/fixture/repo/releases/download/" + f.version + "/"
	switch {
	case r.URL.Path == releasesPath:
		w.Header().Set("Content-Type", "application/json")
		assets := make([]string, 0, len(releaseasset.ExpectedReleaseNames()))
		for _, name := range releaseasset.ExpectedReleaseNames() {
			assets = append(assets, fmt.Sprintf(`{"name":%q}`, name))
		}
		_, _ = fmt.Fprintf(
			w,
			`[{"tag_name":%q,"name":"Fixture release","body":"Fixture migration release notes","assets":[%s]}]`,
			f.version,
			strings.Join(assets, ","),
		)
	case strings.HasPrefix(r.URL.Path, releasePrefix) && strings.HasSuffix(r.URL.Path, "/checksums.txt"):
		digest := sha256.Sum256(f.replacement)
		_, _ = fmt.Fprintf(w, "%x  %s\n", digest, compiledUpdateAssetName())
	case r.URL.Path == releasePrefix+releaseasset.ProvenanceName(compiledUpdateAssetName()) && len(f.provenance) != 0:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f.provenance)
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
