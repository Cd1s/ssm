package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssm/internal/config"
)

// Issue #115: sshctl cp --direct. Host A is an in-process fake SSH server that
// accepts agent forwarding and whose exec handler emulates the ssh client run
// on A: it reads the temporary known_hosts the command writes, dials fake host
// B with strict host-key checking against that file, and authenticates only
// through the agent channel the client forwarded.

const cpDirectBPassword = "CP115_B_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary

// directTestWords splits a command line like a POSIX shell for the quoting the
// repository's ShellQuote produces: single quotes are literal, double quotes
// group, a backslash outside quotes escapes the next character.
func directTestWords(command string) []string {
	var words []string
	var current strings.Builder
	inWord := false
	for i := 0; i < len(command); i++ {
		c := command[i]
		switch {
		case c == '\'':
			inWord = true
			end := strings.IndexByte(command[i+1:], '\'')
			if end < 0 {
				return words
			}
			current.WriteString(command[i+1 : i+1+end])
			i += end + 1
		case c == '"':
			inWord = true
			end := strings.IndexByte(command[i+1:], '"')
			if end < 0 {
				return words
			}
			current.WriteString(command[i+1 : i+1+end])
			i += end + 1
		case c == '\\' && i+1 < len(command):
			inWord = true
			i++
			current.WriteByte(command[i])
		case c == ' ' || c == '\t' || c == '\n':
			if inWord {
				words = append(words, current.String())
				current.Reset()
				inWord = false
			}
		default:
			inWord = true
			current.WriteByte(c)
		}
	}
	if inWord {
		words = append(words, current.String())
	}
	return words
}

// directA emulates the ssh client that host A runs for cp --direct.
type directA struct {
	dir    string
	hasSSH bool
	// hang makes the emulated ssh wait until the session is closed, like a
	// transfer that stalls.
	hang bool

	mu          sync.Mutex
	sshCommands []string
	options     map[string]string
	userHost    string
	port        string
	khLines     []string
	khMode      os.FileMode
	khPath      string
	khRemoved   bool
	agentKeys   [][]byte
	bConnects   int
	script      string
}

func (a *directA) hook(request compiledExecRequest) (uint32, bool) {
	switch {
	case strings.HasPrefix(request.Command, "command -v ssh"):
		if !a.hasSSH {
			return 1, true
		}
		_, _ = io.WriteString(request.Channel, directSSHMarker+"\n")
		return 0, true
	case strings.Contains(request.Command, "ssm-kh."):
		return a.runSSH(request), true
	}
	return 0, false
}

const directSSHMarker = "SSM_SSH_OK"

func (a *directA) runSSH(request compiledExecRequest) uint32 {
	words := directTestWords(request.Command)
	var khLines []string
	options := map[string]string{}
	var userHost, port, script, source string
	for i := 0; i < len(words); i++ {
		switch words[i] {
		case "printf":
			if i+1 < len(words) && words[i+1] == `%s\n` {
				for j := i + 2; j < len(words) && words[j] != ">"; j++ {
					khLines = append(khLines, words[j])
				}
			}
		case "ssh":
			for j := i + 1; j < len(words); j++ {
				switch words[j] {
				case "-o":
					j++
					key, value, _ := strings.Cut(words[j], "=")
					options[key] = value
				case "-p":
					j++
					port = words[j]
				case "--":
					userHost, script = words[j+1], words[j+2]
					j += 2
				case "<":
					source = words[j+1]
					j++
				}
			}
			i = len(words)
		}
	}
	khFile, err := os.CreateTemp(a.dir, "ssm-kh.")
	if err != nil {
		_, _ = io.WriteString(request.Stderr, "mktemp failed\n")
		return 70
	}
	khPath := khFile.Name()
	_, _ = khFile.WriteString(strings.Join(khLines, "\n") + "\n")
	_ = khFile.Close()
	info, _ := os.Stat(khPath)
	defer func() {
		_ = os.Remove(khPath)
		a.mu.Lock()
		a.khRemoved = true
		a.mu.Unlock()
	}()
	for key, value := range options {
		options[key] = strings.ReplaceAll(value, "$kh", khPath)
	}
	a.mu.Lock()
	a.sshCommands = append(a.sshCommands, request.Command)
	a.options, a.userHost, a.port, a.khLines, a.khMode, a.khPath, a.script = options, userHost, port, khLines, info.Mode().Perm(), khPath, script
	a.mu.Unlock()

	if a.hang {
		// Stall until the client closes the session: a write to a closed
		// channel fails.
		for {
			if _, err := io.WriteString(request.Stderr, "."); err != nil {
				return 255
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !request.AgentRequested {
		_, _ = io.WriteString(request.Stderr, "Permission denied (publickey).\n")
		return 255
	}
	agentChannel, err := request.OpenAgent()
	if err != nil {
		_, _ = io.WriteString(request.Stderr, "Permission denied (publickey).\n")
		return 255
	}
	client := agent.NewClient(agentChannel)
	if keys, err := client.List(); err == nil {
		a.mu.Lock()
		for _, key := range keys {
			a.agentKeys = append(a.agentKeys, key.Marshal())
		}
		a.mu.Unlock()
	}
	user, host, _ := strings.Cut(userHost, "@")
	if at := strings.LastIndex(userHost, "@"); at >= 0 {
		user, host = userHost[:at], userHost[at+1:]
	}
	callback, err := knownhosts.New(options["UserKnownHostsFile"])
	if err != nil {
		_, _ = io.WriteString(request.Stderr, "Host key verification failed.\n")
		return 255
	}
	address := net.JoinHostPort(host, port)
	raw, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		_, _ = io.WriteString(request.Stderr, "ssh: connect to host failed\n")
		return 255
	}
	conn, channels, requests, err := gossh.NewClientConn(raw, address, &gossh.ClientConfig{
		User: user, Auth: []gossh.AuthMethod{gossh.PublicKeysCallback(client.Signers)}, HostKeyCallback: callback, Timeout: 5 * time.Second,
	})
	if err != nil {
		_ = raw.Close()
		if strings.Contains(err.Error(), "knownhosts") {
			_, _ = io.WriteString(request.Stderr, "Host key verification failed.\n")
		} else {
			_, _ = io.WriteString(request.Stderr, "Permission denied (publickey).\n")
		}
		return 255
	}
	a.mu.Lock()
	a.bConnects++
	a.mu.Unlock()
	bClient := gossh.NewClient(conn, channels, requests)
	defer func() { _ = bClient.Close() }()
	session, err := bClient.NewSession()
	if err != nil {
		return 255
	}
	defer func() { _ = session.Close() }()
	input, err := os.Open(source) //nolint:gosec // test-owned fixture path parsed from the command under test
	if err != nil {
		_, _ = io.WriteString(request.Stderr, "no such file\n")
		return 1
	}
	defer func() { _ = input.Close() }()
	session.Stdin, session.Stdout, session.Stderr = input, request.Channel, request.Stderr
	if err := session.Run(script); err != nil {
		if exit, ok := err.(*gossh.ExitError); ok {
			return uint32(exit.ExitStatus()) //nolint:gosec // exit statuses are small non-negative integers
		}
		return 255
	}
	return 0
}

type directEnvOptions struct {
	noSSHOnA, noAgentForwarding, untrustedB bool
	bPasswordOnly, bJump, bWrongKey         bool
	sftpA, sftpB                            bool
	bDigestOverride                         string
	aHangs                                  bool
}

type directEnv struct {
	cli      *compiledCLIHarness
	a, b     *compiledSSHFixture
	emulator *directA
	aDir     string
	bDir     string
	bPublic  gossh.PublicKey
	bKeyPEM  string
	localTmp string
}

func newDirectEnv(t *testing.T, opts directEnvOptions) directEnv {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake remote hosts address the local file system with POSIX paths")
	}
	cli := newCompiledCLIHarness(t)
	emulator := &directA{dir: t.TempDir(), hasSSH: !opts.noSSHOnA, hang: opts.aHangs}
	bPublic, bPEM := newJumpKey(t)
	authorized := bPublic
	if opts.bWrongKey {
		authorized, _ = newJumpKey(t)
	}
	a := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password: cpPassword, AgentForwarding: !opts.noAgentForwarding, ExecHook: emulator.hook, SFTP: opts.sftpA,
	})
	bOptions := compiledSSHFixtureOptions{DownloadDigestOverride: opts.bDigestOverride, SFTP: opts.sftpB}
	if opts.bPasswordOnly {
		bOptions.Password = cpDirectBPassword
	} else {
		bOptions.AuthorizedKey = authorized
	}
	b := newCompiledSSHFixture(t, bOptions)
	cli.TrustSSHHost(t, a)
	if !opts.untrustedB {
		cli.TrustSSHHost(t, b)
	}
	src := a.Connection("src", cpPassword)
	dst := b.Connection("dst", cpDirectBPassword)
	if !opts.bPasswordOnly {
		dst.KeyName = "dst-key"
	}
	if opts.bJump {
		dst.ProxyJump = "src"
	}
	if opts.sftpA {
		src.Transfer = "sftp"
	}
	if opts.sftpB {
		dst.Transfer = "sftp"
	}
	cli.SaveVault(t, &config.Vault{
		Connections: []config.Connection{src, dst},
		Keys:        []config.SSHKey{{Name: "dst-key", PrivateKey: bPEM}},
	})
	return directEnv{cli: cli, a: a, b: b, emulator: emulator, aDir: t.TempDir(), bDir: t.TempDir(), bPublic: bPublic, bKeyPEM: bPEM, localTmp: t.TempDir()}
}

func (e directEnv) cp(t *testing.T, args ...string) compiledCLIResult {
	t.Helper()
	env := map[string]string{"TMPDIR": e.localTmp, "TMP": e.localTmp, "TEMP": e.localTmp}
	return e.cli.RunWithEnv(t, "sshctl", nil, env, append([]string{"--offline"}, args...)...)
}

func (e directEnv) requireNoCredentialLeak(t *testing.T, result compiledCLIResult) {
	t.Helper()
	if strings.Contains(result.Stdout+result.Stderr, cpDirectBPassword) || strings.Contains(result.Stdout+result.Stderr, e.bKeyPEM) {
		t.Fatalf("credential leaked: %s", compiledOutputIdentity(result))
	}
	for _, command := range e.a.Commands() {
		if strings.Contains(command, cpDirectBPassword) || strings.Contains(command, "PRIVATE KEY") {
			t.Fatalf("a credential reached host A in a command: %q", command)
		}
	}
	if e.a.RejectedAuth() != 0 {
		t.Fatalf("host A received %d credentials it refused, i.e. not its own", e.a.RejectedAuth())
	}
}

func TestCompiledCopyDirectPushesFromAToBThroughAScopedAgent(t *testing.T) {
	env := newDirectEnv(t, directEnvOptions{})
	data, digest := cpPayload(2<<20 + 5)
	source := filepath.Join(env.aDir, "release.bin")
	issue80WriteFile(t, source, data)
	if err := os.Chmod(source, 0o640); err != nil { //nolint:gosec // the test needs a group-readable source to verify mode preservation
		t.Fatal(err)
	}
	destination := filepath.Join(env.bDir, "new", "release.bin")

	result := env.cp(t, "--json", "cp", "src:"+source, "dst:"+destination, "--direct", "--yes")
	got := issue80JSON(t, result)
	if result.ProcessExit != 0 || got["ok"] != true || got["action"] != "cp" || got["route"] != "direct" || got["stage"] != "complete" ||
		got["integrity"] != "sha256_verified" || got["atomic"] != true || got["bytes"] != float64(len(data)) {
		t.Fatalf("cp --direct = %s", result.Stdout)
	}
	if got["source_sha256"] != digest || got["destination_sha256"] != digest {
		t.Fatalf("digests = %v / %v, want %s", got["source_sha256"], got["destination_sha256"], digest)
	}
	if _, present := got["local_sha256"]; present {
		t.Fatalf("a direct copy reported a relay digest: %s", result.Stdout)
	}
	if written, err := os.ReadFile(destination); err != nil || !bytes.Equal(written, data) { //nolint:gosec // test-owned fixture path
		t.Fatalf("destination bytes differ: %v", err)
	}
	if info, err := os.Stat(destination); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("destination mode = %v (%v), want 640", info, err)
	}
	requireNoStaging(t, filepath.Dir(destination))
	env.requireNoCredentialLeak(t, result)

	// The bytes did not pass through this machine: nothing was read from A
	// with cat, and A made exactly one connection to B.
	for _, command := range env.a.Commands() {
		if strings.HasPrefix(command, "cat -- ") {
			t.Fatalf("source was relayed through this machine: %q", command)
		}
	}
	// Local checks of B (key only) plus the one connection A made through the
	// forwarded agent. No password was ever tried on B, and A made exactly one
	// connection to B.
	env.emulator.mu.Lock()
	if env.emulator.bConnects != 1 || env.b.ConnectionCount() != 2 || env.b.PasswordTries() != 0 || env.b.RejectedAuth() != 0 {
		t.Fatalf("A connected to B %d times, B has %d connections, %d password tries, %d rejected", env.emulator.bConnects, env.b.ConnectionCount(), env.b.PasswordTries(), env.b.RejectedAuth())
	}
	if env.a.ConnectionCount() != 1 || env.a.KeyTries() != 0 {
		t.Fatalf("A saw %d connections and %d key attempts, want one password connection", env.a.ConnectionCount(), env.a.KeyTries())
	}
	// The forwarded agent held exactly B's key.
	if len(env.emulator.agentKeys) != 1 || !bytes.Equal(env.emulator.agentKeys[0], env.bPublic.Marshal()) {
		t.Fatalf("forwarded agent held %d keys, want only B's key", len(env.emulator.agentKeys))
	}
	// The ssh command line A ran.
	if len(env.emulator.sshCommands) != 1 {
		t.Fatalf("ssh commands = %v", env.emulator.sshCommands)
	}
	wantOptions := map[string]string{
		"BatchMode": "yes", "StrictHostKeyChecking": "yes", "GlobalKnownHostsFile": "/dev/null", "IdentitiesOnly": "no",
		"ForwardAgent": "no", "VerifyHostKeyDNS": "no", "UserKnownHostsFile": env.emulator.khPath,
	}
	for key, want := range wantOptions {
		if env.emulator.options[key] != want {
			t.Fatalf("ssh option %s = %q, want %q (options %v)", key, env.emulator.options[key], want, env.emulator.options)
		}
	}
	_, bPort, _ := net.SplitHostPort(env.b.Address())
	if env.emulator.userHost != "fixture@127.0.0.1" || env.emulator.port != bPort || env.emulator.options["ConnectTimeout"] == "" {
		t.Fatalf("ssh target = %q port %q options %v", env.emulator.userHost, env.emulator.port, env.emulator.options)
	}
	if !strings.Contains(env.emulator.script, "SSM_TRANSFER") || !strings.Contains(env.emulator.script, digest) {
		t.Fatalf("the script run on B lacks the receipt or the expected digest: %q", env.emulator.script)
	}
	// The temporary known_hosts holds exactly B's trusted key for the exact
	// host:port, is private, and is gone after the command.
	wantLine := knownhosts.Line([]string{net.JoinHostPort("127.0.0.1", bPort)}, env.b.signer.PublicKey())
	if len(env.emulator.khLines) != 1 || env.emulator.khLines[0] != wantLine {
		t.Fatalf("temporary known_hosts = %q, want %q", env.emulator.khLines, wantLine)
	}
	if runtime.GOOS != "windows" && env.emulator.khMode != 0o600 {
		t.Fatalf("temporary known_hosts mode = %v, want 0600", env.emulator.khMode)
	}
	if !env.emulator.khRemoved {
		t.Fatal("temporary known_hosts was not removed")
	}
	env.emulator.mu.Unlock()

	human := env.cp(t, "cp", "src:"+source, "dst:"+destination, "--direct", "--yes")
	if human.ProcessExit != 0 || !strings.Contains(human.Stdout, "ok=1\n") || !strings.Contains(human.Stdout, "route=direct\n") || !strings.Contains(human.Stdout, "sha256="+digest) {
		t.Fatalf("human cp --direct = exit %d stdout=%q stderr=%q", human.ProcessExit, human.Stdout, human.Stderr)
	}
}

func TestCompiledCopyDirectNeedsExplicitConfirmationBeforeAnyConnection(t *testing.T) {
	env := newDirectEnv(t, directEnvOptions{})
	source := filepath.Join(env.aDir, "a.bin")
	issue80WriteFile(t, source, []byte("payload"))
	destination := filepath.Join(env.bDir, "a.bin")

	got := issue80RequireFailure(t, env.cp(t, "--json", "cp", "src:"+source, "dst:"+destination, "--direct"), 2, "confirmation_required", "validate")
	hint, _ := got["hint"].(string)
	message, _ := got["message"].(string)
	if !strings.Contains(hint, "--yes") || !strings.Contains(hint, "forwarded agent") || !strings.Contains(message, "B's key") {
		t.Fatalf("hint %q message %q do not explain the exposure", hint, message)
	}
	human := env.cp(t, "cp", "src:"+source, "dst:"+destination, "--direct")
	if human.ProcessExit != 2 || !strings.Contains(human.Stdout+human.Stderr, "--yes") {
		t.Fatalf("human refusal = exit %d stdout=%q stderr=%q", human.ProcessExit, human.Stdout, human.Stderr)
	}
	issue80RequireFailure(t, env.cp(t, "--json", "cp", "src:"+source, "dst:"+destination, "--yes"), 2, "invalid_arguments", "validate")
	if env.a.ConnectionCount() != 0 || env.b.ConnectionCount() != 0 || env.a.AcceptedConnections() != 0 || env.b.AcceptedConnections() != 0 {
		t.Fatal("a refused cp --direct opened a connection")
	}
	if _, err := os.Stat(destination); err == nil {
		t.Fatal("destination was written")
	}
}

func TestCompiledCopyDirectRefusals(t *testing.T) {
	for _, test := range []struct {
		name      string
		opts      directEnvOptions
		code      string
		stage     string
		exit      int
		touchesA  bool
		sourceDir bool
	}{
		{name: "password-only destination", opts: directEnvOptions{bPasswordOnly: true}, code: "unsupported_transfer_option", stage: "validate", exit: 1},
		{name: "destination that rejects its key", opts: directEnvOptions{bWrongKey: true}, code: "unsupported_transfer_option", stage: "validate", exit: 1},
		{name: "destination behind proxy_jump", opts: directEnvOptions{bJump: true}, code: "unsupported_transfer_option", stage: "validate", exit: 1},
		{name: "sftp source", opts: directEnvOptions{sftpA: true}, code: "unsupported_transfer_option", stage: "validate", exit: 1},
		{name: "sftp destination", opts: directEnvOptions{sftpB: true}, code: "unsupported_transfer_option", stage: "validate", exit: 1},
		{name: "destination host key not trusted", opts: directEnvOptions{untrustedB: true}, code: "host_key_unknown", stage: "dial", exit: 255},
		{name: "directory source", opts: directEnvOptions{}, code: "unsupported_transfer_option", stage: "validate", exit: 1, touchesA: true, sourceDir: true},
		{name: "source without ssh", opts: directEnvOptions{noSSHOnA: true}, code: "remote_tool_unavailable", stage: "capability", exit: 1, touchesA: true},
		{name: "source refuses agent forwarding", opts: directEnvOptions{noAgentForwarding: true}, code: "unsupported_transfer_option", stage: "validate", exit: 1, touchesA: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			env := newDirectEnv(t, test.opts)
			source := filepath.Join(env.aDir, "a.bin")
			if test.sourceDir {
				source = env.aDir
			} else {
				issue80WriteFile(t, source, []byte("payload"))
			}
			destination := filepath.Join(env.bDir, "a.bin")
			result := env.cp(t, "--json", "cp", "src:"+source, "dst:"+destination, "--direct", "--yes")
			issue80RequireFailure(t, result, test.exit, test.code, test.stage)
			env.requireNoCredentialLeak(t, result)
			if !test.touchesA && (env.a.ConnectionCount() != 0 || env.a.AcceptedConnections() != 0) {
				t.Fatalf("the refusal connected to A (%d connections)", env.a.AcceptedConnections())
			}
			if _, err := os.Stat(destination); err == nil {
				t.Fatal("destination was written")
			}
			env.emulator.mu.Lock()
			defer env.emulator.mu.Unlock()
			if env.emulator.bConnects != 0 {
				t.Fatal("A reached B")
			}
		})
	}
}

func TestCompiledCopyDirectReportsADestinationDigestMismatch(t *testing.T) {
	env := newDirectEnv(t, directEnvOptions{bDigestOverride: strings.Repeat("0", 64)})
	data, _ := cpPayload(4096)
	source := filepath.Join(env.aDir, "a.bin")
	issue80WriteFile(t, source, data)
	destination := filepath.Join(env.bDir, "a.bin")
	result := env.cp(t, "--json", "cp", "src:"+source, "dst:"+destination, "--direct", "--yes")
	got := issue80RequireFailure(t, result, 1, "integrity_failed", "integrity")
	if got["route"] != "direct" || got["integrity"] != "mismatch" {
		t.Fatalf("mismatch result = %s", result.Stdout)
	}
}

func TestCompiledCopyDirectTimeoutStopsAStalledTransfer(t *testing.T) {
	env := newDirectEnv(t, directEnvOptions{aHangs: true})
	source := filepath.Join(env.aDir, "a.bin")
	issue80WriteFile(t, source, []byte("payload"))
	destination := filepath.Join(env.bDir, "a.bin")
	start := time.Now()
	result := env.cp(t, "--json", "cp", "src:"+source, "dst:"+destination, "--direct", "--yes", "--timeout", "1s")
	got := issue80RequireFailure(t, result, 1, "transfer_timeout", "timeout")
	if got["route"] != "direct" || time.Since(start) > 20*time.Second {
		t.Fatalf("timeout result = %s after %v", result.Stdout, time.Since(start))
	}
	if _, err := os.Stat(destination); err == nil {
		t.Fatal("destination was written")
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		env.emulator.mu.Lock()
		removed := env.emulator.khRemoved
		env.emulator.mu.Unlock()
		if removed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("temporary known_hosts was not removed after the timeout")
		}
	}
}
