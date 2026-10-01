package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"ssm/internal/config"
)

// Issue #115 seam tests for cp --direct: the exact command line A runs, the
// temporary known_hosts content, the scoped agent, and the refusals that must
// happen before host A is contacted.

func newDirectTestKey(t *testing.T) (gossh.PublicKey, string) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey(), string(pem.EncodeToMemory(block))
}

func directFailureError(t *testing.T, err error) string {
	t.Helper()
	var transfer *TransferError
	if !errors.As(err, &transfer) {
		t.Fatalf("error %v is not a transfer error", err)
	}
	return transfer.ContractFailure().Error
}

func TestDirectSSHCommandIsExactAndQuotesEveryOperand(t *testing.T) {
	dst := config.Connection{Name: "b", Host: "b.example", Port: 2222, User: "deploy"}
	got := directSSHCommand("/srv/a b/it's.bin", dst, []string{"[b.example]:2222 ssh-ed25519 AAAA"}, 15, 0, "echo 'hi'")
	want := `umask 077; kh=$(mktemp "${TMPDIR:-/tmp}/ssm-kh.XXXXXXXX") || exit 70; ` +
		`trap 'rm -f -- "$kh"' EXIT HUP INT TERM; ` +
		`printf '%s\n' '[b.example]:2222 ssh-ed25519 AAAA' > "$kh" || exit 70; ` +
		`[ -n "$SSH_AUTH_SOCK" ] || { echo 'no forwarded agent' >&2; exit 71; }; ` +
		`ssh -F /dev/null -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$kh" -o GlobalKnownHostsFile=/dev/null ` +
		`-o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o CheckHostIP=no -o ClearAllForwardings=yes -o ForwardAgent=no ` +
		`-o ProxyCommand=none -o ProxyJump=none -o PermitLocalCommand=no -o ControlMaster=no -o ControlPath=none ` +
		`-o PubkeyAuthentication=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o HostbasedAuthentication=no ` +
		`-o IdentityFile=/dev/null -o "IdentityAgent=$SSH_AUTH_SOCK" -o ConnectTimeout=15 ` +
		`-p 2222 -- 'deploy@b.example' 'echo '"'"'hi'"'"'' < '/srv/a b/it'"'"'s.bin'`
	if got != want {
		t.Fatalf("command =\n%s\nwant\n%s", got, want)
	}
	bounded := directSSHCommand("/x", dst, []string{"l"}, 15, 300, "s")
	if !strings.Contains(bounded, `to=; if command -v timeout >/dev/null 2>&1; then to='timeout 300'; fi; $to ssh -F /dev/null `) {
		t.Fatalf("timeout wrapper missing: %s", bounded)
	}
	if strings.Contains(bounded, "IdentitiesOnly") {
		t.Fatalf("IdentitiesOnly must stay at its default: %s", bounded)
	}
	if defaulted := directSSHCommand("/x", config.Connection{Host: "h", User: "u"}, []string{"l"}, 1, 0, "s"); !strings.Contains(defaulted, " -p 22 -- ") {
		t.Fatalf("default port missing: %s", defaulted)
	}
}

func TestDirectSafeTokenRefusesOptionLookalikes(t *testing.T) {
	for _, value := range []string{"", "-oProxyCommand=x", "a b", "h;id", "$(id)", "h'x"} {
		if directSafeToken(value) {
			t.Fatalf("%q was accepted", value)
		}
	}
	for _, value := range []string{"deploy", "b.example", "10.0.0.1", "fe80::1", "web-1"} {
		if !directSafeToken(value) {
			t.Fatalf("%q was refused", value)
		}
	}
}

func TestDirectKnownHostsLinesCopyOnlyTheExactTrustedEntries(t *testing.T) {
	dst := config.Connection{Name: "b", Host: "127.0.0.1", Port: 2222, User: "u"}
	token := "[127.0.0.1]:2222"
	plain, _ := newDirectTestKey(t)
	hashed, _ := newDirectTestKey(t)
	other, _ := newDirectTestKey(t)
	wildcard, _ := newDirectTestKey(t)
	revoked, _ := newDirectTestKey(t)
	authorized := func(key gossh.PublicKey) string { return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key))) }
	file := strings.Join([]string{
		"# comment",
		"",
		knownhosts.Line([]string{token}, plain),
		knownhosts.HashHostname(token) + " " + authorized(hashed),
		knownhosts.Line([]string{"[127.0.0.1]:2223"}, other),
		knownhosts.Line([]string{"other.example"}, other),
		"* " + authorized(wildcard),
		knownhosts.Line([]string{token}, revoked),
		"@revoked * " + authorized(revoked),
		"@cert-authority " + token + " " + authorized(other),
	}, "\n") + "\n"
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err := directKnownHostsLines(path, dst)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{knownhosts.Line([]string{"127.0.0.1:2222"}, plain), knownhosts.Line([]string{"127.0.0.1:2222"}, hashed)}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines =\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "[127.0.0.1]:2222 ") {
			t.Fatalf("entry %q is not written for the exact host:port", line)
		}
	}

	// Port 22 entries are written without brackets, like ssh looks them up.
	defaultPort := config.Connection{Name: "b", Host: "127.0.0.1", User: "u"}
	path22 := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path22, []byte(knownhosts.Line([]string{"127.0.0.1:22"}, plain)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err = directKnownHostsLines(path22, defaultPort)
	if err != nil || len(lines) != 1 || !strings.HasPrefix(lines[0], "127.0.0.1 ") {
		t.Fatalf("port 22 lines = %q, %v", lines, err)
	}

	// A host with no entry for this endpoint, or no file, is host_key_unknown.
	for _, missing := range []string{path22, filepath.Join(t.TempDir(), "absent")} {
		_, err = directKnownHostsLines(missing, dst)
		if err == nil || directFailureError(t, err) != "host_key_unknown" {
			t.Fatalf("error = %v, want host_key_unknown", err)
		}
	}
}

func TestDirectAgentHoldsOnlyTheDestinationKey(t *testing.T) {
	bPublic, bPEM := newDirectTestKey(t)
	_, otherPEM := newDirectTestKey(t)
	vault := &config.Vault{Keys: []config.SSHKey{{Name: "a-key", PrivateKey: otherPEM}, {Name: "b-key", PrivateKey: bPEM}}}
	dst := config.Connection{Name: "b", Host: "h", User: "u", KeyName: "b-key", Password: "B_PASSWORD_CANARY"}

	keyring, public, err := directAgent(dst, vault)
	if err != nil {
		t.Fatal(err)
	}
	if string(public.Marshal()) != string(bPublic.Marshal()) {
		t.Fatal("agent public key is not B's key")
	}
	keys, err := keyring.List()
	if err != nil || len(keys) != 1 || string(keys[0].Marshal()) != string(bPublic.Marshal()) {
		t.Fatalf("agent holds %d keys (%v), want only B's", len(keys), err)
	}
	signers, err := keyring.Signers()
	if err != nil || len(signers) != 1 {
		t.Fatalf("signers = %d, %v", len(signers), err)
	}
	if _, err := signers[0].Sign(rand.Reader, []byte("data")); err != nil {
		t.Fatalf("agent cannot sign with B's key: %v", err)
	}
	if err := keyring.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if keys, _ := keyring.List(); len(keys) != 0 {
		t.Fatalf("agent still holds %d keys after RemoveAll", len(keys))
	}

	for name, connection := range map[string]config.Connection{
		"password only": {Name: "b", Host: "h", User: "u", Password: "B_PASSWORD_CANARY"},
		"missing key":   {Name: "b", Host: "h", User: "u", KeyName: "absent"},
	} {
		_, _, err := directAgent(connection, vault)
		if err == nil || directFailureError(t, err) != "unsupported_transfer_option" {
			t.Fatalf("%s: error = %v", name, err)
		}
		if strings.Contains(err.Error(), "B_PASSWORD_CANARY") {
			t.Fatalf("%s: error leaks the password: %v", name, err)
		}
	}
	vault.Keys[1].PrivateKey = "not a key"
	if _, _, err := directAgent(dst, vault); err == nil || directFailureError(t, err) != "unsupported_transfer_option" {
		t.Fatalf("garbage key: error = %v", err)
	}
}

// directCountingListener counts the connections made to a host that must not
// be contacted.
func directCountingListener(t *testing.T) (config.Connection, *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepts atomic.Int64
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = conn.Close()
		}
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	return config.Connection{Name: "a", Host: host, Port: port, User: "u", Password: "pw"}, &accepts
}

func TestCopyFileDirectRefusesBeforeAnyConnection(t *testing.T) {
	setTestHome(t, t.TempDir()) // no known_hosts: B's host key is not trusted
	_, bPEM := newDirectTestKey(t)
	vault := &config.Vault{Keys: []config.SSHKey{{Name: "b-key", PrivateKey: bPEM}}}
	keyed := config.Connection{Name: "b", Host: "127.0.0.1", Port: 22, User: "u", KeyName: "b-key", Password: "B_PASSWORD_CANARY"}

	for _, test := range []struct {
		name      string
		mutateSrc func(*config.Connection)
		mutateDst func(*config.Connection)
		code      string
	}{
		{name: "password-only destination", mutateDst: func(c *config.Connection) { c.KeyName = "" }, code: "unsupported_transfer_option"},
		{name: "destination behind proxy_jump", mutateDst: func(c *config.Connection) { c.ProxyJump = "jump" }, code: "unsupported_transfer_option"},
		{name: "sftp destination", mutateDst: func(c *config.Connection) { c.Transfer = config.TransferSFTP }, code: "unsupported_transfer_option"},
		{name: "sftp source", mutateSrc: func(c *config.Connection) { c.Transfer = config.TransferSFTP }, code: "unsupported_transfer_option"},
		{name: "option-like destination host", mutateDst: func(c *config.Connection) { c.Host = "-oProxyCommand=x" }, code: "unsupported_transfer_option"},
		{name: "destination host key not trusted", code: "host_key_unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			src, accepts := directCountingListener(t)
			dst := keyed
			if test.mutateSrc != nil {
				test.mutateSrc(&src)
			}
			if test.mutateDst != nil {
				test.mutateDst(&dst)
			}
			result, err := CopyFile(src, "/srv/a.bin", dst, "/srv/b.bin", vault, CopyOptions{Direct: true})
			if err == nil {
				t.Fatal("cp --direct was not refused")
			}
			got := directFailureError(t, err)
			if got != test.code {
				t.Fatalf("error code = %s, want %s", got, test.code)
			}
			if result.OK {
				t.Fatalf("result = %+v", result)
			}
			if accepts.Load() != 0 {
				t.Fatalf("the refusal connected to host A %d times", accepts.Load())
			}
			if strings.Contains(err.Error(), "B_PASSWORD_CANARY") {
				t.Fatalf("error leaks the password: %v", err)
			}
		})
	}
}
