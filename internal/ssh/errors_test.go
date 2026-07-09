package ssh

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"ssm/internal/config"
)

func TestClassifyDialTimeout(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: timeoutError{}}
	ce := ClassifyError(err, config.Connection{Name: "x", Host: "1.2.3.4", Port: 22})
	if ce.Code != ErrCodeDialTimeout {
		t.Fatalf("code=%s", ce.Code)
	}
	if !strings.Contains(ce.Hint, "quote") {
		t.Fatalf("hint should mention not a quote bug: %s", ce.Hint)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestClassifyHostKey(t *testing.T) {
	ce := ClassifyError(errors.New("ssh: handshake failed: knownhosts: key mismatch"), config.Connection{
		Name: "limee-hk", Host: "200.180.165.7", Port: 22,
	})
	if ce.Code != ErrCodeHostKey {
		t.Fatalf("code=%s", ce.Code)
	}
	if !strings.Contains(ce.Hint, "ssh-keygen -R") {
		t.Fatalf("hint=%s", ce.Hint)
	}
}

func TestClassifyAuth(t *testing.T) {
	ce := ClassifyError(errors.New("ssh: unable to authenticate, attempted methods [none publickey]"), config.Connection{Name: "a"})
	if ce.Code != ErrCodeAuth {
		t.Fatalf("code=%s", ce.Code)
	}
}

func TestParseTimeout(t *testing.T) {
	d, err := parseTimeout("10s")
	if err != nil || d != 10*time.Second {
		t.Fatalf("10s -> %v %v", d, err)
	}
	d, err = parseTimeout("30")
	if err != nil || d != 30*time.Second {
		t.Fatalf("30 -> %v %v", d, err)
	}
}

func TestDialTimeoutEnv(t *testing.T) {
	t.Setenv("SSM_TIMEOUT", "7s")
	if DialTimeout() != 7*time.Second {
		t.Fatalf("got %v", DialTimeout())
	}
	_ = os.Unsetenv("SSM_TIMEOUT")
	t.Setenv("SSM_DIAL_TIMEOUT", "3s")
	if DialTimeout() != 3*time.Second {
		t.Fatalf("got %v", DialTimeout())
	}
}

func TestExitCodeForConnection(t *testing.T) {
	err := ClassifyError(errors.New("dial tcp 1.2.3.4:22: i/o timeout"), config.Connection{Host: "1.2.3.4"})
	if ExitCodeFor(err) != ExitConnectionFailed {
		t.Fatalf("exit=%d", ExitCodeFor(err))
	}
}
