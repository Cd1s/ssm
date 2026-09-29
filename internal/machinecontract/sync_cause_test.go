package machinecontract

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"

	"ssm/internal/cloud"
	"ssm/internal/synctransaction"
)

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

type plainNetError struct{}

func (plainNetError) Error() string   { return "connection reset by peer" }
func (plainNetError) Timeout() bool   { return false }
func (plainNetError) Temporary() bool { return false }

func TestSyncFailureCauseClassifiesTypedErrors(t *testing.T) {
	t.Parallel()

	_, missingTokenErr := cloud.RemoteETag(&cloud.CloudConfig{Server: "https://sync.example.invalid"})
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", err: nil, want: ""},
		{name: "missing token from cloud", err: missingTokenErr, want: SyncCauseMissingToken},
		{name: "unauthorized", err: &synctransaction.HTTPStatusError{StatusCode: 401}, want: SyncCauseAuth},
		{name: "forbidden", err: &synctransaction.HTTPStatusError{StatusCode: 403, Message: "revoked"}, want: SyncCauseAuth},
		{name: "server error", err: &synctransaction.HTTPStatusError{StatusCode: 500}, want: SyncCauseHTTP5xx},
		{name: "service unavailable", err: &synctransaction.HTTPStatusError{StatusCode: 503}, want: SyncCauseHTTP5xx},
		{name: "other status", err: &synctransaction.HTTPStatusError{StatusCode: 404}, want: SyncCauseUnknown},
		{
			name: "dns", want: SyncCauseDNS,
			err: &url.Error{Op: "Head", URL: "https://sync.invalid/sync", Err: &net.OpError{
				Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "sync.invalid", IsNotFound: true},
			}},
		},
		{
			name: "connection refused", want: SyncCauseConnectRefused,
			err: &url.Error{Op: "Head", URL: "http://127.0.0.1:1/sync", Err: &net.OpError{
				Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED),
			}},
		},
		{
			name: "connection refused winsock", want: SyncCauseConnectRefused,
			err: &net.OpError{Op: "dial", Err: os.NewSyscallError("connectex", syscall.Errno(wsaeconnrefused))},
		},
		{name: "deadline exceeded", err: fmt.Errorf("connection failed: %w", context.DeadlineExceeded), want: SyncCauseTimeout},
		{
			name: "client timeout", want: SyncCauseTimeout,
			err: &url.Error{Op: "Head", URL: "https://sync.invalid/sync", Err: timeoutNetError{}},
		},
		{
			name: "network reset", want: SyncCauseNetwork,
			err: &url.Error{Op: "Head", URL: "https://sync.invalid/sync", Err: plainNetError{}},
		},
		{name: "url error without net cause", err: &url.Error{Op: "Head", URL: "x", Err: errors.New("EOF")}, want: SyncCauseNetwork},
		{
			name: "unknown authority", want: SyncCauseTLS,
			err: &url.Error{Op: "Head", URL: "https://sync.invalid/sync", Err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}},
		},
		{name: "hostname mismatch", err: x509.HostnameError{Host: "sync.invalid"}, want: SyncCauseTLS},
		{name: "expired certificate", err: x509.CertificateInvalidError{Reason: x509.Expired}, want: SyncCauseTLS},
		{name: "plain http on tls port", err: tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, want: SyncCauseTLS},
		{name: "local failure", err: errors.New("disk full"), want: SyncCauseUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := SyncFailureCause(test.err); got != test.want {
				t.Fatalf("SyncFailureCause(%v) = %q, want %q", test.err, got, test.want)
			}
			if test.err != nil {
				wrapped := fmt.Errorf("%w: remote refresh did not commit: %w", synctransaction.ErrRefresh, test.err)
				if got := SyncFailureCause(wrapped); got != test.want {
					t.Fatalf("wrapped SyncFailureCause = %q, want %q", got, test.want)
				}
			}
		})
	}
}

func TestClassifySyncFailureAddsCauseAndHint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cause       error
		wantCause   string
		wantHint    string
		offlineHint bool
	}{
		{name: "auth", cause: &synctransaction.HTTPStatusError{StatusCode: 401}, wantCause: "auth", wantHint: "sync token rejected; re-authenticate with ssm login, then retry"},
		{name: "missing token", cause: &synctransaction.MissingTokenError{}, wantCause: "missing_token", wantHint: "sync token is not configured; run ssm login, then retry"},
		{name: "dns", cause: &net.DNSError{Err: "no such host"}, wantCause: "dns", offlineHint: true},
		{name: "refused", cause: os.NewSyscallError("connect", syscall.ECONNREFUSED), wantCause: "connect_refused", offlineHint: true},
		{name: "timeout", cause: context.DeadlineExceeded, wantCause: "timeout", offlineHint: true},
		{name: "tls", cause: x509.UnknownAuthorityError{}, wantCause: "tls", offlineHint: true},
		{name: "5xx", cause: &synctransaction.HTTPStatusError{StatusCode: 502}, wantCause: "http_5xx", offlineHint: true},
		{name: "network", cause: plainNetError{}, wantCause: "network", wantHint: "fix sync connectivity or retry explicitly with --offline"},
		{name: "unknown", cause: errors.New("boom"), wantCause: "unknown", wantHint: "fix sync connectivity or retry explicitly with --offline"},
	}
	for _, kind := range []Kind{SyncPullFailed, StreamSyncPullFailed, HostSyncPullFailed} {
		for _, test := range tests {
			t.Run(string(kind)+"/"+test.name, func(t *testing.T) {
				t.Parallel()
				err := fmt.Errorf("%w: remote refresh did not commit: %w", synctransaction.ErrRefresh, test.cause)
				failure := ClassifySyncFailure(err, kind)
				if failure.Error != CodeSyncPull || failure.SyncCause != test.wantCause {
					t.Fatalf("failure = %+v, want cause %q", failure, test.wantCause)
				}
				if test.wantHint != "" && failure.Hint != test.wantHint {
					t.Fatalf("hint = %q, want %q", failure.Hint, test.wantHint)
				}
				hasOffline := strings.Contains(failure.Hint, "--offline")
				if hasOffline != test.offlineHint && test.wantHint == "" {
					t.Fatalf("hint %q offline suggestion = %t, want %t", failure.Hint, hasOffline, test.offlineHint)
				}
				if (test.wantCause == "auth" || test.wantCause == "missing_token") && hasOffline {
					t.Fatalf("credential failure hint suggests --offline: %q", failure.Hint)
				}
				if !strings.Contains(failure.Message, test.cause.Error()) {
					t.Fatalf("message %q lost the underlying error %q", failure.Message, test.cause)
				}
				if strings.Contains(failure.Hint, "restart explicitly") {
					t.Fatalf("hint wording is not unified: %q", failure.Hint)
				}
			})
		}
	}
}

func TestClassifySyncFailureCauseIsAdditiveToSyncFailuresOnly(t *testing.T) {
	t.Parallel()

	for _, err := range []error{synctransaction.ErrConfiguration, synctransaction.ErrConflict, synctransaction.ErrEmptyLedgerDivergence} {
		failure := ClassifySyncFailure(err, SyncPullFailed)
		if failure.SyncCause != "" {
			t.Fatalf("%v carries cause %q", err, failure.SyncCause)
		}
		var stdout bytes.Buffer
		if renderErr := Render(JSONDocument, Streams{Stdout: &stdout}, failure); renderErr != nil {
			t.Fatal(renderErr)
		}
		if strings.Contains(stdout.String(), `"cause"`) {
			t.Fatalf("non-refresh sync failure rendered a cause: %s", stdout.String())
		}
	}
	local := ClassifySyncFailure(errors.New("publication sidecar is invalid"), SyncPushFailed)
	if local.Error != CodeSyncPush || local.SyncCause != "" {
		t.Fatalf("local failure without a remote sync attempt carries cause %q", local.SyncCause)
	}
	if failure := Classify(InternalFailure, Details{Message: "x"}); failure.SyncCause != "" {
		t.Fatalf("non-sync failure carries cause %q", failure.SyncCause)
	}
}

func TestSyncFailureCauseRendering(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("%w: remote refresh did not commit: %w", synctransaction.ErrRefresh, &synctransaction.HTTPStatusError{StatusCode: 401})
	failure := ClassifySyncFailure(err, SyncPullFailed)

	var machine bytes.Buffer
	if renderErr := Render(NDJSON, Streams{Stdout: &machine}, failure); renderErr != nil {
		t.Fatal(renderErr)
	}
	wantMachine := `{"ok":false,"error":"sync_pull_failed","message":"sync refresh failed: remote refresh did not commit: server error (401)",` +
		`"hint":"sync token rejected; re-authenticate with ssm login, then retry","stage":"sync_pull","cause":"auth","exit":1}` + "\n"
	if machine.String() != wantMachine {
		t.Fatalf("machine = %s, want %s", machine.String(), wantMachine)
	}

	var human bytes.Buffer
	if renderErr := Render(Human, Streams{Stderr: &human}, failure); renderErr != nil {
		t.Fatal(renderErr)
	}
	wantHuman := "ssm: error=sync_pull_failed stage=sync_pull cause=auth\n" +
		"Error: sync refresh failed: remote refresh did not commit: server error (401)\n" +
		"ssm: hint=sync token rejected; re-authenticate with ssm login, then retry\n"
	if human.String() != wantHuman {
		t.Fatalf("human = %q, want %q", human.String(), wantHuman)
	}
}

func TestSyncFailureCauseNeverLeaksCredentials(t *testing.T) {
	t.Parallel()

	canaries := []string{"SYNC_CAUSE_TOKEN_CANARY", "SYNC_CAUSE_HEADER_CANARY", "SYNC_CAUSE_CONFIG_CANARY"}
	leaky := &url.Error{Op: "Head", URL: "https://sync.invalid/sync", Err: errors.New(
		"Authorization: Bearer " + canaries[0] + " token=" + canaries[1] + ` config={"token":"` + canaries[2] + `"}`,
	)}
	err := fmt.Errorf("%w: remote refresh did not commit: %w", synctransaction.ErrRefresh, leaky)
	failure := ClassifySyncFailure(err, SyncPullFailed)
	for _, format := range []Format{JSONDocument, NDJSON, Human} {
		var stdout, stderr bytes.Buffer
		if renderErr := Render(format, Streams{Stdout: &stdout, Stderr: &stderr}, failure); renderErr != nil {
			t.Fatal(renderErr)
		}
		output := stdout.String() + stderr.String()
		for _, canary := range canaries {
			if strings.Contains(output, canary) {
				t.Fatalf("format %d leaked %q: %s", format, canary, output)
			}
		}
	}
	if !strings.Contains(failure.Message, "sync refresh failed") {
		t.Fatalf("message = %q", failure.Message)
	}
}
