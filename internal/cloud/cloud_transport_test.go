package cloud

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestTransportErrorRendersOnlyAddressFreeDetail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "connection refused",
			err: &url.Error{Op: "Head", URL: "http://sync-unique.example.invalid:48213/sync", Err: &net.OpError{
				Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 48213},
				Err: os.NewSyscallError("connect", syscall.ECONNREFUSED),
			}},
			want: "connect: connection refused",
		},
		{
			name: "dns",
			err: &url.Error{Op: "Head", URL: "http://sync-unique.example.invalid/sync", Err: &net.OpError{
				Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "sync-unique.example.invalid", Server: "192.0.2.53:53"},
			}},
			want: "dns lookup failed: no such host",
		},
		{
			name: "unknown authority",
			err: &url.Error{Op: "Head", URL: "https://sync-unique.example.invalid/sync",
				Err: x509.UnknownAuthorityError{}},
			want: "certificate signed by unknown authority",
		},
		{
			name: "hostname mismatch",
			err:  x509.HostnameError{Host: "sync-unique.example.invalid"},
			want: "certificate is not valid for the requested host",
		},
		{
			name: "client timeout",
			err: &url.Error{Op: "Head", URL: "https://sync-unique.example.invalid/sync",
				Err: context.DeadlineExceeded},
			want: "request timed out",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			wrapped := &TransportError{Err: test.err}
			if got := wrapped.Error(); got != test.want {
				t.Fatalf("Error() = %q, want %q", got, test.want)
			}
			if !errors.Is(wrapped, test.err) {
				t.Fatal("Unwrap lost the original error chain")
			}
		})
	}
}

func TestRemoteETagFailuresNeverExposeServerAddress(t *testing.T) {
	setTestHome(t, t.TempDir())

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedURL := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(tlsServer.Close)
	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(unavailable.Close)

	for name, server := range map[string]string{
		"refused":     refusedURL,
		"tls":         tlsServer.URL,
		"unavailable": unavailable.URL,
		"dns":         "http://sync-unique-host.invalid:48213",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := RemoteETag(&CloudConfig{Server: server, Token: "TRANSPORT_TOKEN_CANARY"})
			if err == nil {
				t.Fatal("RemoteETag succeeded")
			}
			parsed, parseErr := url.Parse(server)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			for _, forbidden := range []string{parsed.Host, parsed.Hostname(), parsed.Port(), "/sync", "TRANSPORT_TOKEN_CANARY"} {
				if forbidden != "" && strings.Contains(err.Error(), forbidden) {
					t.Fatalf("error %q exposes %q", err.Error(), forbidden)
				}
			}
			if _, convErr := strconv.Atoi(parsed.Port()); convErr != nil {
				t.Fatalf("test URL has no numeric port: %v", convErr)
			}
		})
	}
}

func assertNoAddress(t *testing.T, err error, server string) {
	t.Helper()
	if err == nil {
		t.Fatal("cloud call succeeded, want failure")
	}
	parsed, parseErr := url.Parse(server)
	fragments := []string{"sync-unique-host", "48213", "/sync"}
	if parseErr == nil {
		fragments = append(fragments, parsed.Host, parsed.Hostname(), parsed.Port())
	}
	for _, fragment := range fragments {
		if fragment != "" && strings.Contains(err.Error(), fragment) {
			t.Fatalf("error %q exposes %q", err.Error(), fragment)
		}
	}
}

func TestRequestConstructionFailuresNeverExposeServerAddress(t *testing.T) {
	setTestHome(t, t.TempDir())
	// A control character makes http.NewRequest fail, bypassing the CLI's
	// configuration validation, which the cloud package does not repeat.
	server := "http://sync-unique-host.invalid:48213/\x7f"
	cfg := &CloudConfig{Server: server, Token: "REQUEST_TOKEN_CANARY"}

	_, remoteErr := RemoteETag(cfg)
	_, inspectErr := InspectRemoteBlob(cfg)
	_, pullErr := Pull(cfg)
	_, expectedErr := PullExpected(cfg, "identity")
	_, pushErr := PushBlob(cfg, []byte("blob"))
	_, registerErr := Register(server, "user@example.invalid", "PASSWORD_CANARY")
	_, loginErr := Login(server, "user@example.invalid", "PASSWORD_CANARY")
	for name, err := range map[string]error{
		"RemoteETag": remoteErr, "InspectRemoteBlob": inspectErr, "Pull": pullErr,
		"PullExpected": expectedErr, "PushBlob": pushErr, "Register": registerErr, "Login": loginErr,
	} {
		t.Run(name, func(t *testing.T) {
			assertNoAddress(t, err, "http://sync-unique-host.invalid:48213")
			if strings.Contains(err.Error(), "REQUEST_TOKEN_CANARY") {
				t.Fatalf("error %q exposes the token", err.Error())
			}
		})
	}
}

// truncatingServer answers 200 with a Content-Length it never fulfils, then
// drops the connection, optionally with a TCP reset.
func truncatingServer(t *testing.T, reset bool) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = buffer.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nETag: \"partial\"\r\n\r\npartial")
		_ = buffer.Flush()
		if tcp, ok := conn.(*net.TCPConn); ok && reset {
			_ = tcp.SetLinger(0)
		}
		_ = conn.Close()
	}))
	t.Cleanup(server.Close)
	return server
}

func TestTruncatedResponseBodyNeverExposesServerAddress(t *testing.T) {
	for _, reset := range []bool{false, true} {
		server := truncatingServer(t, reset)
		t.Run("reset="+strconv.FormatBool(reset), func(t *testing.T) {
			setTestHome(t, t.TempDir())
			cfg := &CloudConfig{Server: server.URL, Token: "TRUNCATED_TOKEN_CANARY"} //nolint:gosec // test-only fake credential canary
			_, pullErr := Pull(cfg)
			_, expectedErr := PullExpected(cfg, "identity")
			for name, err := range map[string]error{"Pull": pullErr, "PullExpected": expectedErr} {
				t.Run(name, func(t *testing.T) {
					assertNoAddress(t, err, server.URL)
					var transport *TransportError
					if !errors.As(err, &transport) {
						t.Fatalf("error %T is not a TransportError", err)
					}
				})
			}
		})
	}
}
