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
