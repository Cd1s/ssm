package machinecontract

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"syscall"

	"ssm/internal/synctransaction"
)

// Stable values of the additive top-level "cause" field on sync failures.
const (
	SyncCauseDNS            = "dns"
	SyncCauseConnectRefused = "connect_refused"
	SyncCauseTimeout        = "timeout"
	SyncCauseTLS            = "tls"
	SyncCauseAuth           = "auth"
	SyncCauseHTTP5xx        = "http_5xx"
	SyncCauseMissingToken   = "missing_token"
	// SyncCauseNetwork covers any other transport failure (reset, EOF,
	// unreachable network, and similar).
	SyncCauseNetwork = "network"
	// SyncCauseUnknown covers everything without a more specific class,
	// including other HTTP statuses and local failures.
	SyncCauseUnknown = "unknown"
)

// wsaeconnrefused is the Windows Winsock code for a refused connection; it is
// not the same value as syscall.ECONNREFUSED on that platform.
const wsaeconnrefused = 10061

// SyncFailureCause classifies the underlying reason a sync operation failed
// into one stable enumeration value. It inspects typed errors only, never
// error text, and is safe to reuse by any caller that needs the same
// classification (for example status reporting). A DNS failure is reported as
// dns even when the resolver timed out, because the resolver name is the more
// actionable fact than the timeout.
func SyncFailureCause(err error) string {
	if err == nil {
		return ""
	}
	var missing *synctransaction.MissingTokenError
	if errors.As(err, &missing) {
		return SyncCauseMissingToken
	}
	var status *synctransaction.HTTPStatusError
	if errors.As(err, &status) {
		switch {
		case status.StatusCode == http.StatusUnauthorized || status.StatusCode == http.StatusForbidden:
			return SyncCauseAuth
		case status.StatusCode >= 500 && status.StatusCode <= 599:
			return SyncCauseHTTP5xx
		default:
			return SyncCauseUnknown
		}
	}
	if synctransaction.IsTLSFailure(err) {
		return SyncCauseTLS
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return SyncCauseDNS
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && (errno == syscall.ECONNREFUSED || uintptr(errno) == wsaeconnrefused) {
		return SyncCauseConnectRefused
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return SyncCauseTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return SyncCauseTimeout
		}
		return SyncCauseNetwork
	}
	var urlErr *url.Error
	var transport *synctransaction.TransportError
	if errors.As(err, &urlErr) || errors.As(err, &transport) {
		return SyncCauseNetwork
	}
	return SyncCauseUnknown
}

const syncConnectivityHint = "fix sync connectivity or retry explicitly with --offline"

// syncFailureHint returns the actionable hint for a sync refresh failure.
// Credential problems never suggest --offline as the fix.
func syncFailureHint(cause string) string {
	switch cause {
	case SyncCauseAuth:
		return "sync token rejected; re-authenticate with ssm login, then retry"
	case SyncCauseMissingToken:
		return "sync token is not configured; run ssm login, then retry"
	case SyncCauseDNS:
		return "sync server name did not resolve; check the configured server and DNS, or retry explicitly with --offline"
	case SyncCauseConnectRefused:
		return "sync server refused the connection; check the service is running, or retry explicitly with --offline"
	case SyncCauseTimeout:
		return "sync server did not respond in time; retry later or retry explicitly with --offline"
	case SyncCauseTLS:
		return "sync server certificate verification failed; fix the server certificate or trust chain, or retry explicitly with --offline"
	case SyncCauseHTTP5xx:
		return "sync server returned a 5xx error; retry later or retry explicitly with --offline"
	default:
		return syncConnectivityHint
	}
}

// isRemoteSyncFailure reports whether err came from attempting a remote sync
// operation, as opposed to a local failure that merely shares the command.
func isRemoteSyncFailure(err error) bool {
	return errors.Is(err, synctransaction.ErrRefresh) ||
		errors.Is(err, synctransaction.ErrPushNotSent) ||
		errors.Is(err, synctransaction.ErrPushRejected) ||
		errors.Is(err, synctransaction.ErrPushAmbiguous)
}
