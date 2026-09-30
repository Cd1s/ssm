package ssh

import (
	"testing"
	"time"

	"ssm/internal/machinecontract"
)

func TestRetryDelayBacksOffWithJitterAndCap(t *testing.T) {
	base := time.Second
	for attempt := 1; attempt <= 12; attempt++ {
		want := base << (attempt - 1)
		if want > MaxBackoff || attempt > 6 {
			want = MaxBackoff
		}
		for i := 0; i < 50; i++ {
			got := RetryDelay(base, attempt)
			if got < want || got > want+want/4 {
				t.Fatalf("attempt %d delay %s outside [%s, %s]", attempt, got, want, want+want/4)
			}
		}
	}
}

func TestRetryableTransportFailureOnlyCoversNotYetReachable(t *testing.T) {
	retry := []string{"dial_timeout", "dial_refused", "dial_network", "handshake_failed"}
	for _, code := range retry {
		if !RetryableTransportFailure(machinecontract.Failure{Error: code, Message: "x"}) {
			t.Errorf("%s must be retryable", code)
		}
	}
	stop := []string{"auth_failed", "host_key_unknown", "host_key_mismatch", "host_key_type_changed", "no_authentication_configured", "connection_lost", "session_failed", "alias_not_found", "internal"}
	for _, code := range stop {
		if RetryableTransportFailure(machinecontract.Failure{Error: code}) {
			t.Errorf("%s must not be retryable", code)
		}
	}
	for _, code := range []string{"handshake_failed", "dial_timeout", "connection_lost"} {
		if RetryableTransportFailure(machinecontract.Failure{Error: code, PastKeyExchange: true}) {
			t.Errorf("%s past key exchange must not be retryable", code)
		}
	}
	if RetryableTransportFailure(machinecontract.Failure{Error: "handshake_failed", Message: "ssh: handshake failed: ssh: no common algorithm for key exchange"}) {
		t.Error("deterministic no common algorithm must not be retried")
	}
}
