package machinecontract

import (
	"fmt"
	"strings"
	"testing"

	"ssm/internal/synctransaction"
)

func TestDescribeSyncFailureStoresOnlyAFixedPhraseAndTheStatus(t *testing.T) {
	err := fmt.Errorf("%w: %w", synctransaction.ErrRefresh, &synctransaction.HTTPStatusError{
		StatusCode: 503, Message: "upstream at /srv/private/path leaked <secret>",
	})
	cause, message := DescribeSyncFailure(err)
	if cause != SyncCauseHTTP5xx || message != "sync server returned an error (HTTP 503)" {
		t.Fatalf("cause=%q message=%q", cause, message)
	}
	for _, forbidden := range []string{"/srv", "private", "secret", "upstream"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("message persists server-supplied text %q: %q", forbidden, message)
		}
	}
	if cause, message := DescribeSyncFailure(fmt.Errorf("open /home/u/x: denied")); cause != SyncCauseUnknown || message != "sync failed" {
		t.Fatalf("local failure: cause=%q message=%q", cause, message)
	}
}
