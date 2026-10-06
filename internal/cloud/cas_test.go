package cloud

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPushBlobObservedSendsPrecondition(t *testing.T) {
	var gotMatch, gotNone string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("method=%s, want PUT", r.Method)
		}
		gotMatch = r.Header.Get("If-Match")
		gotNone = r.Header.Get("If-None-Match")
		w.Header().Set("ETag", `"target"`)
		w.Header().Set("X-Sync-Precondition", "1")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := &CloudConfig{Server: srv.URL, Token: "token"}
	if _, _, err := PushBlobObserved(cfg, []byte("blob"), RemoteBlobIdentity{Exists: true, Value: "remote"}); err != nil {
		t.Fatal(err)
	}
	if gotMatch != `"remote"` || gotNone != "" {
		t.Fatalf("existing prerequisite headers: If-Match=%q If-None-Match=%q", gotMatch, gotNone)
	}
	if _, _, err := PushBlobObserved(cfg, []byte("blob"), RemoteBlobIdentity{}); err != nil {
		t.Fatal(err)
	}
	if gotMatch != "" || gotNone != "*" {
		t.Fatalf("first prerequisite headers: If-Match=%q If-None-Match=%q", gotMatch, gotNone)
	}
}
