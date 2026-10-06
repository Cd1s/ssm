package syncserver

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestPushPreconditions(t *testing.T) {
	srv, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()
	token := authCall(t, httpSrv.URL+"/auth/register", "cas@example.test", "long-password")

	put := func(blob []byte, headers map[string]string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/sync", bytes.NewReader(blob))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	missingMatch := put([]byte("missing"), map[string]string{"If-Match": `"does-not-exist"`})
	if missingMatch.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("missing-vault If-Match status=%d, want 412", missingMatch.StatusCode)
	}
	first := put([]byte("one"), map[string]string{"If-None-Match": "*"})
	if first.StatusCode != http.StatusOK || first.Header.Get("X-Sync-Precondition") != "1" {
		t.Fatalf("first push status=%d capability=%q", first.StatusCode, first.Header.Get("X-Sync-Precondition"))
	}
	current := first.Header.Get("ETag")
	if current == "" {
		t.Fatal("first push missing ETag")
	}
	matching := put([]byte("two"), map[string]string{"If-Match": current})
	if matching.StatusCode != http.StatusOK || matching.Header.Get("X-Sync-Precondition") != "1" {
		t.Fatalf("matching push status=%d capability=%q", matching.StatusCode, matching.Header.Get("X-Sync-Precondition"))
	}
	mismatch := put([]byte("three"), map[string]string{"If-Match": current})
	if mismatch.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("mismatched push status=%d, want 412", mismatch.StatusCode)
	}
	legacy := put([]byte("legacy"), nil)
	if legacy.StatusCode != http.StatusOK {
		t.Fatalf("legacy push status=%d, want 200", legacy.StatusCode)
	}
}

func TestConcurrentConditionalPushOnlyOneSucceeds(t *testing.T) {
	srv, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()
	token := authCall(t, httpSrv.URL+"/auth/register", "race@example.test", "long-password")
	initial := putSyncTest(t, httpSrv.URL, token, []byte("initial"), nil)
	initialETag := initial.Header.Get("ETag")
	_ = initial.Body.Close()

	results := make(chan int, 2)
	var wg sync.WaitGroup
	for _, blob := range [][]byte{[]byte("left"), []byte("right")} {
		blob := blob
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := putSyncTest(t, httpSrv.URL, token, blob, map[string]string{"If-Match": initialETag})
			results <- resp.StatusCode
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()
	close(results)
	var ok, conflicts int
	for status := range results {
		switch status {
		case http.StatusOK:
			ok++
		case http.StatusPreconditionFailed:
			conflicts++
		}
	}
	if ok != 1 || conflicts != 1 {
		t.Fatalf("conditional concurrent results: 200=%d 412=%d", ok, conflicts)
	}
}

func putSyncTest(t *testing.T, base, token string, blob []byte, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, base+"/sync", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
