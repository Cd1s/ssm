package synctransaction

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"ssm/internal/cloud"
	"ssm/internal/config"
)

func TestPublicationCASAndMissingCache(t *testing.T) {
	t.Run("412 becomes conflict and does not overwrite remote", func(t *testing.T) {
		isolateTestUserConfig(t)
		baseline := []byte("remote baseline")
		cached := opaqueIdentity(baseline)
		if err := config.WritePrivateFile(filepath.Join(config.Dir(), "remote.etag"), []byte(cached+"\n")); err != nil {
			t.Fatal(err)
		}
		putCount := 0
		headCount := 0
		remote := cached
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodHead:
				headCount++
				w.Header().Set("ETag", `"`+remote+`"`)
			case http.MethodPut:
				putCount++
				if got := r.Header.Get("If-Match"); got != `"`+cached+`"` {
					t.Fatalf("If-Match=%q", got)
				}
				remote = strings.Repeat("c", 64)
				w.WriteHeader(http.StatusPreconditionFailed)
			}
		}))
		defer server.Close()
		if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "token"}); err != nil {
			t.Fatal(err)
		}
		tx := New(Options{})
		prepared, err := tx.PreparePublication([]byte("candidate"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.SendPublication([]byte("candidate"), prepared)
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("SendPublication error=%v, want ErrConflict", err)
		}
		if putCount != 1 {
			t.Fatalf("PUT count=%d, want 1", putCount)
		}
		if headCount != 3 || remote != strings.Repeat("c", 64) {
			t.Fatalf("remote after rejected PUT: heads=%d etag=%q", headCount, remote)
		}
		conflict := loadConflict()
		if conflict == nil || conflict.RemoteETag != remote {
			t.Fatalf("conflict evidence=%+v, want remote=%q", conflict, remote)
		}
	})

	t.Run("missing cache rejects existing remote without PUT", func(t *testing.T) {
		isolateTestUserConfig(t)
		remoteETag := strings.Repeat("a", 64)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				w.Header().Set("ETag", `"`+remoteETag+`"`)
			}
			if r.Method == http.MethodPut {
				t.Fatalf("unexpected PUT")
			}
		}))
		defer server.Close()
		if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "token"}); err != nil {
			t.Fatal(err)
		}
		_, err := New(Options{}).PreparePublication([]byte("candidate"))
		if !errors.Is(err, ErrRefresh) {
			t.Fatalf("PreparePublication error=%v, want ErrRefresh", err)
		}
	})

	t.Run("missing cache and missing remote allows first push", func(t *testing.T) {
		isolateTestUserConfig(t)
		putCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodHead:
				w.WriteHeader(http.StatusNotFound)
			case http.MethodPut:
				putCount++
				if got := r.Header.Get("If-None-Match"); got != "*" {
					t.Fatalf("If-None-Match=%q", got)
				}
				w.Header().Set("ETag", `"`+opaqueIdentity([]byte("candidate"))+`"`)
				w.Header().Set("X-Sync-Precondition", "1")
			}
		}))
		defer server.Close()
		if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "token"}); err != nil {
			t.Fatal(err)
		}
		tx := New(Options{})
		prepared, err := tx.PreparePublication([]byte("candidate"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.SendPublication([]byte("candidate"), prepared); err != nil {
			t.Fatal(err)
		}
		if putCount != 1 {
			t.Fatalf("PUT count=%d, want 1", putCount)
		}
	})

	t.Run("old server without capability header remains compatible", func(t *testing.T) {
		isolateTestUserConfig(t)
		baseline := []byte("old server baseline")
		cached := opaqueIdentity(baseline)
		if err := config.WritePrivateFile(filepath.Join(config.Dir(), "remote.etag"), []byte(cached+"\n")); err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodHead:
				w.Header().Set("ETag", `"`+cached+`"`)
			case http.MethodPut:
				w.Header().Set("ETag", `"`+opaqueIdentity([]byte("candidate"))+`"`)
			}
		}))
		defer server.Close()
		if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "token"}); err != nil {
			t.Fatal(err)
		}
		tx := New(Options{})
		prepared, err := tx.PreparePublication([]byte("candidate"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.SendPublication([]byte("candidate"), prepared); err != nil {
			t.Fatalf("old server compatibility error=%v", err)
		}
	})
}
