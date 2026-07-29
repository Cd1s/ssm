package synctransaction

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"ssm/internal/cloud"
	"ssm/internal/config"
)

func TestStreamTransactionPolicy(t *testing.T) {
	t.Run("online zero and every negative interval are rejected", func(t *testing.T) {
		isolateTestUserConfig(t)
		if _, err := New(Options{}).BeginStream(0); !errors.Is(err, ErrStreamRefresh) {
			t.Fatalf("online zero interval error = %v, want %v", err, ErrStreamRefresh)
		}
		if _, err := New(Options{Offline: true}).BeginStream(-time.Second); !errors.Is(err, ErrStreamRefresh) {
			t.Fatalf("offline negative interval error = %v, want %v", err, ErrStreamRefresh)
		}
	})

	t.Run("offline zero never parses cloud configuration or performs transport", func(t *testing.T) {
		isolateTestUserConfig(t)
		var requests atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			requests.Add(1)
		}))
		t.Cleanup(server.Close)
		path := filepath.Join(config.Dir(), "cloud.json")
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}

		stream, err := New(Options{Offline: true}).BeginStream(0)
		if err != nil {
			t.Fatal(err)
		}
		facts, err := stream.Initialize()
		if err != nil {
			t.Fatal(err)
		}
		if !facts.Offline || facts.Configuration != ConfigurationOffline ||
			facts.Freshness != FreshnessCached || facts.Remote != RemoteNotChecked {
			t.Fatalf("offline initialization facts = %+v", facts)
		}
		for index := 0; index < 3; index++ {
			facts, err = stream.BeforeLine()
			if err != nil || facts.Changed {
				t.Fatalf("offline line %d facts=%+v err=%v", index, facts, err)
			}
		}
		if requests.Load() != 0 {
			t.Fatalf("offline stream requests = %d, want 0", requests.Load())
		}
	})

	t.Run("positive online cadence refreshes only when due", func(t *testing.T) {
		isolateTestUserConfig(t)
		now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
		var headCount, getCount atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", `"stream-current"`)
			switch r.Method {
			case http.MethodHead:
				headCount.Add(1)
			case http.MethodGet:
				getCount.Add(1)
				_, _ = w.Write([]byte("opaque stream snapshot"))
			default:
				t.Fatalf("unexpected method %s", r.Method)
			}
		}))
		t.Cleanup(server.Close)
		if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "opaque"}); err != nil {
			t.Fatal(err)
		}

		invalidations := 0
		stream, err := New(Options{
			Now:        func() time.Time { return now },
			Invalidate: func() { invalidations++ },
		}).BeginStream(10 * time.Second)
		if err != nil {
			t.Fatal(err)
		}
		facts, err := stream.Initialize()
		if err != nil || !facts.Changed {
			t.Fatalf("initialize facts=%+v err=%v", facts, err)
		}
		now = now.Add(9 * time.Second)
		facts, err = stream.BeforeLine()
		if err != nil || facts.Changed {
			t.Fatalf("early line facts=%+v err=%v", facts, err)
		}
		now = now.Add(time.Second)
		facts, err = stream.BeforeLine()
		if err != nil || facts.Changed {
			t.Fatalf("due unchanged line facts=%+v err=%v", facts, err)
		}
		if headCount.Load() != 2 || getCount.Load() != 1 || invalidations != 1 {
			t.Fatalf(
				"cadence counts HEAD=%d GET=%d invalidations=%d, want 2, 1, 1",
				headCount.Load(),
				getCount.Load(),
				invalidations,
			)
		}
	})

	t.Run("due refresh failure never reports changed state", func(t *testing.T) {
		isolateTestUserConfig(t)
		now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
		var headCount atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodHead {
				t.Fatalf("unexpected method %s", r.Method)
			}
			count := headCount.Add(1)
			if count > 1 {
				http.Error(w, `{"error":"fixture refresh failure"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("ETag", `"stream-current"`)
		}))
		t.Cleanup(server.Close)
		if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "opaque"}); err != nil {
			t.Fatal(err)
		}
		if err := config.WritePrivateFile(
			filepath.Join(config.Dir(), "remote.etag"),
			[]byte("stream-current\n"),
		); err != nil {
			t.Fatal(err)
		}

		stream, err := New(Options{Now: func() time.Time { return now }}).BeginStream(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Initialize(); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
		facts, err := stream.BeforeLine()
		if !errors.Is(err, ErrRefresh) || facts.Changed {
			t.Fatalf("failed refresh facts=%+v err=%v", facts, err)
		}
		if headCount.Load() != 2 {
			t.Fatalf("failed refresh HEAD count = %d, want 2", headCount.Load())
		}
	})
}
