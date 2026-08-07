package synctransaction

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"ssm/internal/cloud"
	"ssm/internal/config"
)

func TestAdoptRemoteRequiresReviewedIdentityAndCommitsVerifiedBlob(t *testing.T) {
	isolateTestUserConfig(t)
	local := []byte("opaque local encrypted vault")
	remote := []byte("opaque reviewed remote encrypted vault")
	if err := config.WritePrivateFile(config.Path(), local); err != nil {
		t.Fatal(err)
	}
	remoteIdentity := PublicationTargetIdentity(remote)
	if err := config.WritePrivateFile(remoteIdentityPath(), []byte("cached-baseline\n")); err != nil {
		t.Fatal(err)
	}
	if err := preserveConflict(SyncConflict{
		LocalETag:  PublicationTargetIdentity(local),
		RemoteETag: remoteIdentity,
		CachedETag: "cached-baseline",
	}); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"`+remoteIdentity+`"`)
		if r.Method == http.MethodGet {
			_, _ = w.Write(remote)
		}
	}))
	t.Cleanup(server.Close)
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: server.URL}); err != nil {
		t.Fatal(err)
	}

	invalidFacts, err := New(Options{}).AdoptRemote(BlobIdentity{Exists: true, Value: "not-a-sha"})
	if !errors.Is(err, ErrConflict) || invalidFacts.Changed {
		t.Fatalf("invalid adoption = facts=%+v err=%v", invalidFacts, err)
	}

	invalidations := 0
	facts, err := New(Options{Invalidate: func() { invalidations++ }}).AdoptRemote(BlobIdentity{Exists: true, Value: remoteIdentity})
	if err != nil || !facts.Changed || invalidations != 1 {
		t.Fatalf("adoption = facts=%+v err=%v invalidations=%d", facts, err, invalidations)
	}
	got, err := os.ReadFile(config.Path())
	if err != nil || string(got) != string(remote) {
		t.Fatalf("local vault = %q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(config.Dir(), "sync-conflict.json")); !os.IsNotExist(err) {
		t.Fatalf("conflict evidence remains: %v", err)
	}
	if got := cachedRemoteIdentity(); got != remoteIdentity {
		t.Fatalf("cached identity = %q, want %q", got, remoteIdentity)
	}
}

func TestAdoptRemoteRejectsChangedHeadWithoutLocalMutation(t *testing.T) {
	isolateTestUserConfig(t)
	local := []byte("opaque local encrypted vault")
	if err := config.WritePrivateFile(config.Path(), local); err != nil {
		t.Fatal(err)
	}
	expected := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := preserveConflict(SyncConflict{RemoteETag: expected}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`)
	}))
	t.Cleanup(server.Close)
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: server.URL}); err != nil {
		t.Fatal(err)
	}
	_, err := New(Options{}).AdoptRemote(BlobIdentity{Exists: true, Value: expected})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("error = %v, want conflict", err)
	}
	got, readErr := os.ReadFile(config.Path())
	if readErr != nil || string(got) != string(local) {
		t.Fatalf("local vault changed: %q err=%v", got, readErr)
	}
}
