package synctransaction

import (
	"bytes"
	"errors"
	"testing"

	"ssm/internal/config"
)

func TestSyncAcceptsIdenticalLocalAndRemoteWhenCachedIdentityIsStale(test *testing.T) {
	fixture := newPullRace(test, config.SyncModeStrict, nil)
	fixture.remote = fixture.local
	fixture.remoteID = opaqueIdentity(fixture.local)
	stale := opaqueIdentity([]byte("an older vault"))
	if err := config.WritePrivateFile(remoteIdentityPath(), []byte(stale+"\n")); err != nil {
		test.Fatal(err)
	}
	tx := fixture.tx()
	cachedStale := cachedRemoteIdentity() != fixture.remoteID

	_, syncErr := tx.Sync()
	test.Logf("local==remote=%v cached_stale=%v err=%v", opaqueIdentity(readVault(test)) == fixture.remoteID, cachedStale, syncErr)
	_, pullErr := tx.Pull()
	test.Logf("Pull(): err=%v", pullErr)
	if syncErr != nil || pullErr != nil {
		test.Fatalf("identical local and remote blobs should sync and pull successfully (sync=%v pull=%v)", syncErr, pullErr)
	}
	if !bytes.Equal(readVault(test), fixture.local) {
		test.Fatal("sync or pull changed the identical vault")
	}
	if got := cachedRemoteIdentity(); got != fixture.remoteID {
		test.Fatalf("cached remote identity = %q, want %q", got, fixture.remoteID)
	}
	if loadConflict() != nil {
		test.Fatal("identical blobs must not leave conflict evidence")
	}
}

func TestPullAfterFailedMetadataWriteIsNotAConflict(test *testing.T) {
	fixture := newPullRace(test, config.SyncModeStrict, nil)
	previousIdentity := opaqueIdentity(fixture.local)
	if got := cachedRemoteIdentity(); got != previousIdentity {
		test.Fatalf("setup: cache=%q, want %q", got, previousIdentity)
	}
	tx := fixture.tx()
	if _, err := tx.Pull(); err != nil {
		test.Fatalf("setup: first pull should succeed, got %v", err)
	}
	if !bytes.Equal(readVault(test), fixture.remote) {
		test.Fatal("first pull did not install the remote vault")
	}
	if err := config.WritePrivateFile(remoteIdentityPath(), []byte(previousIdentity+"\n")); err != nil {
		test.Fatal(err)
	}
	test.Logf("state: local==remote=%v cached_stale=%v", opaqueIdentity(readVault(test)) == fixture.remoteID, cachedRemoteIdentity() == previousIdentity)
	_, err := tx.Pull()
	test.Logf("Pull() of the unchanged remote: err=%v", err)
	if err != nil {
		test.Fatalf("pull of an unchanged remote should succeed, got %v", err)
	}
	if !bytes.Equal(readVault(test), fixture.remote) {
		test.Fatal("second pull changed the installed vault")
	}
	if got := cachedRemoteIdentity(); got != fixture.remoteID {
		test.Fatalf("cached remote identity = %q, want %q", got, fixture.remoteID)
	}
	if loadConflict() != nil {
		test.Fatal("an unchanged remote must not leave conflict evidence")
	}
}

func TestStaleCachedIdentityStillConflictsWhenLocalAndRemoteDiverge(test *testing.T) {
	for _, operation := range []string{"sync", "pull", "background"} {
		test.Run(operation, func(test *testing.T) {
			fixture := newPullRace(test, config.SyncModeLocalFirst, nil)
			cached := cachedRemoteIdentity()
			mutated := fakeVaultBlob("divergent local vault")
			local := opaqueIdentity(mutated)
			if local == fixture.remoteID || local == cached || fixture.remoteID == cached {
				test.Fatal("setup: local, remote, and cached identities must all differ")
			}
			if err := config.WritePrivateFile(config.Path(), mutated); err != nil {
				test.Fatal(err)
			}
			tx := fixture.tx()
			var err error
			switch operation {
			case "sync":
				_, err = tx.Sync()
			case "pull":
				_, err = tx.Pull()
			case "background":
				err = tx.BackgroundSync("")
			}
			if !errors.Is(err, ErrConflict) {
				test.Fatalf("error = %v, want %v", err, ErrConflict)
			}
			if !bytes.Equal(readVault(test), mutated) {
				test.Fatal("a truly divergent local vault was overwritten")
			}
			if got := cachedRemoteIdentity(); got != cached {
				test.Fatalf("cached remote identity changed to %q, want %q", got, cached)
			}
			conflict := loadConflict()
			if conflict == nil || conflict.LocalETag != local || conflict.RemoteETag != fixture.remoteID || conflict.CachedETag != cached {
				test.Fatalf("conflict evidence = %+v, want the three divergent identities", conflict)
			}
			if fixture.gets.Load() != 0 {
				test.Fatal("a truly divergent vault must not be downloaded")
			}
		})
	}
}
