package inventorytransaction

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ssm/internal/config"
)

func TestPublishingIntentUsesMinimalPrivateTransactionProjection(t *testing.T) {
	intentType := reflect.TypeOf(publishingIntent{})
	wantIntentFields := []struct {
		name string
		tag  string
	}{
		{name: "Version", tag: "version"},
		{name: "State", tag: "state"},
		{name: "Scope", tag: "scope"},
		{name: "TransactionIDs", tag: "transaction_ids"},
		{name: "Transactions", tag: "transactions"},
		{name: "PrerequisiteExists", tag: "prerequisite_remote_exists"},
		{name: "PrerequisiteIdentity", tag: "prerequisite_remote_identity,omitempty"},
		{name: "TargetIdentity", tag: "target_encrypted_blob_identity"},
		{name: "ObservedExists", tag: "observed_remote_exists,omitempty"},
		{name: "ObservedIdentity", tag: "observed_remote_identity,omitempty"},
	}
	if intentType.NumField() != len(wantIntentFields) {
		t.Fatalf("publishing intent has %d fields, want exact private schema of %d", intentType.NumField(), len(wantIntentFields))
	}
	for index, want := range wantIntentFields {
		field := intentType.Field(index)
		if field.Name != want.name || field.Tag.Get("json") != want.tag {
			t.Fatalf("publishing intent field %d = %s %q, want %s %q", index, field.Name, field.Tag.Get("json"), want.name, want.tag)
		}
	}

	transactions, ok := intentType.FieldByName("Transactions")
	if !ok {
		t.Fatal("publishing intent lost its recovered-receipt transaction projection")
	}
	if transactions.Type.Kind() != reflect.Slice {
		t.Fatal("publishing intent transaction projection is not an ordered slice")
	}
	if transactions.Type.Elem() == reflect.TypeOf(MutationView{}) {
		t.Fatal("publishing intent directly embeds the extensible public MutationView")
	}

	projectionType := transactions.Type.Elem()
	wantFields := []struct {
		name string
		tag  string
	}{
		{name: "Operation", tag: "operation"},
		{name: "CreatedAt", tag: "created_at"},
	}
	if projectionType.NumField() != len(wantFields) {
		t.Fatalf("publishing intent transaction projection has %d fields, want %d", projectionType.NumField(), len(wantFields))
	}
	for index, want := range wantFields {
		field := projectionType.Field(index)
		if field.Name != want.name || field.Tag.Get("json") != want.tag {
			t.Fatalf("publishing intent transaction field %d = %s %q, want %s %q", index, field.Name, field.Tag.Get("json"), want.name, want.tag)
		}
	}
}

func TestLoadPublishingIntentSanitizesVersionOneBeforeRecovery(t *testing.T) {
	intentPath := usePublishingIntentTestHome(t)
	const (
		savedKeyNameCanary = "ISSUE23_V1_SAVED_KEY_NAME_CANARY"
		aliasCanary        = "ISSUE23_V1_ALIAS_CANARY"
	)
	versionOne := []byte(`{
  "version": 1,
  "state": "ready",
  "scope": "only",
  "transaction_ids": ["tx_23232323232323232323232323232323"],
  "transactions": [{
    "id": "tx_23232323232323232323232323232323",
    "alias": "` + aliasCanary + `",
    "aliases": ["` + aliasCanary + `"],
    "key_name": "` + savedKeyNameCanary + `",
    "operation": "saved_key_removed",
    "created_at": "2026-07-29T00:00:23Z",
    "connections": 0,
    "keys": 1
  }],
  "prerequisite_remote_exists": true,
  "prerequisite_remote_identity": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "target_encrypted_blob_identity": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "created_at": "2026-07-29T00:00:24Z"
}
`)
	if err := config.WritePrivateFile(intentPath, versionOne); err != nil {
		t.Fatalf("write version-one publishing intent: %v", err)
	}

	intent, err := loadPublishingIntent()
	if err != nil {
		t.Fatalf("load version-one publishing intent: %v", err)
	}
	if intent.Version != publishingIntentVersion || intent.State != intentReady ||
		intent.Scope != "only" || !reflect.DeepEqual(intent.TransactionIDs, []string{"tx_23232323232323232323232323232323"}) ||
		len(intent.Transactions) != 1 ||
		intent.Transactions[0] != (publishingIntentTransaction{
			Operation: "saved_key_removed", CreatedAt: "2026-07-29T00:00:23Z",
		}) {
		t.Fatal("version-one sanitization lost reconciliation or minimum recovered-receipt metadata")
	}

	sanitized, err := os.ReadFile(intentPath) //nolint:gosec // fixed path beneath the test-owned home
	if err != nil {
		t.Fatalf("read sanitized publishing intent: %v", err)
	}
	for _, forbidden := range []string{savedKeyNameCanary, aliasCanary, `"key_name"`, `"alias"`, `"aliases"`, `"connections"`, `"keys"`} {
		if bytes.Contains(sanitized, []byte(forbidden)) {
			t.Fatal("sanitized publishing intent retained deprecated public-view metadata")
		}
	}
	if !bytes.Contains(sanitized, []byte(`"version": 2`)) ||
		!bytes.Contains(sanitized, []byte(`"transaction_ids"`)) ||
		!bytes.Contains(sanitized, []byte(`"saved_key_removed"`)) {
		t.Fatal("sanitized publishing intent omitted its version or reconciliation projection")
	}
}

func TestLoadPublishingIntentRejectsUnknownFieldsWithoutRewrite(t *testing.T) {
	intentPath := usePublishingIntentTestHome(t)
	versionOne := []byte(`{
  "version": 1,
  "state": "ready",
  "scope": "only",
  "transaction_ids": ["tx_23232323232323232323232323232323"],
  "transactions": [{
    "id": "tx_23232323232323232323232323232323",
    "operation": "saved_key_removed",
    "created_at": "2026-07-29T00:00:23Z"
  }],
  "prerequisite_remote_exists": false,
  "target_encrypted_blob_identity": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "created_at": "2026-07-29T00:00:24Z"
}
`)
	versionTwo := bytes.Replace(versionOne, []byte(`"version": 1`), []byte(`"version": 2`), 1)
	versionTwo = bytes.Replace(
		versionTwo,
		[]byte(`    "id": "tx_23232323232323232323232323232323",`+"\n"),
		nil,
		1,
	)
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "version one top level",
			data: bytes.Replace(versionOne, []byte(`"state": "ready"`), []byte(`"unexpected": true, "state": "ready"`), 1),
		},
		{
			name: "version one transaction",
			data: bytes.Replace(versionOne, []byte(`"operation": "saved_key_removed"`), []byte(`"unexpected": true, "operation": "saved_key_removed"`), 1),
		},
		{
			name: "version two top level",
			data: bytes.Replace(versionTwo, []byte(`"state": "ready"`), []byte(`"unexpected": true, "state": "ready"`), 1),
		},
		{
			name: "version two transaction",
			data: bytes.Replace(versionTwo, []byte(`"operation": "saved_key_removed"`), []byte(`"unexpected": true, "operation": "saved_key_removed"`), 1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := config.WritePrivateFile(intentPath, test.data); err != nil {
				t.Fatalf("write strict-decode publishing intent: %v", err)
			}
			_, err := loadPublishingIntent()
			if err == nil || !strings.Contains(err.Error(), `unknown field "unexpected"`) {
				t.Fatal("publishing intent accepted an unknown field")
			}
			after, readErr := os.ReadFile(intentPath) //nolint:gosec // fixed path beneath the test-owned home
			if readErr != nil {
				t.Fatalf("read rejected publishing intent: %v", readErr)
			}
			if !bytes.Equal(after, test.data) {
				t.Fatal("rejected publishing intent was rewritten")
			}
		})
	}
}

func TestLoadPublishingIntentRejectsUnknownVersionWithoutRewrite(t *testing.T) {
	intentPath := usePublishingIntentTestHome(t)
	unknown := []byte(`{"version":99,"unexpected":"not trusted"}` + "\n")
	if err := config.WritePrivateFile(intentPath, unknown); err != nil {
		t.Fatalf("write unknown-version publishing intent: %v", err)
	}
	_, err := loadPublishingIntent()
	if err == nil || !strings.Contains(err.Error(), "unsupported publishing intent version 99") {
		t.Fatal("publishing intent accepted an unknown version")
	}
	after, readErr := os.ReadFile(intentPath) //nolint:gosec // fixed path beneath the test-owned home
	if readErr != nil {
		t.Fatalf("read unknown-version publishing intent: %v", readErr)
	}
	if !bytes.Equal(after, unknown) {
		t.Fatal("unknown-version publishing intent was rewritten")
	}
}

func TestLoadPublishingIntentRejectsChangedVersionOneIDOrderWithoutRewrite(t *testing.T) {
	intentPath := usePublishingIntentTestHome(t)
	changed := []byte(`{
  "version": 1,
  "state": "ready",
  "scope": "only",
  "transaction_ids": ["tx_23232323232323232323232323232323"],
  "transactions": [{
    "id": "tx_24242424242424242424242424242424",
    "operation": "saved_key_removed",
    "created_at": "2026-07-29T00:00:23Z"
  }],
  "prerequisite_remote_exists": false,
  "target_encrypted_blob_identity": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "created_at": "2026-07-29T00:00:24Z"
}
`)
	if err := config.WritePrivateFile(intentPath, changed); err != nil {
		t.Fatalf("write changed-ID publishing intent: %v", err)
	}
	_, err := loadPublishingIntent()
	if err == nil || !strings.Contains(err.Error(), "transaction metadata order changed") {
		t.Fatal("version-one publishing intent accepted changed transaction metadata order")
	}
	after, readErr := os.ReadFile(intentPath) //nolint:gosec // fixed path beneath the test-owned home
	if readErr != nil {
		t.Fatalf("read changed-ID publishing intent: %v", readErr)
	}
	if !bytes.Equal(after, changed) {
		t.Fatal("changed-ID publishing intent was rewritten")
	}
}

func usePublishingIntentTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return filepath.Join(home, ".config", "ssm", "publishing-intent.json")
}
