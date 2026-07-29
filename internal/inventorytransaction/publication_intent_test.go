package inventorytransaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
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

func TestDecodePublishingIntentRejectsDuplicateMembersAtAnyDepth(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{
			name: "top level version dispatch",
			data: `{"version":1,"version":2}`,
		},
		{
			name: "top level state",
			data: `{"state":"ready","state":"ambiguous"}`,
		},
		{
			name: "top level scope",
			data: `{"scope":"only","scope":"all"}`,
		},
		{
			name: "top level transaction IDs",
			data: `{"transaction_ids":[],"transaction_ids":[]}`,
		},
		{
			name: "top level transactions",
			data: `{"transactions":[],"transactions":[]}`,
		},
		{
			name: "top level prerequisite existence",
			data: `{"prerequisite_remote_exists":false,"prerequisite_remote_exists":true}`,
		},
		{
			name: "top level prerequisite identity",
			data: `{"prerequisite_remote_identity":"","prerequisite_remote_identity":""}`,
		},
		{
			name: "top level target identity",
			data: `{"target_encrypted_blob_identity":"","target_encrypted_blob_identity":""}`,
		},
		{
			name: "top level observation existence",
			data: `{"observed_remote_exists":false,"observed_remote_exists":true}`,
		},
		{
			name: "top level observed identity",
			data: `{"observed_remote_identity":"","observed_remote_identity":""}`,
		},
		{
			name: "v2 transaction operation",
			data: `{"transactions":[{"operation":"created","operation":"removed"}]}`,
		},
		{
			name: "v2 transaction creation time",
			data: `{"transactions":[{"created_at":"first","created_at":"second"}]}`,
		},
		{
			name: "v1 creation time",
			data: `{"created_at":"first","created_at":"second"}`,
		},
		{
			name: "v1 transaction ID",
			data: `{"transactions":[{"id":"first","id":"second"}]}`,
		},
		{
			name: "v1 transaction alias",
			data: `{"transactions":[{"alias":"first","alias":"second"}]}`,
		},
		{
			name: "v1 transaction aliases",
			data: `{"transactions":[{"aliases":[],"aliases":[]}]}`,
		},
		{
			name: "v1 transaction key name",
			data: `{"transactions":[{"key_name":"first","key_name":"second"}]}`,
		},
		{
			name: "v1 transaction connection count",
			data: `{"transactions":[{"connections":1,"connections":2}]}`,
		},
		{
			name: "v1 transaction key count",
			data: `{"transactions":[{"keys":1,"keys":2}]}`,
		},
		{
			name: "object inside array with escaped equivalent name",
			data: `{"outer":[{"member":1,"\u006dember":2}]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var value any
			if err := decodePublishingIntent([]byte(test.data), &value, false); err == nil {
				t.Fatal("publishing intent accepted a duplicate JSON member")
			}
		})
	}
}

func TestDecodePublishingIntentAcceptsDistinctMembersAndEscapedStrings(t *testing.T) {
	data := []byte(`{
	  "member": "quote: \" slash: \\ unicode: \u263a",
	  "member_similar": "different",
	  "array": [null, true, 1, "value", {"nested": "ok"}]
	}`)
	var value any
	if err := decodePublishingIntent(data, &value, false); err != nil {
		t.Fatalf("publishing intent rejected valid JSON: %v", err)
	}
}

func TestDecodePublishingIntentRejectsTrailingData(t *testing.T) {
	var value any
	err := decodePublishingIntent([]byte(`{"version":2} {"version":2}`), &value, false)
	if err == nil || err.Error() != "publishing intent document is invalid" {
		t.Fatalf("trailing-data error = %v, want constant invalid-document error", err)
	}
}

func TestDecodePublishingIntentBoundsNestingDepth(t *testing.T) {
	const wantDepth = 16
	if maxPublishingIntentJSONDepth != wantDepth {
		t.Fatalf("publishing intent JSON depth = %d, want reviewed %d", maxPublishingIntentJSONDepth, wantDepth)
	}
	tests := []struct {
		name    string
		depth   int
		wantErr bool
	}{
		{name: "under", depth: wantDepth - 1},
		{name: "exact", depth: wantDepth},
		{name: "over", depth: wantDepth + 1, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := []byte(strings.Repeat("[", test.depth) + "0" + strings.Repeat("]", test.depth))
			var value any
			err := decodePublishingIntent(data, &value, false)
			if test.wantErr {
				if err == nil || err.Error() != "publishing intent document is invalid" {
					t.Fatalf("depth error = %v, want constant invalid-document error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode depth %d: %v", test.depth, err)
			}
		})
	}
}

func TestDecodePublishingIntentBoundsTotalJSONTokens(t *testing.T) {
	const wantTokens = 32 * 1024
	if maxPublishingIntentJSONTokens != wantTokens {
		t.Fatalf("publishing intent JSON token limit = %d, want reviewed %d", maxPublishingIntentJSONTokens, wantTokens)
	}
	tests := []struct {
		name    string
		data    func(int) []byte
		count   int
		wantErr bool
	}{
		{name: "array under", data: jsonArrayWithNulls, count: wantTokens - 3},
		{name: "array exact", data: jsonArrayWithNulls, count: wantTokens - 2},
		{name: "array over", data: jsonArrayWithNulls, count: wantTokens - 1, wantErr: true},
		{name: "object under", data: jsonObjectWithMembers, count: (wantTokens-2)/2 - 1},
		{name: "object exact", data: jsonObjectWithMembers, count: (wantTokens - 2) / 2},
		{name: "object over", data: jsonObjectWithMembers, count: (wantTokens-2)/2 + 1, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var value any
			err := decodePublishingIntent(test.data(test.count), &value, false)
			if test.wantErr {
				if err == nil || err.Error() != "publishing intent document is invalid" {
					t.Fatalf("token-budget error = %v, want constant invalid-document error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode JSON within token budget: %v", err)
			}
		})
	}
}

func TestDecodePublishingIntentRejectsBudgetsBeforeTypedDecode(t *testing.T) {
	const (
		maxJSONDepth  = 16
		maxJSONTokens = 32 * 1024
	)
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "too deep",
			data: []byte(strings.Repeat("[", maxJSONDepth+1) + "null" + strings.Repeat("]", maxJSONDepth+1)),
		},
		{name: "too wide", data: jsonArrayWithNulls(maxJSONTokens)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := typedDecodeCanary{}
			err := decodePublishingIntent(test.data, &target, false)
			if err == nil || err.Error() != "publishing intent document is invalid" {
				t.Fatalf("resource error = %v, want constant invalid-document error", err)
			}
			if target.called {
				t.Fatal("resource-exhausting document reached typed JSON decoding")
			}
		})
	}
}

func TestLoadPublishingIntentBoundsDocumentBytes(t *testing.T) {
	const wantDocumentBytes = 512 * 1024
	if maxPublishingIntentDocumentBytes != wantDocumentBytes {
		t.Fatalf("publishing intent document limit = %d, want reviewed %d", maxPublishingIntentDocumentBytes, wantDocumentBytes)
	}

	intentPath := usePublishingIntentTestHome(t)
	base := []byte(`{
  "version": 2,
  "state": "ready",
  "scope": "only",
  "transaction_ids": ["tx_23232323232323232323232323232323"],
  "transactions": [{
    "operation": "created",
    "created_at": "2026-07-29T00:00:23Z"
  }],
  "prerequisite_remote_exists": false,
  "target_encrypted_blob_identity": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}`)
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "under", size: wantDocumentBytes - 1},
		{name: "exact", size: wantDocumentBytes},
		{name: "over", size: wantDocumentBytes + 1, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := append([]byte(nil), base...)
			document = append(document, bytes.Repeat([]byte(" "), test.size-len(document))...)
			if err := config.WritePrivateFile(intentPath, document); err != nil {
				t.Fatalf("write boundary publishing intent: %v", err)
			}

			_, err := loadPublishingIntent()
			if test.wantErr {
				if err == nil || err.Error() != "publishing intent document is invalid" {
					t.Fatalf("oversize error = %v, want constant invalid-document error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("load %d-byte publishing intent: %v", test.size, err)
			}
		})
	}
}

func TestReadPublishingIntentDocumentRejectsGrowthAfterStat(t *testing.T) {
	const wantDocumentBytes = 512 * 1024
	path := filepath.Join(t.TempDir(), "publishing-intent.json")
	before := bytes.Repeat([]byte(" "), wantDocumentBytes-1)
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatalf("write initial publishing intent: %v", err)
	}
	file, err := os.Open(path) //nolint:gosec // path is beneath the test-owned temporary directory
	if err != nil {
		t.Fatalf("open initial publishing intent: %v", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		t.Fatalf("stat initial publishing intent: %v", err)
	}
	appender, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // path is beneath the test-owned temporary directory
	if err != nil {
		_ = file.Close()
		t.Fatalf("open publishing intent appender: %v", err)
	}
	if _, err := appender.Write([]byte("  ")); err != nil {
		_ = appender.Close()
		t.Fatalf("grow publishing intent after stat: %v", err)
	}
	if err := appender.Close(); err != nil {
		t.Fatalf("close publishing intent appender: %v", err)
	}

	_, err = readPublishingIntentDocument(file, info.Size())
	if err == nil || err.Error() != "publishing intent document is invalid" {
		_ = file.Close()
		t.Fatalf("post-stat growth error = %v, want constant invalid-document error", err)
	}
	if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
		_ = file.Close()
		t.Fatalf("grown publishing intent remains open after rejection: %v", err)
	}
}

func TestReadPublishingIntentDocumentClosesOpenedFileBeforeReturn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "publishing-intent.json")
	document := []byte(`{"version":2}`)
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("write publishing intent: %v", err)
	}
	file, err := os.Open(path) //nolint:gosec // path is beneath the test-owned temporary directory
	if err != nil {
		t.Fatalf("open publishing intent: %v", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		t.Fatalf("stat publishing intent: %v", err)
	}

	data, err := readPublishingIntentDocument(file, info.Size())
	if err != nil {
		_ = file.Close()
		t.Fatalf("read publishing intent: %v", err)
	}
	if !bytes.Equal(data, document) {
		_ = file.Close()
		t.Fatal("publishing intent read changed document bytes")
	}
	if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
		_ = file.Close()
		t.Fatalf("publishing intent file remains open after read: %v", err)
	}
}

func TestLoadPublishingIntentRejectsResourceBudgetsBeforeVersionDispatch(t *testing.T) {
	const (
		maxDocumentBytes = 512 * 1024
		maxJSONDepth     = 16
		maxJSONTokens    = 32 * 1024
	)
	intentPath := usePublishingIntentTestHome(t)
	unsupported := []byte(`{"version":99}`)
	oversized := append([]byte(nil), unsupported...)
	oversized = append(oversized, bytes.Repeat([]byte(" "), maxDocumentBytes+1-len(oversized))...)
	tests := []struct {
		name string
		data []byte
	}{
		{name: "oversized", data: oversized},
		{
			name: "too deep",
			data: []byte(`{"version":99,"resource":` +
				strings.Repeat("[", maxJSONDepth) + "null" + strings.Repeat("]", maxJSONDepth) + `}`),
		},
		{
			name: "too wide",
			data: append(
				append([]byte(`{"version":99,"resource":`), jsonArrayWithNulls(maxJSONTokens)...),
				'}',
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := config.WritePrivateFile(intentPath, test.data); err != nil {
				t.Fatalf("write unsupported resource publishing intent: %v", err)
			}
			_, err := loadPublishingIntent()
			if err == nil || err.Error() != "publishing intent document is invalid" {
				t.Fatalf("resource error = %v, want invalid-document before unsupported-version dispatch", err)
			}
			after, readErr := os.ReadFile(intentPath) //nolint:gosec // fixed path beneath the test-owned home
			if readErr != nil {
				t.Fatalf("read rejected resource publishing intent: %v", readErr)
			}
			if !bytes.Equal(after, test.data) {
				t.Fatal("resource rejection rewrote or removed the unsupported-version sidecar")
			}
		})
	}
}

func TestValidatePublishingIntentUsesConstantSecretSafeErrors(t *testing.T) {
	valid := publishingIntent{
		Version:        publishingIntentVersion,
		State:          intentReady,
		Scope:          "only",
		TransactionIDs: []string{"tx_23232323232323232323232323232323"},
		Transactions: []publishingIntentTransaction{{
			Operation: "created", CreatedAt: "2026-07-29T00:00:23Z",
		}},
		TargetIdentity: strings.Repeat("a", 64),
	}
	tests := []struct {
		name   string
		canary string
		mutate func(*publishingIntent)
		want   string
	}{
		{
			name: "version",
			mutate: func(intent *publishingIntent) {
				intent.Version = 232323
			},
			want: "publishing intent version is unsupported",
		},
		{
			name:   "state",
			canary: "ISSUE23_UNTRUSTED_STATE_CANARY",
			mutate: func(intent *publishingIntent) {
				intent.State = "ISSUE23_UNTRUSTED_STATE_CANARY"
			},
			want: "publishing intent state is invalid",
		},
		{
			name:   "scope",
			canary: "ISSUE23_UNTRUSTED_SCOPE_CANARY",
			mutate: func(intent *publishingIntent) {
				intent.Scope = "ISSUE23_UNTRUSTED_SCOPE_CANARY"
			},
			want: "publishing intent scope is invalid",
		},
		{
			name:   "transaction ID",
			canary: "ISSUE23_UNTRUSTED_TRANSACTION_ID_CANARY",
			mutate: func(intent *publishingIntent) {
				intent.TransactionIDs = []string{
					"ISSUE23_UNTRUSTED_TRANSACTION_ID_CANARY",
					"ISSUE23_UNTRUSTED_TRANSACTION_ID_CANARY",
				}
				intent.Transactions = append(intent.Transactions, intent.Transactions[0])
				intent.Scope = "all"
			},
			want: "publishing intent transaction IDs are invalid",
		},
		{
			name:   "operation",
			canary: "ISSUE23_UNTRUSTED_OPERATION_CANARY",
			mutate: func(intent *publishingIntent) {
				intent.Transactions[0].Operation = "ISSUE23_UNTRUSTED_OPERATION_CANARY"
			},
			want: "publishing intent transaction operation is invalid",
		},
		{
			name:   "creation time",
			canary: "ISSUE23_UNTRUSTED_CREATION_TIME_CANARY",
			mutate: func(intent *publishingIntent) {
				intent.Transactions[0].CreatedAt = "ISSUE23_UNTRUSTED_CREATION_TIME_CANARY"
			},
			want: "publishing intent transaction creation time is invalid",
		},
		{
			name:   "target identity",
			canary: "ISSUE23_UNTRUSTED_TARGET_IDENTITY_CANARY",
			mutate: func(intent *publishingIntent) {
				intent.TargetIdentity = "ISSUE23_UNTRUSTED_TARGET_IDENTITY_CANARY"
			},
			want: "publishing intent target identity is invalid",
		},
		{
			name:   "prerequisite identity",
			canary: "ISSUE23_UNTRUSTED_PREREQUISITE_IDENTITY_CANARY",
			mutate: func(intent *publishingIntent) {
				intent.PrerequisiteExists = true
				intent.PrerequisiteIdentity = "ISSUE23_UNTRUSTED_PREREQUISITE_IDENTITY_CANARY"
			},
			want: "publishing intent prerequisite identity is invalid",
		},
		{
			name:   "observed identity",
			canary: "ISSUE23_UNTRUSTED_OBSERVED_IDENTITY_CANARY",
			mutate: func(intent *publishingIntent) {
				intent.ObservedExists = true
				intent.ObservedIdentity = "ISSUE23_UNTRUSTED_OBSERVED_IDENTITY_CANARY"
			},
			want: "publishing intent observed identity is invalid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := valid
			intent.TransactionIDs = append([]string(nil), valid.TransactionIDs...)
			intent.Transactions = append([]publishingIntentTransaction(nil), valid.Transactions...)
			test.mutate(&intent)
			err := validatePublishingIntent(intent)
			if err == nil || err.Error() != test.want {
				t.Fatalf("validation error = %v, want constant %q", err, test.want)
			}
			if test.canary != "" && strings.Contains(err.Error(), test.canary) {
				t.Fatal("validation error exposed an untrusted sidecar value")
			}
		})
	}
}

func TestPublishingIntentBoundsTransactionCount(t *testing.T) {
	const wantTransactions = 1024
	if maxPublishingIntentTransactions != wantTransactions {
		t.Fatalf("publishing intent transaction limit = %d, want reviewed %d", maxPublishingIntentTransactions, wantTransactions)
	}
	tests := []struct {
		name    string
		count   int
		wantErr bool
	}{
		{name: "under", count: wantTransactions - 1},
		{name: "exact", count: wantTransactions},
		{name: "over", count: wantTransactions + 1, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := publishingIntentWithTransactions(test.count)
			err := validatePublishingIntent(intent)
			if test.wantErr {
				if err == nil || err.Error() != "publishing intent document is invalid" {
					t.Fatalf("transaction-count error = %v, want constant invalid-document error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validate %d-transaction publishing intent: %v", test.count, err)
			}
		})
	}

	intentPath := usePublishingIntentTestHome(t)
	document, err := json.MarshalIndent(publishingIntentWithTransactions(wantTransactions), "", "  ")
	if err != nil {
		t.Fatalf("marshal maximum publishing intent: %v", err)
	}
	document = append(document, '\n')
	if len(document) > 256*1024 {
		t.Fatalf("maximum canonical v2 publishing intent = %d bytes, want at most 256 KiB", len(document))
	}
	if err := config.WritePrivateFile(intentPath, document); err != nil {
		t.Fatalf("write maximum publishing intent: %v", err)
	}
	if _, err := loadPublishingIntent(); err != nil {
		t.Fatalf("load maximum publishing intent: %v", err)
	}
}

func TestSavePublishingIntentRejectsOversizeCanonicalDocumentBeforeWrite(t *testing.T) {
	intentPath := usePublishingIntentTestHome(t)
	intent := publishingIntentWithTransactions(1)
	intent.TransactionIDs[0] = strings.Repeat("x", 512*1024)

	err := savePublishingIntent(intent)
	if err == nil || err.Error() != "publishing intent document is invalid" {
		t.Fatalf("oversize save error = %v, want constant invalid-document error", err)
	}
	if _, statErr := os.Stat(intentPath); !os.IsNotExist(statErr) {
		t.Fatalf("oversize save created a publishing intent: %v", statErr)
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
	const unknownFieldCanary = "ISSUE23_UNKNOWN_FIELD_NAME_CANARY"
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
			data: bytes.Replace(versionOne, []byte(`"state": "ready"`), []byte(`"`+unknownFieldCanary+`": true, "state": "ready"`), 1),
		},
		{
			name: "version one transaction",
			data: bytes.Replace(versionOne, []byte(`"operation": "saved_key_removed"`), []byte(`"`+unknownFieldCanary+`": true, "operation": "saved_key_removed"`), 1),
		},
		{
			name: "version two top level",
			data: bytes.Replace(versionTwo, []byte(`"state": "ready"`), []byte(`"`+unknownFieldCanary+`": true, "state": "ready"`), 1),
		},
		{
			name: "version two transaction",
			data: bytes.Replace(versionTwo, []byte(`"operation": "saved_key_removed"`), []byte(`"`+unknownFieldCanary+`": true, "operation": "saved_key_removed"`), 1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := config.WritePrivateFile(intentPath, test.data); err != nil {
				t.Fatalf("write strict-decode publishing intent: %v", err)
			}
			_, err := loadPublishingIntent()
			if err == nil || err.Error() != "publishing intent document is invalid" {
				t.Fatalf("unknown-field error = %v, want constant invalid-document error", err)
			}
			if strings.Contains(err.Error(), unknownFieldCanary) {
				t.Fatal("unknown-field error exposed the untrusted member name")
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
	if err == nil || err.Error() != "publishing intent version is unsupported" {
		t.Fatalf("unknown-version error = %v, want constant unsupported-version error", err)
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

func jsonArrayWithNulls(values int) []byte {
	var document strings.Builder
	document.Grow(2 + values*5)
	document.WriteByte('[')
	for index := 0; index < values; index++ {
		if index > 0 {
			document.WriteByte(',')
		}
		document.WriteString("null")
	}
	document.WriteByte(']')
	return []byte(document.String())
}

func jsonObjectWithMembers(members int) []byte {
	var document strings.Builder
	document.Grow(2 + members*16)
	document.WriteByte('{')
	for index := 0; index < members; index++ {
		if index > 0 {
			document.WriteByte(',')
		}
		document.WriteString(`"member_`)
		document.WriteString(strconv.Itoa(index))
		document.WriteString(`":null`)
	}
	document.WriteByte('}')
	return []byte(document.String())
}

func publishingIntentWithTransactions(count int) publishingIntent {
	intent := publishingIntent{
		Version:        publishingIntentVersion,
		State:          intentReady,
		Scope:          "all",
		TargetIdentity: strings.Repeat("a", 64),
	}
	for index := 0; index < count; index++ {
		intent.TransactionIDs = append(intent.TransactionIDs, fmt.Sprintf("tx_%032x", index))
		intent.Transactions = append(intent.Transactions, publishingIntentTransaction{
			Operation: "saved_key_removed",
			CreatedAt: "2026-07-29T00:00:23.123456789Z",
		})
	}
	return intent
}

type typedDecodeCanary struct {
	called bool
}

func (canary *typedDecodeCanary) UnmarshalJSON([]byte) error {
	canary.called = true
	return nil
}
