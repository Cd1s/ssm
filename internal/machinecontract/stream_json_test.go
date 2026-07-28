package machinecontract

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestJSONDocumentStreamOwnsSingleObjectFraming(t *testing.T) {
	var stdout bytes.Buffer
	stream, err := BeginJSONDocument(Streams{Stdout: &stdout}, map[string]any{"review": "ready"})
	if err != nil {
		t.Fatal(err)
	}
	if json.Valid(stdout.Bytes()) {
		t.Fatalf("preamble unexpectedly closed document: %q", stdout.Bytes())
	}
	if err := stream.Finish(map[string]any{"ok": true, "installed": true}); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("final document: %v; output=%q", err, stdout.Bytes())
	}
	if document["review"] != "ready" || document["ok"] != true || document["installed"] != true {
		t.Fatalf("document=%v", document)
	}
	if bytes.Count(stdout.Bytes(), []byte(`"ok"`)) != 1 || bytes.Count(stdout.Bytes(), []byte(`"installed"`)) != 1 {
		t.Fatalf("field cardinality output=%q", stdout.Bytes())
	}
	if err := stream.Finish(map[string]any{"ok": false}); err == nil {
		t.Fatal("second finish unexpectedly succeeded")
	}
}

func TestJSONDocumentStreamRequiresObjects(t *testing.T) {
	if _, err := BeginJSONDocument(Streams{Stdout: &bytes.Buffer{}}, []string{"not", "object"}); err == nil {
		t.Fatal("non-object preamble unexpectedly accepted")
	}
	stream, err := BeginJSONDocument(Streams{Stdout: &bytes.Buffer{}}, map[string]any{"review": true})
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Finish([]string{"not", "object"}); err == nil {
		t.Fatal("non-object outcome unexpectedly accepted")
	}
}
