package machinecontract

import (
	"bytes"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKnownValueStreamMasksValueAtEverySplit(t *testing.T) {
	t.Parallel()

	const (
		secret = "SPLIT_SECRET_CANARY"
		input  = "before " + secret + " middle " + secret + "\nafter"
		want   = "before *** middle ***\nafter"
	)
	for first := 0; first <= len(input); first++ {
		for second := first; second <= len(input); second++ {
			var output bytes.Buffer
			stream := NewKnownValueStream(&output, secret)
			for _, fragment := range []string{input[:first], input[first:second], input[second:]} {
				if _, err := stream.Write([]byte(fragment)); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(output.String(), secret) {
					t.Fatalf("split %d/%d leaked before flush: %q", first, second, output.String())
				}
			}
			if err := stream.Flush(); err != nil {
				t.Fatal(err)
			}
			if got := output.String(); got != want {
				t.Fatalf("split %d/%d = %q, want %q", first, second, got, want)
			}
		}
	}
}

func TestKnownValueStreamForwardsSafeBytesWithoutWaiting(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	stream := NewKnownValueStream(&output, "abc")
	write := func(value string) {
		t.Helper()
		if n, err := stream.Write([]byte(value)); err != nil || n != len(value) {
			t.Fatalf("write %q = (%d, %v)", value, n, err)
		}
	}

	write("line one\n")
	if got := output.String(); got != "line one\n" {
		t.Fatalf("complete safe line was delayed: %q", got)
	}
	write("x a")
	if got := output.String(); got != "line one\nx " {
		t.Fatalf("only a possible value prefix may be withheld: %q", got)
	}
	write("b")
	if got := output.String(); got != "line one\nx " {
		t.Fatalf("growing value prefix was released: %q", got)
	}
	write("d")
	if got := output.String(); got != "line one\nx abd" {
		t.Fatalf("mismatched prefix was not released: %q", got)
	}
	write("ab")
	if err := stream.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "line one\nx abdab" {
		t.Fatalf("flush changed an incomplete prefix: %q", got)
	}
}

func TestKnownValueStreamPreservesArbitraryBytes(t *testing.T) {
	t.Parallel()

	payload := make([]byte, 1<<20)
	random := rand.New(rand.NewSource(71)) //nolint:gosec // deterministic test payload
	_, _ = random.Read(payload)
	payload = bytes.ReplaceAll(payload, []byte("Q9"), []byte("q9"))

	for _, values := range [][]string{nil, {"Q9Z_NOT_PRESENT"}} {
		var output bytes.Buffer
		stream := NewKnownValueStream(&output, values...)
		for offset := 0; offset < len(payload); offset += 32 * 1024 {
			end := min(offset+32*1024, len(payload))
			if _, err := stream.Write(payload[offset:end]); err != nil {
				t.Fatal(err)
			}
		}
		if err := stream.Flush(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(output.Bytes(), payload) {
			t.Fatalf("values %q changed %d-byte payload", values, len(payload))
		}
	}
}

func TestKnownValueStreamPrefersLongestOverlappingValue(t *testing.T) {
	t.Parallel()

	for _, fragments := range [][]string{
		{"x ab", "cd y ab"},
		{"x a", "b", "c", "d y a", "b"},
		{"x abcd y ab"},
	} {
		var output bytes.Buffer
		stream := NewKnownValueStream(&output, "ab", "abcd")
		for _, fragment := range fragments {
			if _, err := stream.Write([]byte(fragment)); err != nil {
				t.Fatal(err)
			}
		}
		if err := stream.Flush(); err != nil {
			t.Fatal(err)
		}
		if got := output.String(); got != "x *** y ***" {
			t.Fatalf("fragments %q = %q, want %q", fragments, got, "x *** y ***")
		}
	}
}

func TestKnownValueStreamMasksMultilineValue(t *testing.T) {
	t.Parallel()

	const secret = "-----BEGIN KEY-----\nMULTILINE_CANARY\n-----END KEY-----"
	var output bytes.Buffer
	stream := NewKnownValueStream(&output, secret)
	for _, fragment := range []string{"k=-----BEGIN KEY-----\n", "MULTILINE_CANARY\n-----END", " KEY-----\ndone\n"} {
		if _, err := stream.Write([]byte(fragment)); err != nil {
			t.Fatal(err)
		}
	}
	if err := stream.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "k=***\ndone\n" {
		t.Fatalf("multiline value = %q", got)
	}
}

func TestKnownValueStreamReportsOutputFailure(t *testing.T) {
	t.Parallel()

	stream := NewKnownValueStream(errorWriter{}, "abc")
	if _, err := stream.Write([]byte("safe\n")); err == nil {
		t.Fatal("output failure was not reported")
	}
	if _, err := stream.Write([]byte("more\n")); err == nil {
		t.Fatal("later write after output failure was accepted")
	}
}

func TestStreamingRedactingWriterReleasesLinesAndCarriageReturns(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	writer := NewStreamingRedactingWriter(&output)
	if _, err := writer.Write([]byte("progress 10%\rprogress 20%\r")); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "progress 10%\rprogress 20%\r" {
		t.Fatalf("carriage-return progress was withheld: %q", got)
	}
	for _, fragment := range []string{"tok", "en=STREAM_TOKEN_", "CANARY\nnext"} {
		if _, err := writer.Write([]byte(fragment)); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(output.String(), "STREAM_TOKEN_CANARY") {
		t.Fatalf("fragmented credential leaked: %q", output.String())
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "progress 10%\rprogress 20%\rtoken=<redacted>\nnext" {
		t.Fatalf("streamed diagnostics = %q", got)
	}
}

func TestStreamingRedactingWriterBoundsUnterminatedLines(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	writer := NewStreamingRedactingWriter(&output)
	chunk := bytes.Repeat([]byte("x"), 32*1024)
	for range 8 {
		if _, err := writer.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if output.Len() == 0 {
		t.Fatal("unterminated diagnostic line was buffered without bound")
	}
	if pending := writer.pending.Len(); pending > StreamingLineLimit {
		t.Fatalf("pending diagnostic bytes = %d, want <= %d", pending, StreamingLineLimit)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 8*len(chunk) {
		t.Fatalf("bounded diagnostic bytes = %d, want %d", output.Len(), 8*len(chunk))
	}
}

func TestDiagnosticSpoolOverflowDrainsWithoutAcceptingOutput(t *testing.T) {
	tempDir := t.TempDir()
	const secret = "OVERFLOW_DRAIN_CANARY"
	var output bytes.Buffer
	spool, err := newDiagnosticSpoolWithLimit(&output, tempDir, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Write([]byte("safe")); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if n, err := spool.Write([]byte(secret)); err != nil || n != len(secret) {
			t.Fatalf("over-bound write = (%d, %v), want drained (%d, nil)", n, err, len(secret))
		}
	}
	if entries, err := os.ReadDir(tempDir); err != nil || len(entries) != 0 {
		t.Fatalf("overflow cleanup entries=%v err=%v", entries, err)
	}
	if _, err := spool.Contains("safe"); err == nil {
		t.Fatal("overflowed spool inspection unexpectedly succeeded")
	}
	if err := spool.Replay(true); err == nil || !errors.Is(err, ErrDiagnosticOutputTooLarge) {
		t.Fatalf("overflow replay error = %v, want ErrDiagnosticOutputTooLarge", err)
	}
	if output.Len() != 0 {
		t.Fatalf("overflow replayed partial diagnostics: %q", output.String())
	}
	if err := spool.Close(); err != nil {
		t.Fatalf("close after overflow: %v", err)
	}
}

func TestSweepStaleDiagnosticSpoolsRemovesOnlyOldSpools(t *testing.T) {
	directory := t.TempDir()
	now := time.Now()
	files := map[string]time.Time{
		".ssm-diagnostic-old":    now.Add(-48 * time.Hour),
		".ssm-diagnostic-recent": now.Add(-time.Hour),
		"unrelated-old":          now.Add(-48 * time.Hour),
	}
	for name, modified := range files {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("raw"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(directory, ".ssm-diagnostic-dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-48 * time.Hour)
	if err := os.Chtimes(filepath.Join(directory, ".ssm-diagnostic-dir"), old, old); err != nil {
		t.Fatal(err)
	}

	sweepStaleDiagnosticSpools(directory, 24*time.Hour, now)

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if strings.Join(names, ",") != ".ssm-diagnostic-dir,.ssm-diagnostic-recent,unrelated-old" {
		t.Fatalf("remaining entries = %q", names)
	}
}
