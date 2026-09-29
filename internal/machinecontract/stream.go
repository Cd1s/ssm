package machinecontract

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// StreamingLineLimit bounds how many bytes of one unterminated diagnostic
// line a streaming redacting writer holds before releasing it.
const StreamingLineLimit = 64 * 1024

// staleDiagnosticSpoolAge is how old an abandoned diagnostic spool must be
// before a later process removes it.
const staleDiagnosticSpoolAge = 24 * time.Hour

const diagnosticSpoolPattern = ".ssm-diagnostic-*"

// ErrDiagnosticOutputTooLarge reports that a bounded diagnostic spool
// discarded output after reaching its byte limit.
var ErrDiagnosticOutputTooLarge = errors.New("diagnostic output exceeds the bounded spool limit")

// KnownValueStream forwards a byte stream while replacing every exact
// occurrence of a caller-supplied sensitive value with "***". All other bytes
// pass through unchanged and immediately; only a trailing fragment that could
// still begin a sensitive value is withheld until the next write or Flush.
type KnownValueStream struct {
	mu      sync.Mutex
	output  io.Writer
	values  [][]byte
	prefix  [][]int
	pending []byte
	scratch []byte
	err     error
}

func NewKnownValueStream(output io.Writer, sensitiveValues ...string) *KnownValueStream {
	if output == nil {
		output = io.Discard
	}
	prepared := prepareSensitiveValues(sensitiveValues)
	stream := &KnownValueStream{output: output}
	for _, value := range prepared {
		stream.values = append(stream.values, []byte(value))
		stream.prefix = append(stream.prefix, prefixFunction([]byte(value)))
	}
	return stream
}

func (s *KnownValueStream) Write(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	if len(s.values) == 0 {
		if _, err := s.output.Write(data); err != nil {
			s.err = err
			return 0, err
		}
		return len(data), nil
	}
	s.pending = append(s.pending, data...)
	if err := s.release(false); err != nil {
		return 0, err
	}
	return len(data), nil
}

// Flush releases any withheld fragment. It is called once the stream ends.
func (s *KnownValueStream) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	return s.release(true)
}

func (s *KnownValueStream) release(final bool) error {
	buffer := s.pending
	s.scratch = s.scratch[:0]
	position := 0
	for {
		index, length := s.nextMatch(buffer, position)
		if index < 0 {
			break
		}
		if !final && index >= len(buffer)-s.withheld(buffer[position:]) {
			break
		}
		s.scratch = append(s.scratch, buffer[position:index]...)
		s.scratch = append(s.scratch, "***"...)
		position = index + length
	}
	cut := len(buffer)
	if !final {
		cut -= s.withheld(buffer[position:])
	}
	s.scratch = append(s.scratch, buffer[position:cut]...)
	s.pending = append(s.pending[:0], buffer[cut:]...)
	if len(s.scratch) == 0 {
		return nil
	}
	if _, err := s.output.Write(s.scratch); err != nil {
		s.err = err
		return err
	}
	return nil
}

// nextMatch returns the earliest complete value occurrence at or after start,
// preferring the longest value when several begin at the same byte.
func (s *KnownValueStream) nextMatch(buffer []byte, start int) (int, int) {
	best, bestLength := -1, 0
	for _, value := range s.values {
		index := bytes.Index(buffer[start:], value)
		if index < 0 {
			continue
		}
		index += start
		if best < 0 || index < best || (index == best && len(value) > bestLength) {
			best, bestLength = index, len(value)
		}
	}
	return best, bestLength
}

// withheld returns the length of the longest suffix of buffer that is a proper
// prefix of any sensitive value.
func (s *KnownValueStream) withheld(buffer []byte) int {
	longest := 0
	for index, value := range s.values {
		window := buffer
		if limit := len(value) - 1; len(window) > limit {
			window = window[len(window)-limit:]
		}
		if matched := suffixPrefixLength(value, s.prefix[index], window); matched > longest {
			longest = matched
		}
	}
	return longest
}

// prefixFunction is the Knuth-Morris-Pratt failure table of value.
func prefixFunction(value []byte) []int {
	table := make([]int, len(value))
	for index, matched := 1, 0; index < len(value); index++ {
		for matched > 0 && value[index] != value[matched] {
			matched = table[matched-1]
		}
		if value[index] == value[matched] {
			matched++
		}
		table[index] = matched
	}
	return table
}

func suffixPrefixLength(value []byte, table []int, text []byte) int {
	matched := 0
	for _, current := range text {
		for matched > 0 && value[matched] != current {
			matched = table[matched-1]
		}
		if value[matched] == current {
			matched++
		}
		if matched == len(value) {
			matched = table[matched-1]
		}
	}
	return matched
}

// NewStreamingRedactingWriter returns a line-oriented redacting writer for
// live diagnostics. It releases each line at a newline or carriage return and
// never holds more than StreamingLineLimit bytes of an unterminated line.
func NewStreamingRedactingWriter(output io.Writer, sensitiveValues ...string) *RedactingWriter {
	writer := NewRedactingWriter(output, sensitiveValues...)
	writer.streaming = true
	return writer
}

var sweepDiagnosticSpoolsOnce sync.Once

// SweepStaleDiagnosticSpools removes diagnostic spools abandoned by earlier
// processes that were killed before cleanup. It runs at most once per process
// and ignores every error.
func SweepStaleDiagnosticSpools() {
	sweepDiagnosticSpoolsOnce.Do(func() {
		sweepStaleDiagnosticSpools(os.TempDir(), staleDiagnosticSpoolAge, time.Now())
	})
}

func sweepStaleDiagnosticSpools(directory string, maxAge time.Duration, now time.Time) {
	matches, err := filepath.Glob(filepath.Join(directory, diagnosticSpoolPattern))
	if err != nil {
		return
	}
	for _, path := range matches {
		if !strings.HasPrefix(filepath.Base(path), ".ssm-diagnostic-") {
			continue
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || now.Sub(info.ModTime()) < maxAge {
			continue
		}
		_ = os.Remove(path)
	}
}
