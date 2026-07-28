package machinecontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"

	"ssm/internal/privatepath"
)

// DiagnosticSpoolByteLimit is the maximum number of diagnostic bytes buffered
// per stdout or stderr stream while an operation's outcome is unknown. The
// 8 MiB bound limits temporary-file use and failure-redaction memory while
// retaining enough diagnostic context for ordinary SSH commands and transfers.
const DiagnosticSpoolByteLimit int64 = 8 << 20

var (
	redactAssignmentPrefix = regexp.MustCompile(`(?i)(?:(?:\\+)?["'])?\b(?:password|passwd|pass|passphrase|master_pass|masterpass|credential|token|secret|config|private_key|request_body|decrypted_inventory)\b(?:(?:\\+)?["'])?\s*[:=]\s*`)
	redactBearerPattern    = regexp.MustCompile(`(?i)(["']?\bauthorization\b["']?\s*:\s*["']?bearer\s+)(?:"[^"]*"|'[^']*'|[^\s,}]+)`)
	redactStructuredPrefix = regexp.MustCompile(`(?i)(?:(?:\\+)?["'])?\b(?:config|request_body|decrypted_inventory)\b(?:(?:\\+)?["'])?\s*[:=]\s*`)
	privateKeyBlockPattern = regexp.MustCompile(`(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`)
)

// Format identifies one existing public rendering mode.
type Format uint8

const (
	JSONDocument Format = iota
	NDJSON
	Human
)

// Streams names the only two public process output destinations. Render owns
// which destination each format uses.
type Streams struct {
	Stdout io.Writer
	Stderr io.Writer
}

// Render selects and executes the exact public renderer. Canonical Failure
// values are always sanitized; command-specific success values retain their
// established payload bytes.
func Render(format Format, streams Streams, value any) error {
	return render(format, streams, value, isCanonicalFailure(value))
}

// RenderFailure sanitizes a canonical or command-specific failure document
// immediately before selecting and executing its public renderer.
func RenderFailure(format Format, streams Streams, value any) error {
	return render(format, streams, value, true)
}

func render(format Format, streams Streams, value any, redact bool) error {
	if streams.Stdout == nil {
		streams.Stdout = io.Discard
	}
	if streams.Stderr == nil {
		streams.Stderr = io.Discard
	}
	safe := value
	if redact {
		safe = redactValue(value)
	}
	switch format {
	case JSONDocument:
		encoder := json.NewEncoder(streams.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(safe)
	case NDJSON:
		return json.NewEncoder(streams.Stdout).Encode(safe)
	case Human:
		failure, ok := safe.(Failure)
		if !ok {
			if pointer, pointerOK := safe.(*Failure); pointerOK && pointer != nil {
				failure, ok = *pointer, true
			}
		}
		if !ok {
			return fmt.Errorf("machine contract human renderer requires Failure, got %T", safe)
		}
		return renderHuman(streams, failure)
	default:
		return fmt.Errorf("unknown machine contract format %d", format)
	}
}

func isCanonicalFailure(value any) bool {
	switch value.(type) {
	case Failure, *Failure:
		return true
	default:
		return false
	}
}

func WriteJSON(value any) error {
	return Render(JSONDocument, Streams{Stdout: os.Stdout, Stderr: os.Stderr}, value)
}

func WriteFailureJSON(value any) error {
	return RenderFailure(JSONDocument, Streams{Stdout: os.Stdout, Stderr: os.Stderr}, value)
}

func WriteNDJSON(output io.Writer, value any) error {
	return Render(NDJSON, Streams{Stdout: output, Stderr: os.Stderr}, value)
}

func WriteFailureNDJSON(output io.Writer, value any) error {
	return RenderFailure(NDJSON, Streams{Stdout: output, Stderr: os.Stderr}, value)
}

func WriteHuman(failure Failure) error {
	return Render(Human, Streams{Stdout: os.Stdout, Stderr: os.Stderr}, failure)
}

// WriteClassified is the production failure boundary. It owns classification,
// human-vs-machine placement, rendering, redaction, and process-exit policy.
func WriteClassified(asJSON bool, kind Kind, details Details) int {
	failure := Classify(kind, details)
	return WriteFailure(asJSON, failure, failure)
}

// WriteFailure renders a previously classified failure. machineValue may be a
// command-specific typed failure document; human mode always uses the canonical
// Failure renderer.
func WriteFailure(asJSON bool, failure Failure, machineValue any) int {
	if asJSON && failure.renderer != rendererHumanOnly {
		_ = WriteFailureJSON(machineValue)
	} else {
		_ = WriteHuman(failure)
	}
	return ProcessExit(failure)
}

// WriteMetadataError preserves the established metadata-only typed failure
// document while keeping error recovery, fallback classification, rendering,
// and process-exit policy in this package.
func WriteMetadataError(asJSON bool, err error, fallback Kind) int {
	failure, ok := FailureFromError(err)
	if !ok {
		failure = Classify(fallback, Details{Cause: err})
	}
	return WriteFailure(asJSON, failure, failure.MetadataDocument())
}

func renderHuman(streams Streams, failure Failure) error {
	output := streams.Stderr
	if failure.humanProjection != nil {
		failure = redactValue(*failure.humanProjection).(Failure)
	}
	switch failure.style {
	case humanPlain:
		_, err := fmt.Fprintf(output, "Error: %s\n", failure.Message)
		return err
	case humanAliasNotFound:
		if _, err := fmt.Fprintf(output, "ssm: error=%s alias=%s\n", failure.Error, shellMetaSafe(failure.Alias)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(output, "Connection %q not found.\n", failure.Alias); err != nil {
			return err
		}
		if len(failure.Candidates) > 0 {
			if _, err := fmt.Fprintf(output, "ssm: did_you_mean=%s\n", strings.Join(failure.Candidates, ",")); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(output, "Did you mean: %s\n", strings.Join(failure.Candidates, ", ")); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintln(output, "ssm: hint=use sshctl host list --json; or ssm redirect set <old> <new> after migration")
		return err
	case humanScript:
		if _, err := fmt.Fprintf(output, "ssm: error=%s script=%s exit=%d\n", failure.Error, failure.Script, failure.Exit); err != nil {
			return err
		}
		if failure.Hint != "" {
			_, err := fmt.Fprintf(output, "ssm: hint=%s\n", failure.Hint)
			return err
		}
		return nil
	case humanHostVerification:
		if _, err := fmt.Fprintf(output, "ssm: error=%s alias=%s\n", failure.Error, shellMetaSafe(failure.Alias)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(output, "Error: %s\n", failure.Message); err != nil {
			return err
		}
		if failure.VerificationError != "" {
			_, err := fmt.Fprintf(output, "ssm: verification_error=%s\n", failure.VerificationError)
			return err
		}
		return nil
	case humanHostPush:
		if _, err := fmt.Fprintf(output, "ssm: error=%s alias=%s\n", failure.Error, shellMetaSafe(failure.Alias)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(output, "Error: %s\n", failure.Message); err != nil {
			return err
		}
		_, err := fmt.Fprintf(output, "ssm: hint=%s\n", failure.HumanHint)
		return err
	case humanMapNoTargets:
		_, err := fmt.Fprintln(output, "sshctl map: no targets matched")
		return err
	case humanRunArguments:
		if failure.Alias != "" {
			if _, err := fmt.Fprintf(output, "%s: error=%s alias=%s\n", failure.Tool, failure.Error, failure.Alias); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(output, "%s: error=%s\n", failure.Tool, failure.Error); err != nil {
			return err
		}
		_, err := fmt.Fprintf(output, "%s: %s\n", failure.Tool, failure.Hint)
		return err
	case humanHostKeyOperation:
		if _, err := fmt.Fprintf(output, "ssm: error=%s\n", failure.Error); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(output, "Error: %s\n", failure.Message); err != nil {
			return err
		}
		if failure.Hint != "" {
			_, err := fmt.Fprintf(output, "ssm: hint=%s\n", failure.Hint)
			return err
		}
		return nil
	case humanPanic:
		_, err := fmt.Fprintf(
			output,
			"\n\x1b[1;31mssm crashed!\x1b[0m\n\nVersion: %s\nOS:      %s\nError:   %s\n\nStack trace:\n%s\n\nPlease include the info above when reporting this issue.\n",
			failure.Version,
			failure.Platform,
			failure.Message,
			failure.Stack,
		)
		return err
	case humanLegacyUsage:
		switch failure.Script {
		case "remove":
			_, err := fmt.Fprintln(streams.Stdout, "Usage: ssm remove <name>")
			return err
		case "keys_remove":
			_, err := fmt.Fprintln(streams.Stdout, "Usage: ssm keys remove <name>")
			return err
		case "exec":
			_, err := fmt.Fprintln(streams.Stdout, "Usage: ssm exec <name> <command...>")
			return err
		case "plan":
			_, err := fmt.Fprintln(streams.Stdout, "Usage: ssm plan <name> <command...>")
			return err
		case "map":
			_, err := fmt.Fprintln(streams.Stdout, "Usage: ssm map <targets> [options] <command...>")
			return err
		case "check":
			_, err := fmt.Fprintln(streams.Stdout, "Usage: ssm check <name> [--json]")
			return err
		case "get":
			_, err := fmt.Fprintln(streams.Stdout, "Usage: ssm get <name> <remote> <local>")
			return err
		}
	case humanLegacyNotFound:
		switch failure.Script {
		case "connection":
			_, err := fmt.Fprintf(streams.Stdout, "Connection %q not found.\n", failure.Alias)
			return err
		case "key":
			_, err := fmt.Fprintf(streams.Stdout, "Key %q not found.\n", failure.Alias)
			return err
		}
	case humanLegacyUnknownCommand:
		switch failure.Script {
		case "keys":
			_, err := fmt.Fprintf(streams.Stdout, "Unknown keys command: %s\n", failure.Alias)
			return err
		case "ssm":
			if _, err := fmt.Fprintf(streams.Stdout, "Unknown command: %s\n", failure.Alias); err != nil {
				return err
			}
			_, err := fmt.Fprintln(streams.Stdout, "Usage: ssm [host|remove|list|keys|exec|put|get|import-json|server|update|login|register|push|pull|pull-if-changed|remote-hash|logout]")
			return err
		}
	case humanLegacyMessage:
		switch failure.Script {
		case "logout":
			_, err := fmt.Fprintln(output, "Not logged in.")
			return err
		case "map_empty":
			_, err := fmt.Fprintln(output, "sshctl map: nothing to run")
			return err
		}
	case humanRaw:
		_, err := fmt.Fprint(output, failure.Message)
		return err
	case humanDoctorOption:
		_, err := fmt.Fprintf(output, "sshctl doctor: unknown option %s\n", failure.Alias)
		return err
	case humanImportArguments:
		if err := renderStandardHuman(output, failure); err != nil {
			return err
		}
		_, err := fmt.Fprintln(output, "Usage: ssm import-json <path> (--merge | --replace --yes) [--manifest <path>] [--expect-count <n>] [--json]")
		return err
	default:
	}
	return renderStandardHuman(output, failure)
}

func renderStandardHuman(output io.Writer, failure Failure) error {
	if _, err := fmt.Fprintf(output, "ssm: error=%s", failure.Error); err != nil {
		return err
	}
	if failure.Stage != "" {
		if _, err := fmt.Fprintf(output, " stage=%s", failure.Stage); err != nil {
			return err
		}
	}
	alias := failure.Alias
	if failure.humanAlias != "" {
		alias = failure.humanAlias
	}
	if alias != "" {
		if _, err := fmt.Fprintf(output, " alias=%s", shellMetaSafe(alias)); err != nil {
			return err
		}
	}
	if failure.Address != "" {
		if _, err := fmt.Fprintf(output, " address=%s", shellMetaSafe(failure.Address)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(output); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(output, "Error: %s\n", failure.Message); err != nil {
		return err
	}
	if failure.Hint != "" {
		if _, err := fmt.Fprintf(output, "ssm: hint=%s\n", failure.Hint); err != nil {
			return err
		}
	}
	return nil
}

func shellMetaSafe(value string) string {
	return strings.ReplaceAll(strings.TrimSpace(value), " ", "_")
}

// RedactString strips credential-shaped values and private-key blocks.
func RedactString(value string) string {
	output := redactStructuredValues(value)
	output = privateKeyBlockPattern.ReplaceAllString(output, "<redacted-private-key>")
	output = replaceSensitiveValue(output, redactBearerPattern, "***")
	output = redactAssignmentValues(output)
	output = strings.ReplaceAll(output, "-----BEGIN OPENSSH PRIVATE KEY-----", "<redacted-private-key>")
	return output
}

func redactAssignmentValues(value string) string {
	matches := redactAssignmentPrefix.FindAllStringIndex(value, -1)
	if len(matches) == 0 {
		return value
	}
	var output strings.Builder
	cursor := 0
	for _, match := range matches {
		if match[0] < cursor || match[1] >= len(value) {
			continue
		}
		end := assignmentValueEnd(value, match[1])
		if end == match[1] {
			continue
		}
		raw := strings.Trim(strings.TrimSpace(value[match[1]:end]), `"'`)
		if raw == "***" || strings.HasPrefix(raw, "<redacted") {
			continue
		}
		output.WriteString(value[cursor:match[1]])
		output.WriteString("<redacted>")
		cursor = end
	}
	if cursor == 0 {
		return value
	}
	output.WriteString(value[cursor:])
	return output.String()
}

func assignmentValueEnd(value string, start int) int {
	if start >= len(value) {
		return start
	}
	quoteStart := start
	for quoteStart < len(value) && value[quoteStart] == '\\' {
		quoteStart++
	}
	if quoteStart < len(value) && (value[quoteStart] == '"' || value[quoteStart] == '\'') {
		quote := value[quoteStart]
		escapeLevel := quoteStart - start
		if escapeLevel > 0 {
			for i := quoteStart + 1; i < len(value); i++ {
				if value[i] != quote {
					continue
				}
				slashes := 0
				for cursor := i - 1; cursor >= quoteStart+1 && value[cursor] == '\\'; cursor-- {
					slashes++
				}
				if slashes == escapeLevel {
					return i + 1
				}
			}
			return len(value)
		}
		escaped := false
		for i := quoteStart + 1; i < len(value); i++ {
			switch {
			case escaped:
				escaped = false
			case value[i] == '\\':
				escaped = true
			case value[i] == quote:
				return i + 1
			}
		}
		return len(value)
	}
	for i := start; i < len(value); i++ {
		switch value[i] {
		case ' ', '\t', '\r', '\n', ',', '}':
			return i
		}
	}
	return len(value)
}

func redactKnownValues(value string, sensitiveValues []string) string {
	output := RedactString(value)
	for _, sensitive := range sensitiveValues {
		output = strings.ReplaceAll(output, sensitive, "***")
	}
	return output
}

func prepareSensitiveValues(values []string) []string {
	output := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		output = append(output, value)
	}
	sort.SliceStable(output, func(i, j int) bool {
		return len(output[i]) > len(output[j])
	})
	return output
}

func replaceSensitiveValue(value string, pattern *regexp.Regexp, replacement string) string {
	return pattern.ReplaceAllStringFunc(value, func(match string) string {
		indices := pattern.FindStringSubmatchIndex(match)
		if len(indices) < 4 {
			return replacement
		}
		raw := strings.Trim(strings.TrimSpace(match[indices[3]:]), `"'`)
		if raw == "***" || strings.HasPrefix(raw, "<redacted") {
			return match
		}
		return match[:indices[3]] + replacement
	})
}

func redactStructuredValues(value string) string {
	matches := redactStructuredPrefix.FindAllStringIndex(value, -1)
	if len(matches) == 0 {
		return value
	}
	var output strings.Builder
	cursor := 0
	for _, match := range matches {
		if match[0] < cursor || match[1] >= len(value) || (value[match[1]] != '{' && value[match[1]] != '[') {
			continue
		}
		end, ok := structuredValueEnd(value, match[1])
		if !ok {
			continue
		}
		output.WriteString(value[cursor:match[1]])
		output.WriteString("<redacted>")
		cursor = end
	}
	if cursor == 0 {
		return value
	}
	output.WriteString(value[cursor:])
	return output.String()
}

func structuredValueEnd(value string, start int) (int, bool) {
	stack := []byte{value[start]}
	inString := byte(0)
	escaped := false
	for i := start + 1; i < len(value); i++ {
		current := value[i]
		if inString != 0 {
			switch {
			case escaped:
				escaped = false
			case current == '\\':
				escaped = true
			case current == inString:
				inString = 0
			}
			continue
		}
		switch current {
		case '"', '\'':
			inString = current
		case '{', '[':
			stack = append(stack, current)
		case '}', ']':
			open := stack[len(stack)-1]
			if (open == '{' && current != '}') || (open == '[' && current != ']') {
				return 0, false
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return i + 1, true
			}
		}
	}
	return 0, false
}

// RedactError returns a safe rendering of an error.
func RedactError(err error) string {
	if err == nil {
		return ""
	}
	return RedactString(err.Error())
}

// Redact returns a same-typed failure copy with every exported string
// recursively sanitized. Additional values remove opaque request material
// known to the caller. Typed failure writers use this immediately before human
// formatting so they retain their established schemas.
func Redact[T any](value T, sensitiveValues ...string) T {
	return redactValueKnown(value, prepareSensitiveValues(sensitiveValues)).(T)
}

// RedactingWriter preserves safe line bytes while holding partial writes until
// a line boundary, so credential assignments split across writes cannot bypass
// redaction. Private-key blocks are suppressed across line boundaries.
type RedactingWriter struct {
	mu              sync.Mutex
	output          io.Writer
	pending         strings.Builder
	structured      strings.Builder
	inPrivateBlock  bool
	sensitiveValues []string
}

// DiagnosticSpool holds transport diagnostics until the caller knows whether
// the operation succeeded. Replay preserves success bytes and sanitizes
// failed or cancelled diagnostics.
type DiagnosticSpool struct {
	mu              sync.Mutex
	output          io.Writer
	file            *os.File
	path            string
	sensitiveValues []string
	replayed        bool
	size            int64
	limit           int64
	terminalErr     error
	remove          func(string) error
}

func NewDiagnosticSpool(output io.Writer, sensitiveValues ...string) (*DiagnosticSpool, error) {
	return newDiagnosticSpool(output, "", sensitiveValues...)
}

func newDiagnosticSpool(output io.Writer, directory string, sensitiveValues ...string) (*DiagnosticSpool, error) {
	return newDiagnosticSpoolWithLimit(output, directory, DiagnosticSpoolByteLimit, sensitiveValues...)
}

func newDiagnosticSpoolWithLimit(output io.Writer, directory string, limit int64, sensitiveValues ...string) (*DiagnosticSpool, error) {
	if output == nil {
		output = io.Discard
	}
	if limit < 0 {
		return nil, fmt.Errorf("diagnostic spool byte limit must be non-negative")
	}
	file, err := os.CreateTemp(directory, ".ssm-diagnostic-*")
	if err != nil {
		return nil, fmt.Errorf("create private diagnostic spool: %w", err)
	}
	path := file.Name()
	if err := privatepath.RestrictFile(path); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("secure private diagnostic spool: %w", err)
	}
	return &DiagnosticSpool{
		output:          output,
		file:            file,
		path:            filepath.Clean(path),
		sensitiveValues: prepareSensitiveValues(sensitiveValues),
		limit:           limit,
		remove:          os.Remove,
	}, nil
}

func (s *DiagnosticSpool) Write(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.replayed {
		if s.terminalErr != nil {
			return 0, s.terminalErr
		}
		return 0, fmt.Errorf("machine contract diagnostic spool already replayed")
	}
	if int64(len(data)) > s.limit-s.size {
		file := s.file
		s.file = nil
		s.replayed = true
		s.terminalErr = fmt.Errorf("diagnostic output exceeds %d-byte limit", s.limit)
		cleanupErr := file.Close()
		if removeErr := s.remove(s.path); removeErr != nil {
			cleanupErr = errors.Join(cleanupErr, removeErr)
		} else {
			s.path = ""
		}
		return 0, errors.Join(s.terminalErr, cleanupErr)
	}
	n, err := s.file.Write(data)
	s.size += int64(n)
	return n, err
}

func (s *DiagnosticSpool) Replay(success bool) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.replayed {
		return s.terminalErr
	}
	s.replayed = true
	file := s.file
	s.file = nil

	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
		if removeErr := s.remove(s.path); removeErr != nil {
			resultErr = errors.Join(resultErr, removeErr)
		} else {
			s.path = ""
		}
	}()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind diagnostic spool: %w", err)
	}
	if success {
		_, err := io.Copy(s.output, file)
		return err
	}
	writer := NewRedactingWriter(s.output, s.sensitiveValues...)
	if _, err := io.Copy(writer, file); err != nil {
		return err
	}
	return writer.Flush()
}

// Contains reports whether a bounded diagnostic spool contains marker. It
// scans the private file with fixed-size memory and does not replay any bytes.
func (s *DiagnosticSpool) Contains(marker string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminalErr != nil {
		return false, s.terminalErr
	}
	if s.replayed || s.file == nil {
		return false, fmt.Errorf("machine contract diagnostic spool already replayed")
	}
	if marker == "" {
		return true, nil
	}
	const chunkSize = 32 * 1024
	buffer := make([]byte, chunkSize+len(marker)-1)
	var offset int64
	carried := 0
	for {
		n, err := s.file.ReadAt(buffer[carried:carried+chunkSize], offset)
		if bytes.Contains(buffer[:carried+n], []byte(marker)) {
			return true, nil
		}
		offset += int64(n)
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("inspect diagnostic spool: %w", err)
		}
		carried = min(len(marker)-1, carried+n)
		copy(buffer[:carried], buffer[carried+n-carried:carried+n])
	}
}

// Close discards diagnostics and removes their private temporary file. If a
// prior removal failed, Close retries it while retaining the private path.
func (s *DiagnosticSpool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replayed = true
	file := s.file
	s.file = nil
	var result error
	if file != nil {
		result = file.Close()
	}
	if s.path != "" {
		if removeErr := s.remove(s.path); removeErr != nil {
			result = errors.Join(result, removeErr)
		} else {
			s.path = ""
		}
	}
	return result
}

func NewRedactingWriter(output io.Writer, sensitiveValues ...string) *RedactingWriter {
	if output == nil {
		output = io.Discard
	}
	return &RedactingWriter{output: output, sensitiveValues: prepareSensitiveValues(sensitiveValues)}
}

func (w *RedactingWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.pending.Write(data)
	for {
		value := w.pending.String()
		lineEnd := strings.IndexByte(value, '\n')
		if lineEnd < 0 {
			break
		}
		line := value[:lineEnd+1]
		w.pending.Reset()
		w.pending.WriteString(value[lineEnd+1:])
		if err := w.writeLine(line); err != nil {
			return len(data), err
		}
	}
	return len(data), nil
}

func (w *RedactingWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.pending.Len() == 0 {
		return w.flushStructured()
	}
	line := w.pending.String()
	w.pending.Reset()
	if err := w.writeLine(line); err != nil {
		return err
	}
	return w.flushStructured()
}

func (w *RedactingWriter) writeLine(line string) error {
	if w.structured.Len() > 0 {
		w.structured.WriteString(line)
		value := w.structured.String()
		safe := redactStructuredValues(value)
		if safe == value {
			return nil
		}
		if hasIncompleteSensitiveStructure(safe) {
			w.structured.Reset()
			w.structured.WriteString(safe)
			return nil
		}
		w.structured.Reset()
		_, err := io.WriteString(w.output, redactKnownValues(safe, w.sensitiveValues))
		return err
	}
	if hasIncompleteSensitiveStructure(line) {
		w.structured.WriteString(line)
		return nil
	}

	upper := strings.ToUpper(line)
	if w.inPrivateBlock {
		if end := privateKeyEnd(upper); end >= 0 {
			w.inPrivateBlock = false
			_, err := io.WriteString(w.output, redactKnownValues(line[end:], w.sensitiveValues))
			return err
		}
		return nil
	}
	begin := strings.Index(upper, "-----BEGIN ")
	if begin < 0 || !strings.Contains(upper[begin:], "PRIVATE KEY-----") {
		_, err := io.WriteString(w.output, redactKnownValues(line, w.sensitiveValues))
		return err
	}
	if end := privateKeyEnd(upper[begin:]); end >= 0 {
		_, err := io.WriteString(w.output, redactKnownValues(line, w.sensitiveValues))
		return err
	}
	if _, err := io.WriteString(w.output, redactKnownValues(line[:begin], w.sensitiveValues)+"<redacted-private-key>"); err != nil {
		return err
	}
	w.inPrivateBlock = true
	return nil
}

func (w *RedactingWriter) flushStructured() error {
	if w.structured.Len() == 0 {
		return nil
	}
	value := w.structured.String()
	w.structured.Reset()
	match := redactStructuredPrefix.FindStringIndex(value)
	if len(match) != 2 {
		return nil
	}
	_, err := io.WriteString(w.output, redactKnownValues(value[:match[1]], w.sensitiveValues)+"<redacted>")
	return err
}

func hasIncompleteSensitiveStructure(value string) bool {
	for _, match := range redactStructuredPrefix.FindAllStringIndex(value, -1) {
		if match[1] >= len(value) {
			return true
		}
		if value[match[1]] != '{' && value[match[1]] != '[' {
			continue
		}
		if _, complete := structuredValueEnd(value, match[1]); !complete {
			return true
		}
	}
	return false
}

func privateKeyEnd(upper string) int {
	start := strings.Index(upper, "-----END ")
	if start < 0 {
		return -1
	}
	suffix := upper[start:]
	markerEnd := strings.Index(suffix, "PRIVATE KEY-----")
	if markerEnd < 0 {
		return -1
	}
	return start + markerEnd + len("PRIVATE KEY-----")
}

func redactValue(value any) any {
	return redactValueKnown(value, nil)
}

func redactValueKnown(value any, sensitiveValues []string) any {
	if value == nil {
		return nil
	}
	return cloneRedacted(reflect.ValueOf(value), false, sensitiveValues).Interface()
}

func cloneRedacted(value reflect.Value, force bool, sensitiveValues []string) reflect.Value {
	if !value.IsValid() {
		return value
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		safe := cloneRedacted(value.Elem(), force, sensitiveValues)
		output := reflect.New(value.Type()).Elem()
		output.Set(safe)
		return output
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		output := reflect.New(value.Type().Elem())
		output.Elem().Set(cloneRedacted(value.Elem(), force, sensitiveValues))
		return output
	case reflect.String:
		if force {
			return reflect.ValueOf("<redacted>").Convert(value.Type())
		}
		return reflect.ValueOf(redactKnownValues(value.String(), sensitiveValues)).Convert(value.Type())
	case reflect.Struct:
		output := reflect.New(value.Type()).Elem()
		output.Set(value)
		for i := 0; i < value.NumField(); i++ {
			field := output.Field(i)
			structField := value.Type().Field(i)
			if field.CanSet() && structField.IsExported() {
				field.Set(cloneRedacted(value.Field(i), force || sensitiveIdentifier(structField.Name) || sensitiveIdentifier(structField.Tag.Get("json")), sensitiveValues))
			}
		}
		return output
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		if force && value.Type().Elem().Kind() == reflect.Uint8 {
			return redactedBytes(value.Type())
		}
		output := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		for i := 0; i < value.Len(); i++ {
			output.Index(i).Set(cloneRedacted(value.Index(i), force, sensitiveValues))
		}
		return output
	case reflect.Array:
		if force && value.Type().Elem().Kind() == reflect.Uint8 {
			output := reflect.New(value.Type()).Elem()
			for i := 0; i < value.Len(); i++ {
				output.Index(i).SetUint(0)
			}
			return output
		}
		output := reflect.New(value.Type()).Elem()
		for i := 0; i < value.Len(); i++ {
			output.Index(i).Set(cloneRedacted(value.Index(i), force, sensitiveValues))
		}
		return output
	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		output := reflect.MakeMapWithSize(value.Type(), value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			key := cloneRedacted(iterator.Key(), false, sensitiveValues)
			sensitiveValue := force
			if iterator.Key().Kind() == reflect.String {
				sensitiveValue = sensitiveValue || sensitiveIdentifier(iterator.Key().String())
			}
			output.SetMapIndex(key, cloneRedacted(iterator.Value(), sensitiveValue, sensitiveValues))
		}
		return output
	default:
		return value
	}
}

func redactedBytes(valueType reflect.Type) reflect.Value {
	marker := []byte("<redacted>")
	output := reflect.MakeSlice(valueType, len(marker), len(marker))
	for i, value := range marker {
		output.Index(i).SetUint(uint64(value))
	}
	return output
}

func sensitiveIdentifier(identifier string) bool {
	if comma := strings.IndexByte(identifier, ','); comma >= 0 {
		identifier = identifier[:comma]
	}
	identifier = strings.ToLower(identifier)
	identifier = strings.NewReplacer("_", "", "-", "").Replace(identifier)
	for _, fragment := range []string{
		"password",
		"passwd",
		"passphrase",
		"masterpass",
		"credential",
		"token",
		"privatekey",
		"apikey",
		"secret",
	} {
		if strings.Contains(identifier, fragment) {
			return true
		}
	}
	switch identifier {
	case "pass", "config", "requestbody", "decryptedinventory":
		return true
	default:
		return false
	}
}
