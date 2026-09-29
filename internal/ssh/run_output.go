package ssh

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"sync"

	"ssm/internal/machinecontract"
)

// RunOutputEnv selects how a non-captured (human-mode) run delivers remote
// output. The default streams it; "buffered" restores the v2.0.2 behavior of
// holding output until the outcome is known and sanitizing failed output.
const RunOutputEnv = "SSM_RUN_OUTPUT"

// humanRunOutput owns remote stdout and stderr for a non-captured run.
type humanRunOutput interface {
	Stdout() io.Writer
	Stderr() io.Writer
	// InterpreterMarkerSeen reports whether remote stderr contained the
	// interpreter-not-found marker.
	InterpreterMarkerSeen() (bool, error)
	// Finish delivers any output still held once the remote command ended.
	Finish(success bool) error
	// FinishFailure names a Finish failure for the human error line.
	FinishFailure(success bool) string
	// WriteErr reports a local output failure that aborted the session.
	WriteErr() error
	Close()
}

func bufferedRunOutputRequested() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(RunOutputEnv)), "buffered")
}

// streamingRunOutput forwards remote output as it arrives. Stdout bytes pass
// through unchanged, keeping byte pipes and caller-echoed values intact as
// the success contract requires; stderr carries diagnostics, so explicit
// secret values are masked and credential-shaped lines are sanitized.
type streamingRunOutput struct {
	stderrValues *machinecontract.KnownValueStream
	stderrLines  *machinecontract.RedactingWriter
	stderr       io.Writer
	marker       *markerWatcher
	stdoutSink   *abortingWriter
	stderrSink   *abortingWriter
}

func newStreamingRunOutput(stdout, stderr io.Writer, secrets []string, interpreterMarker string, abort func()) *streamingRunOutput {
	var once sync.Once
	stop := func() { once.Do(abort) }
	output := &streamingRunOutput{
		stdoutSink: &abortingWriter{output: stdout, abort: stop},
		stderrSink: &abortingWriter{output: stderr, abort: stop},
	}
	output.stderrLines = machinecontract.NewStreamingRedactingWriter(output.stderrSink)
	output.stderrValues = machinecontract.NewKnownValueStream(output.stderrLines, secrets...)
	output.stderr = output.stderrValues
	if interpreterMarker != "" {
		output.marker = &markerWatcher{marker: []byte(interpreterMarker), next: output.stderrValues}
		output.stderr = output.marker
	}
	return output
}

func (o *streamingRunOutput) Stdout() io.Writer { return o.stdoutSink }
func (o *streamingRunOutput) Stderr() io.Writer { return o.stderr }

func (o *streamingRunOutput) InterpreterMarkerSeen() (bool, error) {
	if o.marker == nil {
		return false, nil
	}
	return o.marker.Seen(), nil
}

func (o *streamingRunOutput) Finish(bool) error {
	return errors.Join(o.stderrValues.Flush(), o.stderrLines.Flush())
}

func (o *streamingRunOutput) FinishFailure(bool) string { return "failed to write remote output" }

func (o *streamingRunOutput) WriteErr() error {
	return errors.Join(o.stdoutSink.Err(), o.stderrSink.Err())
}

func (o *streamingRunOutput) Close() {}

// spoolRunOutput is the SSM_RUN_OUTPUT=buffered compatibility mode.
type spoolRunOutput struct {
	stdout *machinecontract.DiagnosticSpool
	stderr *machinecontract.DiagnosticSpool
	marker string
}

func newSpoolRunOutput(sensitiveValues []string, interpreterMarker string) (*spoolRunOutput, string, error) {
	stdout, err := machinecontract.NewDiagnosticSpool(os.Stdout, sensitiveValues...)
	if err != nil {
		return nil, "failed to spool remote stdout", err
	}
	stderr, err := machinecontract.NewDiagnosticSpool(os.Stderr, sensitiveValues...)
	if err != nil {
		_ = stdout.Close()
		return nil, "failed to spool remote stderr", err
	}
	return &spoolRunOutput{stdout: stdout, stderr: stderr, marker: interpreterMarker}, "", nil
}

func (o *spoolRunOutput) Stdout() io.Writer { return o.stdout }
func (o *spoolRunOutput) Stderr() io.Writer { return o.stderr }

func (o *spoolRunOutput) InterpreterMarkerSeen() (bool, error) {
	if o.marker == "" {
		return false, nil
	}
	return o.stderr.Contains(o.marker)
}

func (o *spoolRunOutput) Finish(success bool) error {
	return errors.Join(o.stdout.Replay(success), o.stderr.Replay(success))
}

func (o *spoolRunOutput) FinishFailure(success bool) string {
	if success {
		return "failed to replay remote output"
	}
	return "failed to replay bounded remote diagnostics"
}

func (o *spoolRunOutput) WriteErr() error { return nil }

func (o *spoolRunOutput) Close() {
	_ = o.stdout.Close()
	_ = o.stderr.Close()
}

// abortingWriter stops the SSH session on the first local write failure. The
// session would otherwise stop draining its channel and wait forever for a
// remote command blocked on a full window.
type abortingWriter struct {
	mu     sync.Mutex
	output io.Writer
	abort  func()
	err    error
}

func (w *abortingWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.output.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.err = err
		w.abort()
	}
	return n, err
}

func (w *abortingWriter) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

// markerWatcher records whether a byte sequence appears anywhere in a stream,
// including across write boundaries, and forwards every byte unchanged.
type markerWatcher struct {
	mu     sync.Mutex
	marker []byte
	tail   []byte
	seen   bool
	next   io.Writer
}

func (w *markerWatcher) Write(data []byte) (int, error) {
	w.mu.Lock()
	if !w.seen {
		window := make([]byte, 0, len(w.tail)+len(data))
		window = append(window, w.tail...)
		window = append(window, data...)
		if bytes.Contains(window, w.marker) {
			w.seen = true
			w.tail = nil
		} else {
			keep := min(len(window), len(w.marker)-1)
			w.tail = append(w.tail[:0], window[len(window)-keep:]...)
		}
	}
	w.mu.Unlock()
	return w.next.Write(data)
}

func (w *markerWatcher) Seen() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seen
}
