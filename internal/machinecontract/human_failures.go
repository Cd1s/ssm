package machinecontract

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// RunFailureView is the concrete legacy key/value projection for a failed run.
type RunFailureView struct {
	Plan            bool
	Alias           string
	ResolvedAlias   string
	Exit            int
	RemoteCommand   string
	Script          string
	Interpreter     string
	InputBytes      int
	ScriptSHA256    string
	Mode            string
	Transport       string
	Preflight       string
	Risk            string
	LatencyMS       int64
	Error           string
	Message         string
	Hint            string
	Stage           string
	Stdout          string
	SensitiveValues []string
}

// CheckFailureView is the concrete legacy key/value projection for a failed check.
type CheckFailureView struct {
	Alias     string
	User      string
	Host      string
	Port      int
	Address   string
	LatencyMS int64
	Hostname  string
	Uname     string
	Error     string
	Message   string
	Hint      string
	Stage     string
}

type DoctorMergeConflict struct {
	Kind   string
	Name   string
	Winner string
}

type DoctorCheckView struct {
	OK        bool
	Hostname  string
	Uname     string
	LatencyMS int64
}

// DoctorFailureView is the concrete legacy key/value projection for a failed doctor.
type DoctorFailureView struct {
	Vault          string
	Sync           string
	LocalVault     string
	RemoteVault    string
	Pending        bool
	Hosts          int
	Redirects      int
	Reuse          string
	Alias          string
	ResolvedAlias  string
	Candidates     []string
	MergeConflicts []DoctorMergeConflict
	Check          *DoctorCheckView
	Deep           map[string]string
	Error          string
	Message        string
	Hint           string
	Stage          string
	LatencyMS      int64
}

// MapResultView is one concrete row in the legacy failed-map projection.
type MapResultView struct {
	OK              bool
	Alias           string
	Script          string
	Exit            int
	LatencyMS       int64
	Error           string
	Stdout          string
	Stderr          string
	SensitiveValues []string
}

// RenderFlagHelp preserves the flag package's raw help bytes on stderr.
func RenderFlagHelp(streams Streams, message string) error {
	_, err := io.WriteString(streamOutput(streams.Stderr), message)
	return err
}

// WriteFlagHelp owns raw help placement and its successful process exit.
func WriteFlagHelp(message string) int {
	_ = RenderFlagHelp(Streams{Stdout: os.Stdout, Stderr: os.Stderr}, message)
	return 0
}

func RenderRunFailure(streams Streams, view RunFailureView) error {
	output := streamOutput(streams.Stdout)
	known := append([]string(nil), view.SensitiveValues...)
	view.SensitiveValues = nil
	view = Redact(view, known...)
	if view.Plan {
		if _, err := fmt.Fprintln(output, "plan=1"); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(output, "ok=0"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(output, "alias=%s\n", view.Alias); err != nil {
		return err
	}
	if view.ResolvedAlias != "" && view.ResolvedAlias != view.Alias {
		if _, err := fmt.Fprintf(output, "resolved_alias=%s\n", view.ResolvedAlias); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(output, "exit=%d\n", view.Exit); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"remote_command", view.RemoteCommand},
		{"script", view.Script},
		{"interpreter", view.Interpreter},
	} {
		if field.value != "" {
			if _, err := fmt.Fprintf(output, "%s=%s\n", field.name, field.value); err != nil {
				return err
			}
		}
	}
	if view.InputBytes > 0 {
		if _, err := fmt.Fprintf(output, "stdin_bytes=%d\n", view.InputBytes); err != nil {
			return err
		}
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"script_sha256", view.ScriptSHA256},
		{"mode", view.Mode},
		{"transport", view.Transport},
		{"preflight", view.Preflight},
		{"risk", view.Risk},
	} {
		if field.value != "" {
			if _, err := fmt.Fprintf(output, "%s=%s\n", field.name, field.value); err != nil {
				return err
			}
		}
	}
	if view.LatencyMS > 0 {
		if _, err := fmt.Fprintf(output, "latency_ms=%d\n", view.LatencyMS); err != nil {
			return err
		}
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"error", view.Error},
		{"message", view.Message},
		{"hint", view.Hint},
		{"stage", view.Stage},
	} {
		if field.value != "" {
			if _, err := fmt.Fprintf(output, "%s=%s\n", field.name, field.value); err != nil {
				return err
			}
		}
	}
	if view.Stdout != "" {
		_, err := fmt.Fprintf(output, "stdout=%s\n", strings.ReplaceAll(view.Stdout, "\n", "\\n"))
		return err
	}
	return nil
}

func RenderCheckFailure(streams Streams, view CheckFailureView) error {
	output := streamOutput(streams.Stdout)
	view = Redact(view)
	if _, err := fmt.Fprintln(output, "ok=0"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(output, "alias=%s\nuser=%s\nhost=%s\nport=%d\n", view.Alias, view.User, view.Host, view.Port); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"address", view.Address},
		{"hostname", view.Hostname},
		{"uname", view.Uname},
	} {
		if field.value != "" {
			if _, err := fmt.Fprintf(output, "%s=%s\n", field.name, field.value); err != nil {
				return err
			}
		}
		if field.name == "address" && view.LatencyMS > 0 {
			if _, err := fmt.Fprintf(output, "latency_ms=%d\n", view.LatencyMS); err != nil {
				return err
			}
		}
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"error", view.Error},
		{"message", view.Message},
		{"hint", view.Hint},
		{"stage", view.Stage},
	} {
		if field.value != "" {
			if _, err := fmt.Fprintf(output, "%s=%s\n", field.name, field.value); err != nil {
				return err
			}
		}
	}
	return nil
}

func RenderDoctorFailure(streams Streams, view DoctorFailureView) error {
	output := streamOutput(streams.Stdout)
	view = Redact(view)
	if _, err := fmt.Fprintf(
		output,
		"ok=0\nvault=%s\nsync=%s\nlocal_vault_state=%s\nremote_vault_state=%s\npending_changes=%d\nhosts=%d\nredirects=%d\nreuse=%s\n",
		view.Vault,
		view.Sync,
		view.LocalVault,
		view.RemoteVault,
		boolNumber(view.Pending),
		view.Hosts,
		view.Redirects,
		view.Reuse,
	); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"alias", view.Alias},
		{"resolved_alias", view.ResolvedAlias},
	} {
		if field.value != "" {
			if _, err := fmt.Fprintf(output, "%s=%s\n", field.name, field.value); err != nil {
				return err
			}
		}
	}
	for _, candidate := range view.Candidates {
		if _, err := fmt.Fprintf(output, "candidate=%s\n", candidate); err != nil {
			return err
		}
	}
	for _, conflict := range view.MergeConflicts {
		if _, err := fmt.Fprintf(output, "merge_conflict=%s:%s:%s\n", conflict.Kind, conflict.Name, conflict.Winner); err != nil {
			return err
		}
	}
	if view.Check != nil {
		if _, err := fmt.Fprintf(output, "check_ok=%d\n", boolNumber(view.Check.OK)); err != nil {
			return err
		}
		if view.Check.Hostname != "" {
			if _, err := fmt.Fprintf(output, "hostname=%s\n", view.Check.Hostname); err != nil {
				return err
			}
		}
		if view.Check.Uname != "" {
			if _, err := fmt.Fprintf(output, "uname=%s\n", view.Check.Uname); err != nil {
				return err
			}
		}
		if view.Check.LatencyMS > 0 {
			if _, err := fmt.Fprintf(output, "check_latency_ms=%d\n", view.Check.LatencyMS); err != nil {
				return err
			}
		}
	}
	for key, value := range view.Deep {
		if _, err := fmt.Fprintf(output, "deep_%s=%s\n", key, value); err != nil {
			return err
		}
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"error", view.Error},
		{"message", view.Message},
		{"hint", view.Hint},
		{"stage", view.Stage},
	} {
		if field.value != "" {
			if _, err := fmt.Fprintf(output, "%s=%s\n", field.name, field.value); err != nil {
				return err
			}
		}
	}
	if view.LatencyMS > 0 {
		_, err := fmt.Fprintf(output, "latency_ms=%d\n", view.LatencyMS)
		return err
	}
	return nil
}

func RenderMapFailure(streams Streams, views []MapResultView) error {
	stdout := streamOutput(streams.Stdout)
	stderr := streamOutput(streams.Stderr)
	okCount := 0
	for _, original := range views {
		view := original
		if view.OK {
			okCount++
		} else {
			known := append([]string(nil), view.SensitiveValues...)
			view.SensitiveValues = nil
			view = Redact(view, known...)
		}
		label := view.Alias
		if view.Script != "" {
			label += "/" + view.Script
		}
		status := "ok"
		if !view.OK {
			status = "fail"
		}
		code := view.Error
		if code == "" && !view.OK {
			code = fmt.Sprintf("exit_%d", view.Exit)
		}
		if _, err := fmt.Fprintf(stdout, "%s\t%s\texit=%d\tlatency_ms=%d", label, status, view.Exit, view.LatencyMS); err != nil {
			return err
		}
		if code != "" {
			if _, err := fmt.Fprintf(stdout, "\terror=%s", code); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(stdout); err != nil {
			return err
		}
		if view.Stdout != "" {
			if _, err := io.WriteString(stdout, view.Stdout); err != nil {
				return err
			}
			if !strings.HasSuffix(view.Stdout, "\n") {
				if _, err := fmt.Fprintln(stdout); err != nil {
					return err
				}
			}
		}
		if view.Stderr != "" {
			if _, err := io.WriteString(stderr, view.Stderr); err != nil {
				return err
			}
			if !strings.HasSuffix(view.Stderr, "\n") {
				if _, err := fmt.Fprintln(stderr); err != nil {
					return err
				}
			}
		}
	}
	_, err := fmt.Fprintf(stdout, "summary\tok=%d\tfail=%d\ttotal=%d\n", okCount, len(views)-okCount, len(views))
	return err
}

func streamOutput(output io.Writer) io.Writer {
	if output == nil {
		return io.Discard
	}
	return output
}

func boolNumber(value bool) int {
	if value {
		return 1
	}
	return 0
}
