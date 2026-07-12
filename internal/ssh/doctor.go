package ssh

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ssm/internal/cloud"
	"ssm/internal/config"
)

// DoctorReport is agent-oriented local + remote diagnostics.
type DoctorReport struct {
	OK            bool                `json:"ok"`
	VersionHint   string              `json:"version_hint,omitempty"`
	Vault         string              `json:"vault"` // present|missing
	Sync          string              `json:"sync"`  // configured|missing
	LocalVault    string              `json:"local_vault_state"`
	RemoteVault   string              `json:"remote_vault_state"`
	LastPull      string              `json:"last_pull,omitempty"`
	LastPush      string              `json:"last_push,omitempty"`
	Pending       bool                `json:"pending_changes"`
	Hosts         int                 `json:"hosts"`
	Redirects     int                 `json:"redirects"`
	Reuse         string              `json:"reuse"` // on|off
	Alias         string              `json:"alias,omitempty"`
	ResolvedAlias string              `json:"resolved_alias,omitempty"`
	Check         *CheckResult        `json:"check,omitempty"`
	Deep          map[string]string   `json:"deep,omitempty"`
	Error         string              `json:"error,omitempty"`
	Message       string              `json:"message,omitempty"`
	Hint          string              `json:"hint,omitempty"`
	Exit          int                 `json:"exit"`
	Stage         string              `json:"stage,omitempty"`
	Candidates    []string            `json:"candidates,omitempty"`
	MergeReport   config.MergeReport  `json:"merge_report"`
	SyncConflict  *cloud.SyncConflict `json:"sync_conflict,omitempty"`
	LatencyMS     int64               `json:"latency_ms,omitempty"`
}

// Doctor gathers vault/sync status and optional remote check/deep probes.
func Doctor(v *config.Vault, alias string, deep bool) DoctorReport {
	start := time.Now()
	rep := DoctorReport{
		Vault:        "missing",
		Sync:         "missing",
		LocalVault:   "missing",
		RemoteVault:  "unknown",
		Reuse:        "on",
		MergeReport:  config.LoadMergeReport(),
		SyncConflict: cloud.LoadSyncConflict(),
	}
	settings := config.LoadSettings()
	rep.LastPull, rep.LastPush = settings.LastPull, settings.LastPush
	if !reuseEnabled() {
		rep.Reuse = "off"
	}
	if config.Exists() {
		rep.Vault = "present"
		rep.LocalVault = "present"
	}
	if _, err := os.Stat(filepath.Join(config.Dir(), "cloud.json")); err == nil {
		rep.Sync = "configured"
		rep.RemoteVault = "cached_unknown"
	}
	if local, err := cloud.LocalVaultETag(); err == nil && cloud.CachedRemoteETag() != "" {
		if local == cloud.CachedRemoteETag() {
			rep.LocalVault = "matches_remote"
			rep.RemoteVault = "cached_match"
		} else {
			rep.LocalVault = "local_ahead"
			rep.RemoteVault = "cached_behind"
			rep.Pending = true
		}
	}
	if v != nil {
		rep.Hosts = len(v.Connections)
	}
	rep.Redirects = len(config.LoadRedirects())

	if alias == "" {
		rep.OK = rep.Vault == "present"
		rep.LatencyMS = time.Since(start).Milliseconds()
		return rep
	}

	rep.Alias = alias
	c, resolved, ok := config.ResolveAlias(v, alias)
	if !ok {
		rep.OK = false
		rep.Error = ErrCodeAliasNotFound
		rep.Message = "requested alias was not found"
		rep.Hint = "use sshctl --json host list and retry with an exact alias"
		rep.Exit = ExitConnectionFailed
		rep.Stage = "lookup"
		names := make([]string, 0, len(v.Connections))
		for _, connection := range v.Connections {
			names = append(names, connection.Name)
		}
		rep.Candidates = SuggestNames(alias, names, 5)
		rep.ResolvedAlias = resolved
		rep.LatencyMS = time.Since(start).Milliseconds()
		return rep
	}
	rep.ResolvedAlias = resolved
	ch := Check(c, v)
	// Prefer requested alias in nested check display.
	ch.Alias = alias
	rep.Check = &ch
	if !ch.OK {
		rep.OK = false
		rep.Error = ch.Error
		rep.Message = ch.Message
		rep.Hint = ch.Hint
		rep.Exit = ch.Exit
		rep.Stage = ch.Stage
		rep.LatencyMS = time.Since(start).Milliseconds()
		return rep
	}

	if deep {
		rep.Deep = deepProbe(c, v)
	}
	rep.OK = true
	rep.Exit = 0
	rep.LatencyMS = time.Since(start).Milliseconds()
	return rep
}

func deepProbe(c config.Connection, v *config.Vault) map[string]string {
	// One remote script: collect a few health signals without being a monitoring suite.
	script := strings.Join([]string{
		`echo "uptime=$(uptime 2>/dev/null | tr -s ' ' | sed 's/^ //')"`,
		`echo "df_root=$(df -P / 2>/dev/null | awk 'NR==2{print $5" used of "$2}')"`,
		`echo "mem=$( (free -m 2>/dev/null || true) | awk '/Mem:/{print $3"/"$2"MB"}')"`,
		`echo "load=$(cat /proc/loadavg 2>/dev/null | awk '{print $1" "$2" "$3}')"`,
		`echo "shell=$(command -v bash || command -v sh || echo none)"`,
	}, "; ")
	res := Run(c, v, RunOptions{Command: script, Capture: true})
	out := map[string]string{}
	if !res.OK {
		out["probe_error"] = res.Error
		if res.Stderr != "" {
			out["stderr"] = strings.TrimSpace(res.Stderr)
		}
		return out
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[k] = val
	}
	return out
}

// WriteDoctorReport prints doctor output.
func WriteDoctorReport(rep DoctorReport, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return
	}
	fmt.Printf("ok=%d\n", boolInt(rep.OK))
	fmt.Printf("vault=%s\n", rep.Vault)
	fmt.Printf("sync=%s\n", rep.Sync)
	fmt.Printf("local_vault_state=%s\n", rep.LocalVault)
	fmt.Printf("remote_vault_state=%s\n", rep.RemoteVault)
	fmt.Printf("pending_changes=%d\n", boolInt(rep.Pending))
	fmt.Printf("hosts=%d\n", rep.Hosts)
	fmt.Printf("redirects=%d\n", rep.Redirects)
	fmt.Printf("reuse=%s\n", rep.Reuse)
	if rep.Alias != "" {
		fmt.Printf("alias=%s\n", rep.Alias)
	}
	if rep.ResolvedAlias != "" {
		fmt.Printf("resolved_alias=%s\n", rep.ResolvedAlias)
	}
	for _, candidate := range rep.Candidates {
		fmt.Printf("candidate=%s\n", candidate)
	}
	for _, conflict := range rep.MergeReport.Conflicts {
		fmt.Printf("merge_conflict=%s:%s:%s\n", conflict.Kind, conflict.Name, conflict.Winner)
	}
	if rep.Check != nil {
		fmt.Printf("check_ok=%d\n", boolInt(rep.Check.OK))
		if rep.Check.Hostname != "" {
			fmt.Printf("hostname=%s\n", rep.Check.Hostname)
		}
		if rep.Check.Uname != "" {
			fmt.Printf("uname=%s\n", rep.Check.Uname)
		}
		if rep.Check.LatencyMS > 0 {
			fmt.Printf("check_latency_ms=%d\n", rep.Check.LatencyMS)
		}
	}
	for k, val := range rep.Deep {
		fmt.Printf("deep_%s=%s\n", k, val)
	}
	if rep.Error != "" {
		fmt.Printf("error=%s\n", rep.Error)
	}
	if rep.Message != "" {
		fmt.Printf("message=%s\n", rep.Message)
	}
	if rep.Hint != "" {
		fmt.Printf("hint=%s\n", rep.Hint)
	}
	if rep.Stage != "" {
		fmt.Printf("stage=%s\n", rep.Stage)
	}
	if rep.LatencyMS > 0 {
		fmt.Printf("latency_ms=%d\n", rep.LatencyMS)
	}
}
