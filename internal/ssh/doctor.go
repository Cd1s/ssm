package ssh

import (
	"fmt"
	"os"
	"strings"
	"time"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
	"ssm/internal/synctransaction"
)

// DoctorReport is agent-oriented local + remote diagnostics.
type DoctorReport struct {
	OK            bool              `json:"ok"`
	VersionHint   string            `json:"version_hint,omitempty"`
	Vault         string            `json:"vault"` // present|missing
	Sync          string            `json:"sync"`  // configured|missing|offline
	LocalVault    string            `json:"local_vault_state"`
	RemoteVault   string            `json:"remote_vault_state"`
	LastPull      string            `json:"last_pull,omitempty"`
	LastPush      string            `json:"last_push,omitempty"`
	LastSync      string            `json:"last_sync,omitempty"`
	Freshness     string            `json:"freshness"`
	RemoteState   string            `json:"remote_state"`
	Offline       bool              `json:"offline"`
	CacheAge      int64             `json:"cache_age_seconds,omitempty"`
	Pending       bool              `json:"pending_changes"`
	Hosts         int               `json:"hosts"`
	Redirects     int               `json:"redirects"`
	Reuse         string            `json:"reuse"` // on|off
	Alias         string            `json:"alias,omitempty"`
	ResolvedAlias string            `json:"resolved_alias,omitempty"`
	Check         *CheckResult      `json:"check,omitempty"`
	Deep          map[string]string `json:"deep,omitempty"`
	machinecontract.Metadata
	Candidates   []string                      `json:"candidates,omitempty"`
	MergeReport  config.MergeReport            `json:"merge_report"`
	SyncConflict *synctransaction.SyncConflict `json:"sync_conflict,omitempty"`
	LatencyMS    int64                         `json:"latency_ms,omitempty"`
}

// Doctor gathers vault/sync status and optional remote check/deep probes.
func Doctor(v *config.Vault, alias string, deep bool, facts synctransaction.Facts) DoctorReport {
	start := time.Now()
	rep := DoctorReport{
		Vault:        "missing",
		Sync:         "missing",
		LocalVault:   "missing",
		RemoteVault:  "unknown",
		Reuse:        "on",
		MergeReport:  config.LoadMergeReport(),
		SyncConflict: facts.Conflict,
		LastPull:     facts.LastPull, LastPush: facts.LastPush, LastSync: facts.LastSync,
		Freshness: string(facts.Freshness), RemoteState: string(facts.Remote),
		Offline: facts.Offline, CacheAge: facts.CacheAge,
	}
	if !reuseEnabled() {
		rep.Reuse = "off"
	}
	if config.Exists() {
		rep.Vault = "present"
		rep.LocalVault = "present"
	}
	switch facts.Configuration {
	case synctransaction.ConfigurationConfigured:
		rep.Sync = "configured"
		rep.RemoteVault = "cached_unknown"
	case synctransaction.ConfigurationOffline:
		rep.Sync = "offline"
	}
	if facts.LocalETag != "" && facts.RemoteETag != "" {
		if facts.Freshness == synctransaction.FreshnessFresh || facts.Freshness == synctransaction.FreshnessCached {
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
		failure := machinecontract.Classify(machinecontract.DoctorAliasNotFound, machinecontract.Details{
			Message: "requested alias was not found",
			Alias:   alias,
		})
		rep.Metadata = failure.Metadata()
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
		rep.Metadata = ch.Metadata
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
		if rep.OK {
			_ = machinecontract.WriteJSON(rep)
		} else {
			_ = machinecontract.WriteFailureJSON(rep)
		}
		return
	}
	if !rep.OK {
		conflicts := make([]machinecontract.DoctorMergeConflict, len(rep.MergeReport.Conflicts))
		for i, conflict := range rep.MergeReport.Conflicts {
			conflicts[i] = machinecontract.DoctorMergeConflict{
				Kind: conflict.Kind, Name: conflict.Name, Winner: conflict.Winner,
			}
		}
		var check *machinecontract.DoctorCheckView
		if rep.Check != nil {
			check = &machinecontract.DoctorCheckView{
				OK: rep.Check.OK, Hostname: rep.Check.Hostname,
				Uname: rep.Check.Uname, LatencyMS: rep.Check.LatencyMS,
			}
		}
		_ = machinecontract.RenderDoctorFailure(
			machinecontract.Streams{Stdout: os.Stdout, Stderr: os.Stderr},
			machinecontract.DoctorFailureView{
				Vault: rep.Vault, Sync: rep.Sync, LocalVault: rep.LocalVault, RemoteVault: rep.RemoteVault,
				Pending: rep.Pending, Hosts: rep.Hosts, Redirects: rep.Redirects, Reuse: rep.Reuse,
				Alias: rep.Alias, ResolvedAlias: rep.ResolvedAlias, Candidates: rep.Candidates,
				MergeConflicts: conflicts, Check: check, Deep: rep.Deep,
				Error: rep.Error, Message: rep.Message, Hint: rep.Hint, Stage: rep.Stage, LatencyMS: rep.LatencyMS,
			},
		)
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
	if rep.LatencyMS > 0 {
		fmt.Printf("latency_ms=%d\n", rep.LatencyMS)
	}
}
