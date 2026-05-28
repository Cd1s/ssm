package update

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"ssm/internal/config"
)

const (
	defaultRepo = "Cd1s/ssm"
	cooldown    = 6 * time.Hour
)

func flagPath() string {
	return filepath.Join(config.Dir(), ".update-available")
}

func Auto(currentVersion string) error {
	if !shouldCheck() {
		return nil
	}
	markChecked("")
	repo := releaseRepo()
	if repo == "" {
		return nil
	}
	latest, err := checkLatest()
	if err != nil || latest == "" || !newerVersion(latest, currentVersion) {
		return err
	}
	return DownloadVersion(latest, false)
}

func markChecked(latest string) {
	if latest == "" {
		latest = "-"
	}
	_ = os.MkdirAll(config.Dir(), 0700)
	_ = os.WriteFile(flagPath(), []byte(latest+"\n"+fmt.Sprint(time.Now().Unix())), 0600)
}

func ClearFlag() {
	_ = os.Remove(flagPath())
}

func Download() error {
	latest, err := checkLatest()
	if err != nil {
		return err
	}
	if latest == "" {
		return fmt.Errorf("no release found")
	}

	return DownloadVersion(latest, true)
}

func DownloadVersion(version string, verbose bool) error {
	repo := releaseRepo()
	if repo == "" {
		return fmt.Errorf("update repo is not configured")
	}
	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repo, version, assetName())

	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot find current binary: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}

	tmp := exe + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	_, err = io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}

	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	ClearFlag()
	if verbose {
		fmt.Printf("Updated to %s\n", version)
	}
	return nil
}

func assetName() string {
	name := fmt.Sprintf("ssm-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func shouldCheck() bool {
	data, err := os.ReadFile(flagPath())
	if err != nil {
		return true
	}
	parts := strings.SplitN(string(data), "\n", 2)
	if len(parts) < 2 {
		return true
	}
	var ts int64
	_, _ = fmt.Sscanf(parts[1], "%d", &ts)
	return time.Since(time.Unix(ts, 0)) > cooldown
}

func checkLatest() (string, error) {
	repo := releaseRepo()
	if repo == "" {
		return "", nil
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/" + repo + "/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API: %s", resp.Status)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	return release.TagName, nil
}

func releaseRepo() string {
	if repo := strings.TrimSpace(os.Getenv("SSM_UPDATE_REPO")); repo != "" {
		return repo
	}
	if data, err := os.ReadFile(filepath.Join(config.Dir(), "update_repo")); err == nil {
		if repo := strings.TrimSpace(string(data)); repo != "" {
			return repo
		}
	}
	if repo := strings.TrimSpace(config.LoadSettings().UpdateRepo); repo != "" {
		return repo
	}
	return defaultRepo
}

func newerVersion(latest, current string) bool {
	l := parseVersion(latest)
	c := parseVersion(current)
	if len(l) == 0 || len(c) == 0 {
		return latest != current
	}
	for i := 0; i < 3; i++ {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

func parseVersion(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	if len(parts) < 3 {
		return nil
	}
	out := make([]int, 3)
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return nil
		}
		out[i] = n
	}
	return out
}
