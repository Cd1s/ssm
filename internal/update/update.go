package update

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
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
	defaultRepo    = "Cd1s/ssm"
	checksumsAsset = "checksums.txt"
	cooldown       = 6 * time.Hour
)

var (
	httpClient      = &http.Client{Timeout: 15 * time.Second}
	apiBaseURL      = "https://api.github.com"
	downloadBaseURL = "https://github.com"
	executablePath  = os.Executable
	evalSymlinks    = filepath.EvalSymlinks
)

func flagPath() string {
	return filepath.Join(config.Dir(), ".update-available")
}

func Auto(currentVersion string) error {
	repo := releaseRepo()
	if repo == "" {
		return nil
	}
	if !shouldCheck() {
		return nil
	}
	markChecked("")
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
	_ = config.WritePrivateFile(flagPath(), []byte(latest+"\n"+fmt.Sprint(time.Now().Unix())))
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

	asset := assetName()
	checksums, err := downloadReleaseAsset(repo, version, checksumsAsset)
	if err != nil {
		return err
	}
	expected, err := checksumForAsset(checksums, asset)
	if err != nil {
		return err
	}

	resp, err := getReleaseAsset(repo, version, asset)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	exe, err := executablePath()
	if err != nil {
		return fmt.Errorf("cannot find current binary: %w", err)
	}
	exe, err = evalSymlinks(exe)
	if err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(exe), "."+filepath.Base(exe)+".*.new")
	if err != nil {
		return err
	}
	tmp := tmpFile.Name()
	keepTmp := false
	defer func() {
		if !keepTmp {
			_ = os.Remove(tmp)
		}
	}()

	if err := tmpFile.Chmod(0755); err != nil {
		_ = tmpFile.Close()
		return err
	}

	h := sha256.New()
	if err := copyAndVerify(tmpFile, resp.Body, h, expected); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		return err
	}
	keepTmp = true

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

func getReleaseAsset(repo, version, asset string) (*http.Response, error) {
	url := fmt.Sprintf("%s/%s/releases/download/%s/%s", strings.TrimRight(downloadBaseURL, "/"), repo, version, asset)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		return nil, fmt.Errorf("%s: %s", asset, resp.Status)
	}
	return resp, nil
}

func downloadReleaseAsset(repo, version, asset string) ([]byte, error) {
	resp, err := getReleaseAsset(repo, version, asset)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func checksumForAsset(data []byte, asset string) (string, error) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name != asset {
			continue
		}
		sum := strings.ToLower(fields[0])
		if len(sum) != sha256.Size*2 {
			return "", fmt.Errorf("invalid checksum for %s", asset)
		}
		for _, r := range sum {
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
				return "", fmt.Errorf("invalid checksum for %s", asset)
			}
		}
		return sum, nil
	}
	return "", fmt.Errorf("checksum for %s not found", asset)
}

func copyAndVerify(dst io.Writer, src io.Reader, h hash.Hash, expected string) error {
	if _, err := io.Copy(io.MultiWriter(dst, h), src); err != nil {
		return err
	}
	actual := fmt.Sprintf("%x", h.Sum(nil))
	if actual != strings.ToLower(expected) {
		return fmt.Errorf("checksum mismatch: got %s, want %s", actual, expected)
	}
	return nil
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
	resp, err := httpClient.Get(strings.TrimRight(apiBaseURL, "/") + "/repos/" + repo + "/releases/latest")
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
		if updateDisabled(repo) {
			return ""
		}
		return repo
	}
	if data, err := os.ReadFile(filepath.Join(config.Dir(), "update_repo")); err == nil {
		if repo := strings.TrimSpace(string(data)); repo != "" {
			if updateDisabled(repo) {
				return ""
			}
			return repo
		}
	}
	if repo := strings.TrimSpace(config.LoadSettings().UpdateRepo); repo != "" {
		if updateDisabled(repo) {
			return ""
		}
		return repo
	}
	return defaultRepo
}

func updateDisabled(repo string) bool {
	switch strings.ToLower(strings.TrimSpace(repo)) {
	case "off", "none", "disabled":
		return true
	default:
		return false
	}
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
