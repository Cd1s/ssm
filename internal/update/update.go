package update

import (
	"context"
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
	"ssm/internal/provenance"
	"ssm/internal/releaseasset"
)

type Release struct {
	TagName    string `json:"tag_name"`
	Name       string `json:"name,omitempty"`
	Body       string `json:"body,omitempty"`
	Draft      bool   `json:"draft,omitempty"`
	Prerelease bool   `json:"prerelease,omitempty"`
	Assets     []struct {
		Name string `json:"name"`
	} `json:"assets,omitempty"`
}

type semanticVersion struct {
	major int
	minor int
	patch int
}

// SelectRelease deterministically separates ordinary same-major updates from
// cross-major migration targets. Drafts, prereleases, malformed versions, and
// versions that are not newer than the running binary are unsupported.
func SelectRelease(releases []Release, current string) (sameMajor, crossMajor *Release) {
	currentVersion, ok := parseSemanticVersion(current)
	if !ok {
		return nil, nil
	}
	for i := range releases {
		candidate := &releases[i]
		version, valid := parseSemanticVersion(candidate.TagName)
		if !valid || candidate.Draft || candidate.Prerelease || compareVersion(version, currentVersion) <= 0 {
			continue
		}
		if version.major == currentVersion.major {
			if sameMajor == nil || releaseNewer(candidate.TagName, sameMajor.TagName) {
				sameMajor = candidate
			}
		} else if version.major > currentVersion.major {
			if crossMajor == nil {
				crossMajor = candidate
				continue
			}
			selected, _ := parseSemanticVersion(crossMajor.TagName)
			if compareVersion(version, selected) > 0 {
				crossMajor = candidate
			}
		}
	}
	return sameMajor, crossMajor
}

func releaseNewer(left, right string) bool {
	l, lok := parseSemanticVersion(left)
	r, rok := parseSemanticVersion(right)
	return lok && rok && compareVersion(l, r) > 0
}

func compareVersion(left, right semanticVersion) int {
	if left.major != right.major {
		return left.major - right.major
	}
	if left.minor != right.minor {
		return left.minor - right.minor
	}
	return left.patch - right.patch
}

func parseSemanticVersion(value string) (semanticVersion, bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if value == "" || strings.ContainsAny(value, "-+") {
		return semanticVersion{}, false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return semanticVersion{}, false
	}
	values := [3]int{}
	for i, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return semanticVersion{}, false
		}
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return semanticVersion{}, false
		}
		values[i] = number
	}
	return semanticVersion{major: values[0], minor: values[1], patch: values[2]}, true
}

const (
	defaultRepo    = "Cd1s/ssm"
	checksumsAsset = "checksums.txt"
	maxChecksums   = 16 << 10
	maxMetadata    = 1 << 20
	maxBinary      = 64 << 20
	cooldown       = 6 * time.Hour
)

var (
	httpClient       = &http.Client{Timeout: 15 * time.Second}
	apiBaseURL       = "https://api.github.com"
	downloadBaseURL  = "https://github.com"
	executablePath   = os.Executable
	evalSymlinks     = filepath.EvalSymlinks
	verifyProvenance = provenance.VerifyPublicGoodBundle
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
	releases, err := listReleases()
	if err != nil {
		return err
	}
	sameMajor, crossMajor := SelectRelease(releases, currentVersion)
	available := ""
	if crossMajor != nil {
		available = crossMajor.TagName
	}
	markChecked(available)
	if sameMajor == nil {
		return nil
	}
	if err := validateReleaseAssets(*sameMajor); err != nil {
		return err
	}
	if err := DownloadVersion(sameMajor.TagName, false); err != nil {
		return err
	}
	if available != "" {
		markChecked(available)
	}
	return nil
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

// CleanupPreviousExecutable removes the rollback image retained by a completed
// Windows replacement after the process that mapped it has exited.
func CleanupPreviousExecutable() {
	exe, err := executablePath()
	if err != nil {
		return
	}
	exe, err = evalSymlinks(exe)
	if err != nil {
		return
	}
	_ = cleanupPreviousExecutable(exe)
}

type OrdinaryResult struct {
	Installed           string
	CrossMajorAvailable string
}

func Download(currentVersion string) (OrdinaryResult, error) {
	releases, err := listReleases()
	if err != nil {
		return OrdinaryResult{}, err
	}
	sameMajor, crossMajor := SelectRelease(releases, currentVersion)
	result := OrdinaryResult{}
	if crossMajor != nil {
		result.CrossMajorAvailable = crossMajor.TagName
	}
	if sameMajor == nil {
		if result.CrossMajorAvailable != "" {
			return result, nil
		}
		for _, release := range releases {
			if _, ok := parseSemanticVersion(release.TagName); ok && !release.Draft && !release.Prerelease {
				return result, nil
			}
		}
		return result, fmt.Errorf("no supported newer release found")
	}
	if err := validateReleaseAssets(*sameMajor); err != nil {
		return result, err
	}
	if err := DownloadVersion(sameMajor.TagName, false); err != nil {
		return result, err
	}
	result.Installed = sameMajor.TagName
	return result, nil
}

func DownloadVersion(version string, verbose bool) error {
	return DownloadVersionBeforeReplace(version, verbose, nil)
}

// DownloadVersionBeforeReplace downloads, stages, and verifies an update, then
// invokes beforeReplace immediately before the atomic executable replacement.
func DownloadVersionBeforeReplace(version string, verbose bool, beforeReplace func() error) error {
	repo := releaseRepo()
	if repo == "" {
		return fmt.Errorf("update repo is not configured")
	}

	asset := assetName()
	checksums, err := downloadReleaseAssetLimited(repo, version, checksumsAsset, maxChecksums)
	if err != nil {
		return err
	}
	expected, err := checksumForAsset(checksums, asset)
	if err != nil {
		return err
	}
	provenanceBundle, err := downloadReleaseAssetLimited(
		repo,
		version,
		releaseasset.ProvenanceName(asset),
		provenance.MaxBundleBytes,
	)
	if err != nil {
		return err
	}
	if len(provenanceBundle) == 0 {
		return fmt.Errorf("provenance for %s is empty", asset)
	}

	resp, err := getReleaseAsset(repo, version, asset)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: %s", resp.Status)
	}
	if resp.ContentLength > maxBinary {
		return fmt.Errorf("%s exceeds %d-byte limit", asset, maxBinary)
	}

	exe, err := executablePath()
	if err != nil {
		return fmt.Errorf("cannot find current binary: %w", err)
	}
	exe, err = evalSymlinks(exe)
	if err != nil {
		return err
	}
	executableInfo, err := os.Stat(exe)
	if err != nil {
		return fmt.Errorf("inspect current binary: %w", err)
	}
	if !executableInfo.Mode().IsRegular() {
		return fmt.Errorf("current binary is not a regular file")
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

	if err := tmpFile.Chmod(executableInfo.Mode().Perm()); err != nil {
		_ = tmpFile.Close()
		return err
	}

	h := sha256.New()
	actualDigest, err := copyAndVerifyDigest(tmpFile, resp.Body, h, expected)
	if err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	verificationContext, cancelVerification := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelVerification()
	if err := verifyProvenance(verificationContext, provenanceBundle, provenance.Request{
		AssetName: asset,
		Version:   version,
		Digest:    actualDigest,
	}); err != nil {
		return fmt.Errorf("provenance verification failed for %s: %w", asset, err)
	}
	if beforeReplace != nil {
		if err := beforeReplace(); err != nil {
			return err
		}
	}
	if err := replaceExecutable(tmp, exe); err != nil {
		return err
	}
	keepTmp = true

	ClearFlag()
	if verbose {
		fmt.Printf("Updated to %s\n", version)
	}
	return nil
}

func validateReleaseAssets(release Release) error {
	names := make([]string, 0, len(release.Assets))
	for _, asset := range release.Assets {
		names = append(names, asset.Name)
	}
	if err := releaseasset.ValidateReleaseNames(names); err != nil {
		return fmt.Errorf("release %s asset selection failed: %w", release.TagName, err)
	}
	return nil
}

func assetName() string {
	return AssetNameFor(runtime.GOOS, runtime.GOARCH)
}

// AssetNameFor exposes the production updater selector to release verification.
func AssetNameFor(goos, goarch string) string {
	return releaseasset.Name(goos, goarch)
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

func downloadReleaseAssetLimited(repo, version, asset string, limit int64) ([]byte, error) {
	resp, err := getReleaseAsset(repo, version, asset)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", asset, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", asset, limit)
	}
	return data, nil
}

func checksumForAsset(data []byte, asset string) (string, error) {
	var found string
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
		if found != "" {
			return "", fmt.Errorf("multiple checksums found for %s", asset)
		}
		found = sum
	}
	if found != "" {
		return found, nil
	}
	return "", fmt.Errorf("checksum for %s not found", asset)
}

func copyAndVerify(dst io.Writer, src io.Reader, h hash.Hash, expected string) error {
	_, err := copyAndVerifyDigest(dst, src, h, expected)
	return err
}

func copyAndVerifyDigest(dst io.Writer, src io.Reader, h hash.Hash, expected string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	written, err := io.Copy(io.MultiWriter(dst, h), io.LimitReader(src, maxBinary+1))
	if err != nil {
		return digest, err
	}
	if written > maxBinary {
		return digest, fmt.Errorf("binary exceeds %d-byte limit", maxBinary)
	}
	sum := h.Sum(nil)
	if len(sum) != sha256.Size {
		return digest, fmt.Errorf("invalid SHA-256 result length %d", len(sum))
	}
	copy(digest[:], sum)
	actual := fmt.Sprintf("%x", digest)
	if actual != strings.ToLower(expected) {
		return digest, fmt.Errorf("checksum mismatch: got %s, want %s", actual, expected)
	}
	return digest, nil
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadata+1))
	if err != nil {
		return "", fmt.Errorf("read GitHub release metadata: %w", err)
	}
	if len(data) > maxMetadata {
		return "", fmt.Errorf("GitHub release metadata exceeds %d-byte limit", maxMetadata)
	}
	if err := json.Unmarshal(data, &release); err != nil {
		return "", err
	}
	return release.TagName, nil
}

func listReleases() ([]Release, error) {
	repo := releaseRepo()
	if repo == "" {
		return nil, nil
	}
	url := strings.TrimRight(apiBaseURL, "/") + "/repos/" + repo + "/releases?per_page=100"
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadata+1))
	if err != nil {
		return nil, fmt.Errorf("read GitHub release metadata: %w", err)
	}
	if len(data) > maxMetadata {
		return nil, fmt.Errorf("GitHub release metadata exceeds %d-byte limit", maxMetadata)
	}
	var releases []Release
	if err := json.Unmarshal(data, &releases); err != nil {
		return nil, err
	}
	return releases, nil
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
