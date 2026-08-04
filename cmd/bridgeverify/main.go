package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"ssm/internal/provenance"
	"ssm/internal/provenancefixture"
	"ssm/internal/releaseasset"
)

const v143Commit = "47309c26b95db6ba5f3c91a1d9c63a9a17353060"

var stableV1Tag = regexp.MustCompile(`^v1\.[0-9]+\.[0-9]+$`)

type candidateResult struct {
	OK              bool              `json:"ok"`
	Status          string            `json:"status"`
	Tag             string            `json:"tag"`
	Version         string            `json:"version"`
	Base            string            `json:"base"`
	Targets         int               `json:"targets"`
	ManifestEntries int               `json:"manifest_entries"`
	ChecksumEntries int               `json:"checksum_entries"`
	ChecksumDigest  string            `json:"checksum_manifest_sha256"`
	Checksums       map[string]string `json:"checksums"`
	Publication     bool              `json:"publication"`
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "candidate" {
		fmt.Fprintln(os.Stderr, "usage: bridgeverify candidate [--tag v1.x.y]")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("candidate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	tag := flags.String("tag", "", "intended v1 maintenance tag")
	if err := flags.Parse(os.Args[2:]); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	result, err := verifyCandidate(*tag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bridge candidate failed: %v\n", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "bridge candidate output failed: %v\n", err)
		os.Exit(1)
	}
}

func verifyCandidate(requestedTag string) (candidateResult, error) {
	repo, err := repositoryRoot()
	if err != nil {
		return candidateResult{}, err
	}
	statusBefore, err := gitOutput(repo, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return candidateResult{}, err
	}
	version, err := readSourceVersion(repo)
	if err != nil {
		return candidateResult{}, err
	}
	tag := requestedTag
	if tag == "" {
		tag = "v" + version
	}
	if !stableV1Tag.MatchString(tag) || strings.TrimPrefix(tag, "v") != version {
		return candidateResult{}, fmt.Errorf("candidate tag %q does not match stable v1 source version %q", tag, version)
	}
	if _, err := readReleaseNotes(repo, tag); err != nil {
		return candidateResult{}, err
	}
	if err := verifyMaintenanceAncestry(repo); err != nil {
		return candidateResult{}, err
	}
	if err := verifyBridgeChangeBoundary(repo); err != nil {
		return candidateResult{}, err
	}

	temporary, err := os.MkdirTemp("", "ssm-v1-bridge-candidate-*")
	if err != nil {
		return candidateResult{}, err
	}
	defer func() { _ = os.RemoveAll(temporary) }()

	checksums := make(map[string]string, len(releaseasset.SupportedTargets())+1)
	checksumNames := make([]string, 0, len(releaseasset.SupportedTargets())+1)
	manifest := make([]string, 0, len(releaseasset.ExpectedReleaseNames()))
	for _, target := range releaseasset.SupportedTargets() {
		name := releaseasset.Name(target.GOOS, target.GOARCH)
		path := filepath.Join(temporary, name)
		command := exec.Command("go", "build", "-buildvcs=false", "-ldflags=-s -w -X main.version="+version, "-o", path, "./cmd/ssm") //nolint:gosec // version is strict semver and output is beneath a verifier-owned temporary directory
		command.Dir = repo
		command.Env = buildEnvironment(target.GOOS, target.GOARCH)
		output, buildErr := command.CombinedOutput()
		if buildErr != nil {
			return candidateResult{}, fmt.Errorf("build %s: %w: %s", name, buildErr, strings.TrimSpace(string(output)))
		}
		asset, readErr := os.ReadFile(path) //nolint:gosec // path is beneath the verifier-owned temporary directory
		if readErr != nil || len(asset) == 0 {
			return candidateResult{}, fmt.Errorf("read non-empty %s: %w", name, readErr)
		}
		digest := sha256.Sum256(asset)
		checksums[name] = fmt.Sprintf("%x", digest)
		checksumNames = append(checksumNames, name)
		if err := verifySyntheticProvenance(name, tag, asset); err != nil {
			return candidateResult{}, fmt.Errorf("verify %s provenance: %w", name, err)
		}
		manifest = append(manifest, name, releaseasset.ProvenanceName(name))
	}
	installer, err := os.ReadFile(filepath.Join(repo, "install.sh")) //nolint:gosec // fixed file beneath the resolved repository root
	if err != nil || len(installer) == 0 {
		return candidateResult{}, fmt.Errorf("read non-empty install.sh: %w", err)
	}
	checksums["install.sh"] = fmt.Sprintf("%x", sha256.Sum256(installer))
	checksumNames = append(checksumNames, "install.sh")
	manifest = append(manifest, "install.sh", "checksums.txt")
	if err := releaseasset.ValidateReleaseNames(manifest); err != nil {
		return candidateResult{}, err
	}
	checksumEntries, checksumDigest, err := materializeAndVerifyChecksums(
		filepath.Join(temporary, "checksums.txt"), checksumNames, checksums,
	)
	if err != nil {
		return candidateResult{}, err
	}

	statusAfter, err := gitOutput(repo, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return candidateResult{}, err
	}
	if statusAfter != statusBefore {
		return candidateResult{}, errors.New("candidate verification changed the repository worktree")
	}
	return candidateResult{
		OK: true, Status: "preflight_passed", Tag: tag, Version: version,
		Base: v143Commit, Targets: len(releaseasset.SupportedTargets()),
		ManifestEntries: len(manifest), ChecksumEntries: checksumEntries,
		ChecksumDigest: checksumDigest, Checksums: checksums, Publication: false,
	}, nil
}

func materializeAndVerifyChecksums(path string, names []string, checksums map[string]string) (int, string, error) {
	if len(names) == 0 || len(checksums) != len(names) {
		return 0, "", errors.New("checksum inputs do not exactly match the release manifest")
	}
	var content strings.Builder
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, duplicate := seen[name]; duplicate {
			return 0, "", fmt.Errorf("duplicate checksum input %q", name)
		}
		seen[name] = struct{}{}
		digest, ok := checksums[name]
		if !ok || len(digest) != sha256.Size*2 {
			return 0, "", fmt.Errorf("invalid checksum input for %q", name)
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return 0, "", fmt.Errorf("invalid checksum input for %q: %w", name, err)
		}
		_, _ = fmt.Fprintf(&content, "%s  %s\n", digest, name)
	}
	if err := os.WriteFile(path, []byte(content.String()), 0600); err != nil { //nolint:gosec // path is verifier-owned temporary output
		return 0, "", err
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is verifier-owned temporary output
	if err != nil {
		return 0, "", err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	entries := 0
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || entries >= len(names) || fields[1] != names[entries] || fields[0] != checksums[fields[1]] {
			return 0, "", fmt.Errorf("checksum manifest entry %d does not match exact inputs", entries+1)
		}
		entries++
	}
	if err := scanner.Err(); err != nil {
		return 0, "", err
	}
	if entries != len(names) {
		return 0, "", fmt.Errorf("checksum manifest contains %d entries, want %d", entries, len(names))
	}
	digest := sha256.Sum256(data)
	return entries, fmt.Sprintf("%x", digest), nil
}

func repositoryRoot() (string, error) {
	output, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("find repository root: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func readSourceVersion(repo string) (string, error) {
	data, err := os.ReadFile(filepath.Join(repo, "cmd", "ssm", "main.go")) //nolint:gosec // fixed file beneath the resolved repository root
	if err != nil {
		return "", err
	}
	pattern := regexp.MustCompile(`(?m)^\s*version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$`)
	matches := pattern.FindSubmatch(data)
	if len(matches) != 2 {
		return "", errors.New("source contains no unique stable version assignment")
	}
	return string(matches[1]), nil
}

func readReleaseNotes(repo, tag string) (string, error) {
	file, err := os.Open(filepath.Join(repo, "RELEASE_NOTES.md")) //nolint:gosec // fixed file beneath the resolved repository root
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	header := "## " + tag
	inside := false
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == header {
			inside = true
			continue
		}
		if inside && strings.HasPrefix(line, "## v") {
			break
		}
		if inside {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	notes := strings.TrimSpace(strings.Join(lines, "\n"))
	if !inside || notes == "" {
		return "", fmt.Errorf("release notes for %s are missing or empty", tag)
	}
	if !strings.Contains(strings.ToLower(notes), "not published") {
		return "", fmt.Errorf("release notes for %s do not state candidate publication status", tag)
	}
	return notes, nil
}

func verifyMaintenanceAncestry(repo string) error {
	tagCommit, err := gitOutput(repo, "rev-parse", "v1.4.3^{commit}")
	if err != nil {
		return err
	}
	if tagCommit != v143Commit {
		return fmt.Errorf("v1.4.3 resolves to %s, want %s", tagCommit, v143Commit)
	}
	command := exec.Command("git", "merge-base", "--is-ancestor", v143Commit, "HEAD")
	command.Dir = repo
	if err := command.Run(); err != nil {
		return fmt.Errorf("HEAD is not descended from exact v1.4.3: %w", err)
	}
	return nil
}

func verifyBridgeChangeBoundary(repo string) error {
	changed, err := gitOutput(repo, "diff", "--name-only", v143Commit, "--")
	if err != nil {
		return err
	}
	untracked, err := gitOutput(repo, "ls-files", "--others", "--exclude-standard")
	if err != nil {
		return err
	}
	paths := append(strings.Fields(changed), strings.Fields(untracked)...)
	for _, path := range paths {
		if !pathAllowedForBridge(filepath.ToSlash(path)) {
			return fmt.Errorf("change outside strict v1 bridge boundary: %s", path)
		}
	}
	for _, forbidden := range []string{
		"internal/machinecontract", "internal/synctransaction", "internal/inventorytransaction", "cmd/verify",
	} {
		if info, statErr := os.Stat(filepath.Join(repo, filepath.FromSlash(forbidden))); statErr == nil && info.IsDir() {
			return fmt.Errorf("forbidden v2 runtime package is present: %s", forbidden)
		} else if statErr != nil && !os.IsNotExist(statErr) {
			return statErr
		}
	}
	return nil
}

func pathAllowedForBridge(path string) bool {
	for _, exact := range []string{
		".github/workflows/ci.yml", ".github/workflows/release.yml",
		"README.md", "README.en.md", "RELEASE_NOTES.md", "SECURITY.md", "install.sh",
		"go.mod", "go.sum", "cmd/ssm/main.go", "cmd/ssm/main_test.go",
	} {
		if path == exact {
			return true
		}
	}
	for _, prefix := range []string{
		"cmd/bridgeverify/", "docs/", "internal/update/", "internal/provenance/",
		"internal/provenancefixture/", "internal/releaseasset/",
	} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func verifySyntheticProvenance(asset, tag string, payload []byte) error {
	claims, err := provenancefixture.DefaultClaims(asset, tag, payload)
	if err != nil {
		return err
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		return err
	}
	return provenance.VerifyBundle(fixture.Bundle, provenance.Request{
		AssetName: asset, Version: tag, Digest: sha256.Sum256(payload),
	}, provenance.Options{TrustedMaterial: fixture.TrustedMaterial})
}

func buildEnvironment(goos, goarch string) []string {
	environment := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "GOOS=") || strings.HasPrefix(entry, "GOARCH=") || strings.HasPrefix(entry, "CGO_ENABLED=") {
			continue
		}
		environment = append(environment, entry)
	}
	return append(environment, "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
}

func gitOutput(repo string, args ...string) (string, error) {
	command := exec.Command("git", args...) //nolint:gosec // callers provide only fixed, source-controlled inspection arguments
	command.Dir = repo
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}
