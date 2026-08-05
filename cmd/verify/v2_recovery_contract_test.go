package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const exactV2ArtifactsPage = `{"total_count":6,"artifacts":[{"id":8893638050,"name":"ssm-linux-amd64","expired":false},{"id":8893654485,"name":"ssm-linux-arm64","expired":false},{"id":8893655254,"name":"ssm-darwin-amd64","expired":false},{"id":8893658709,"name":"ssm-darwin-arm64","expired":false},{"id":8893659626,"name":"ssm-windows-amd64.exe","expired":false},{"id":8893655015,"name":"ssm-windows-arm64.exe","expired":false}]}`

func TestV2RecoveryHelperAcceptsExactPaginatedArtifactResponse(t *testing.T) {
	output, calls, err := runV2RecoveryToArtifactDownload(t, exactV2ArtifactsPage)
	if err == nil {
		t.Fatalf("test fake unexpectedly allowed a complete recovery: %s", output)
	}
	if strings.Contains(output, "workflow artifacts are missing, expired, duplicate, or extra") {
		t.Fatalf("exact GitHub artifact page was rejected before download: %s", output)
	}
	if !strings.Contains(calls, "repos/Cd1s/ssm/actions/artifacts/8893638050/zip") {
		t.Fatalf("exact GitHub artifact page did not reach bound archive download; calls=%s; output=%s", calls, output)
	}
	assertNoV2RecoveryMutation(t, calls)
}

func TestV2RecoveryHelperRejectsInexactArtifactBindings(t *testing.T) {
	tests := map[string]string{
		"expired":        strings.Replace(exactV2ArtifactsPage, `"expired":false`, `"expired":true`, 1),
		"duplicate ID":   strings.Replace(exactV2ArtifactsPage, "8893654485", "8893638050", 1),
		"duplicate name": strings.Replace(exactV2ArtifactsPage, "ssm-linux-arm64", "ssm-linux-amd64", 1),
		"wrong ID":       strings.Replace(exactV2ArtifactsPage, "8893654485", "8893654486", 1),
	}
	for name, fixture := range tests {
		t.Run(name, func(t *testing.T) {
			output, calls, err := runV2RecoveryToArtifactDownload(t, fixture)
			if err == nil || !strings.Contains(output, "workflow artifacts are missing, expired, duplicate, or extra") {
				t.Fatalf("inexact binding failure = %q, err=%v", output, err)
			}
			if strings.Contains(calls, "/actions/artifacts/") {
				t.Fatalf("inexact binding reached artifact download: %s", calls)
			}
			assertNoV2RecoveryMutation(t, calls)
		})
	}
}

func TestV2RecoveryHelperRejectsMalformedPaginatedArtifactResponses(t *testing.T) {
	tests := map[string]string{
		"null":           `null`,
		"array wrapped":  `[{"total_count":6,"artifacts":[]}]`,
		"missing count":  `{"artifacts":[]}`,
		"string count":   `{"total_count":"6","artifacts":[]}`,
		"null artifacts": `{"total_count":6,"artifacts":null}`,
		"extra shape":    `{"total_count":6,"artifacts":[],"unexpected":true}`,
	}
	for name, fixture := range tests {
		t.Run(name, func(t *testing.T) {
			output, calls, err := runV2RecoveryToArtifactDownload(t, fixture)
			if err == nil {
				t.Fatalf("malformed response unexpectedly succeeded: %s", output)
			}
			if !strings.Contains(output, "workflow artifact inventory is malformed") {
				t.Fatalf("malformed response failure = %q", output)
			}
			if strings.Contains(calls, "/actions/artifacts/") {
				t.Fatalf("malformed response reached artifact download: %s", calls)
			}
			assertNoV2RecoveryMutation(t, calls)
		})
	}
}

func runV2RecoveryToArtifactDownload(t *testing.T, artifactsPage string) (string, string, error) {
	t.Helper()
	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "gh.log")
	fakeGH := filepath.Join(bin, "gh")
	if runtime.GOOS == "windows" {
		fakeGH += ".exe"
	}
	fakeSource := filepath.Join(bin, "fake-gh.go")
	fake := `package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	call := strings.Join(os.Args[1:], " ")
	logPath := os.Getenv("GH_FAKE_LOG")
	if logPath != "" {
		log, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			panic(err)
		}
		_, _ = fmt.Fprintln(log, call)
		_ = log.Close()
	}
	switch {
	case strings.Contains(call, "releases?per_page=100"):
		fmt.Println(` + strconv.Quote(`[{"id":364882535,"tag_name":"v2.0.0"},{"id":364597135,"tag_name":"v1.4.4"}]`) + `)
	case strings.Contains(call, "actions/runs/30911029600/jobs?per_page=100"):
		fmt.Println(` + strconv.Quote(`{"total_count":8,"jobs":[{"name":"preflight","conclusion":"success"},{"name":"publish","conclusion":"failure"},{"name":"build (linux, amd64, ssm-linux-amd64)","conclusion":"success"},{"name":"build (linux, arm64, ssm-linux-arm64)","conclusion":"success"},{"name":"build (darwin, amd64, ssm-darwin-amd64)","conclusion":"success"},{"name":"build (darwin, arm64, ssm-darwin-arm64)","conclusion":"success"},{"name":"build (windows, amd64, ssm-windows-amd64.exe)","conclusion":"success"},{"name":"build (windows, arm64, ssm-windows-arm64.exe)","conclusion":"success"}]}`) + `)
	case strings.Contains(call, "actions/runs/30911029600/artifacts?per_page=100"):
		fmt.Println(os.Getenv("GH_FAKE_ARTIFACTS_PAGE"))
	case call == "api repos/Cd1s/ssm/releases/364882535":
		fmt.Println(` + strconv.Quote(`{"id":364882535,"tag_name":"v2.0.0","target_commitish":"10417d0e235eff9b22081765b0ad17b75cf74990","name":"v2.0.0","body":"recovery notes\n","draft":false,"prerelease":false,"assets":[]}`) + `)
	case call == "api repos/Cd1s/ssm/releases/latest":
		fmt.Println(` + strconv.Quote(`{"id":364597135,"tag_name":"v1.4.4","draft":false,"prerelease":false}`) + `)
	case call == "api repos/Cd1s/ssm/contents/RELEASE_NOTES.md?ref=10417d0e235eff9b22081765b0ad17b75cf74990":
		fmt.Println(` + strconv.Quote(`{"type":"file","encoding":"base64","size":30,"content":"IyBOb3RlcwoKIyMgdjIuMC4wCnJlY292ZXJ5IG5vdGVzCg=="}`) + `)
	case call == "api repos/Cd1s/ssm/actions/runs/30911029600":
		fmt.Println(` + strconv.Quote(`{"id":30911029600,"event":"push","status":"completed","conclusion":"failure","head_branch":"v2.0.0","head_sha":"10417d0e235eff9b22081765b0ad17b75cf74990","path":".github/workflows/release.yml","name":"Release","run_attempt":1}`) + `)
	case call == "api repos/Cd1s/ssm/actions/artifacts/8893638050/zip":
		os.Exit(88)
	default:
		os.Exit(97)
	}
}
`
	if err := os.WriteFile(fakeSource, []byte(fake), 0o600); err != nil { //nolint:gosec // test-owned fake CLI source
		t.Fatal(err)
	}
	goExecutable, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command(goExecutable, "build", "-buildvcs=false", "-o", fakeGH, fakeSource) //nolint:gosec // fixed test-owned compiler and source
	build.Env = append(os.Environ(), "GO111MODULE=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake gh: %v: %s", err, output)
	}
	root := filepath.Join("..", "..")
	command := exec.Command("bash", filepath.Join(root, "scripts", "recover-v2.0.0-release.sh")) //nolint:gosec // fixed repository helper
	command.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GH_FAKE_LOG="+logPath,
		"GH_FAKE_ARTIFACTS_PAGE="+artifactsPage,
		"GITHUB_REPOSITORY=Cd1s/ssm",
		"GH_TOKEN=test-only",
		"RUNNER_TEMP="+t.TempDir(),
		"EXPECTED_REPOSITORY=Cd1s/ssm",
		"EXPECTED_SOURCE_SHA=10417d0e235eff9b22081765b0ad17b75cf74990",
		"EXPECTED_RELEASE_ID=364882535",
		"EXPECTED_SOURCE_RUN_ID=30911029600",
		"REQUIRED_LATEST_ID=364597135",
		"REQUIRED_LATEST_TAG=v1.4.4",
	)
	output, err := command.CombinedOutput()
	calls, readErr := os.ReadFile(logPath) //nolint:gosec // test-owned log
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(output), string(calls), err
}

func assertNoV2RecoveryMutation(t *testing.T, calls string) {
	t.Helper()
	for _, forbidden := range []string{"--method POST", "--method PATCH", "--method DELETE", "uploads.github.com", "--clobber"} {
		if strings.Contains(calls, forbidden) {
			t.Errorf("recovery used forbidden mutation %q: %s", forbidden, calls)
		}
	}
}

func TestV2RecoveryWorkflowIsExactlyBound(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "recover-v2.0.0.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for description, required := range map[string]string{
		"manual trigger":  "  workflow_dispatch:\n",
		"repository":      "Cd1s/ssm",
		"source SHA":      "10417d0e235eff9b22081765b0ad17b75cf74990",
		"release ID":      "364882535",
		"source run":      "30911029600",
		"latest ID":       "364597135",
		"latest tag":      "v1.4.4",
		"one-time helper": "./scripts/recover-v2.0.0-release.sh",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("recovery workflow lacks %s %q", description, required)
		}
	}
	for _, forbidden := range []string{"schedule:", "push:\n", "pull_request:", "--method PATCH", "--method DELETE", "gh release upload", "--clobber"} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("recovery workflow contains forbidden behavior %q", forbidden)
		}
	}
}

func TestV2RecoveryHelperHasExactClosedContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "recover-v2.0.0-release.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for description, required := range map[string]string{
		"exact repository":         `expected_repository="Cd1s/ssm"`,
		"exact tag":                `expected_tag="v2.0.0"`,
		"exact SHA":                `expected_source_sha="10417d0e235eff9b22081765b0ad17b75cf74990"`,
		"fixed release ID":         `expected_release_id="364882535"`,
		"source run ID":            `expected_run_id="30911029600"`,
		"latest release ID":        `required_latest_id="364597135"`,
		"latest tag":               `required_latest_tag="v1.4.4"`,
		"exhaustive inventory":     `releases?per_page=100`,
		"fixed release reads":      `releases/$expected_release_id`,
		"fixed upload origin":      `https://uploads.github.com/repos/$expected_repository/releases/$expected_release_id/assets?name=`,
		"tagged install source":    `contents/install.sh?ref=$expected_source_sha`,
		"original artifacts":       `actions/runs/$expected_run_id/artifacts?per_page=100`,
		"crypto verifier":          `go run ./cmd/recoveryverify`,
		"transport reconciliation": `reconcile_ambiguous_upload`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("recovery helper lacks %s %q", description, required)
		}
	}
	for _, name := range v2ReleaseAssetNames() {
		if !strings.Contains(script, name) {
			t.Errorf("recovery helper lacks exact asset %q", name)
		}
	}
	for _, forbidden := range []string{"--method PATCH", "--method DELETE", "gh release upload", "--clobber", "releases/tags/", "make_latest"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("recovery helper contains forbidden mutation/resolution %q", forbidden)
		}
	}
}
