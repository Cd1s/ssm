package main

import (
	"archive/zip"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const exactV2ArtifactsPage = `{"total_count":6,"artifacts":[{"id":8951330070,"name":"ssm-linux-amd64","digest":"sha256:32da0ec46f51df83dcf534f9b2d7bbdd2a870b59d5ccc9399fcda10001428b6e","expired":false},{"id":8951337800,"name":"ssm-linux-arm64","digest":"sha256:7b44b39067a145d79c2cf302b1d3e6164d5e9982ef2afa41627f6d261e1a9d7d","expired":false},{"id":8951339181,"name":"ssm-darwin-amd64","digest":"sha256:b388f87c932b2bad588fe3ca6e2f3144dbee0765e79e6ec663bdbe8ecbc893ab","expired":false},{"id":8951335502,"name":"ssm-darwin-arm64","digest":"sha256:45dc3a18b03dbd71512dac1a3f7be4d38111a998681871e9168a9766272fcaf0","expired":false},{"id":8951336933,"name":"ssm-windows-amd64.exe","digest":"sha256:a05ef33de51e6b243aa830eb3d2ca4e8629f8cf9552dafe15a940f94010004fa","expired":false},{"id":8951336159,"name":"ssm-windows-arm64.exe","digest":"sha256:048f338f6f05c49ad73c04c99c1594adca46e8897df4ba9978c94d939ce94ea0","expired":false}]}`

const exactV2ReleaseInventory = `[{"id":365897243,"tag_name":"v2.0.1"},{"id":364882535,"tag_name":"v2.0.0"}]`
const exactV2Release = `{"id":365897243,"tag_name":"v2.0.1","target_commitish":"379ce2d91825a4d651117e13ec59d9c9baa686f5","name":"v2.0.1","body":"recovery notes\n","draft":false,"prerelease":false,"assets":[]}`
const exactV2Latest = `{"id":364882535,"tag_name":"v2.0.0","draft":false,"prerelease":false}`
const exactV2Tag = `{"ref":"refs/tags/v2.0.1","object":{"type":"commit","sha":"379ce2d91825a4d651117e13ec59d9c9baa686f5"}}`
const exactV2Run = `{"id":31057964128,"event":"push","status":"completed","conclusion":"failure","head_branch":"v2.0.1","head_sha":"379ce2d91825a4d651117e13ec59d9c9baa686f5","path":".github/workflows/release.yml","name":"Release","run_attempt":1}`
const exactV2JobsPage = `{"total_count":8,"jobs":[{"name":"preflight","conclusion":"success"},{"name":"publish","conclusion":"failure"},{"name":"build (linux, amd64, ssm-linux-amd64)","conclusion":"success"},{"name":"build (linux, arm64, ssm-linux-arm64)","conclusion":"success"},{"name":"build (darwin, amd64, ssm-darwin-amd64)","conclusion":"success"},{"name":"build (darwin, arm64, ssm-darwin-arm64)","conclusion":"success"},{"name":"build (windows, amd64, ssm-windows-amd64.exe)","conclusion":"success"},{"name":"build (windows, arm64, ssm-windows-arm64.exe)","conclusion":"success"}]}`

type v2RecoveryScenario struct {
	releasesPage    string
	release         string
	latest          string
	tag             string
	run             string
	jobsPage        string
	artifactsPage   string
	artifactArchive string
}

func exactV2RecoveryScenario() v2RecoveryScenario {
	return v2RecoveryScenario{
		releasesPage:  exactV2ReleaseInventory,
		release:       exactV2Release,
		latest:        exactV2Latest,
		tag:           exactV2Tag,
		run:           exactV2Run,
		jobsPage:      exactV2JobsPage,
		artifactsPage: exactV2ArtifactsPage,
	}
}

func TestV2RecoveryHelperAcceptsExactPaginatedArtifactResponse(t *testing.T) {
	output, calls, err := runV2RecoveryScenario(t, exactV2RecoveryScenario())
	if err == nil {
		t.Fatalf("test fake unexpectedly allowed a complete recovery: %s", output)
	}
	if strings.Contains(output, "workflow artifacts are missing, expired, duplicate, or extra") {
		t.Fatalf("exact GitHub artifact page was rejected before download: %s", output)
	}
	if !strings.Contains(calls, "repos/Cd1s/ssm/actions/artifacts/8951330070/zip") {
		t.Fatalf("exact GitHub artifact page did not reach bound archive download; calls=%s; output=%s", calls, output)
	}
	assertNoV2RecoveryMutation(t, calls)
}

func TestV2RecoveryHelperRejectsInexactArtifactBindings(t *testing.T) {
	tests := map[string]string{
		"expired":          strings.Replace(exactV2ArtifactsPage, `"expired":false`, `"expired":true`, 1),
		"duplicate ID":     strings.Replace(exactV2ArtifactsPage, "8951337800", "8951330070", 1),
		"duplicate name":   strings.Replace(exactV2ArtifactsPage, "ssm-linux-arm64", "ssm-linux-amd64", 1),
		"duplicate digest": strings.Replace(exactV2ArtifactsPage, "sha256:7b44b39067a145d79c2cf302b1d3e6164d5e9982ef2afa41627f6d261e1a9d7d", "sha256:32da0ec46f51df83dcf534f9b2d7bbdd2a870b59d5ccc9399fcda10001428b6e", 1),
		"wrong ID":         strings.Replace(exactV2ArtifactsPage, "8951337800", "8951337801", 1),
		"wrong name":       strings.Replace(exactV2ArtifactsPage, "ssm-linux-arm64", "ssm-linux-riscv64", 1),
		"wrong digest":     strings.Replace(exactV2ArtifactsPage, "32da0ec46f51df83dcf534f9b2d7bbdd2a870b59d5ccc9399fcda10001428b6e", strings.Repeat("0", 64), 1),
		"malformed digest": strings.Replace(exactV2ArtifactsPage, "sha256:32da0ec46f51df83dcf534f9b2d7bbdd2a870b59d5ccc9399fcda10001428b6e", "not-a-digest", 1),
	}
	for name, fixture := range tests {
		t.Run(name, func(t *testing.T) {
			scenario := exactV2RecoveryScenario()
			scenario.artifactsPage = fixture
			output, calls, err := runV2RecoveryScenario(t, scenario)
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

func TestV2RecoveryHelperRejectsInexactReleaseAndSourceEvidenceBeforeMutation(t *testing.T) {
	tests := map[string]struct {
		mutate func(*v2RecoveryScenario)
		want   string
	}{
		"malformed Release inventory": {
			mutate: func(s *v2RecoveryScenario) { s.releasesPage = `[{"id":365897243}]` },
			want:   "exhaustive Release inventory is malformed",
		},
		"duplicate Release tag": {
			mutate: func(s *v2RecoveryScenario) {
				s.releasesPage = `[{"id":365897243,"tag_name":"v2.0.1"},{"id":365897244,"tag_name":"v2.0.1"}]`
			},
			want: "exhaustive Release inventory is ambiguous",
		},
		"wrong Release source": {
			mutate: func(s *v2RecoveryScenario) {
				s.release = strings.Replace(exactV2Release, "379ce2d91825a4d651117e13ec59d9c9baa686f5", strings.Repeat("0", 40), 1)
			},
			want: "initial Release binding failed",
		},
		"wrong Release body": {
			mutate: func(s *v2RecoveryScenario) {
				s.release = strings.Replace(exactV2Release, "recovery notes", "wrong notes", 1)
			},
			want: "initial Release binding failed",
		},
		"preexisting Release asset": {
			mutate: func(s *v2RecoveryScenario) {
				s.release = strings.Replace(exactV2Release, `"assets":[]`, `"assets":[{"name":"unexpected"}]`, 1)
			},
			want: "initial Release binding failed",
		},
		"wrong latest": {
			mutate: func(s *v2RecoveryScenario) { s.latest = strings.Replace(exactV2Latest, "364882535", "364882536", 1) },
			want:   "GitHub latest binding failed",
		},
		"wrong lightweight tag source": {
			mutate: func(s *v2RecoveryScenario) {
				s.tag = strings.Replace(exactV2Tag, "379ce2d91825a4d651117e13ec59d9c9baa686f5", strings.Repeat("f", 40), 1)
			},
			want: "tag binding failed",
		},
		"wrong source run": {
			mutate: func(s *v2RecoveryScenario) {
				s.run = strings.Replace(exactV2Run, `"head_branch":"v2.0.1"`, `"head_branch":"v2.0.0"`, 1)
			},
			want: "source run identity mismatch",
		},
		"unexpected source job": {
			mutate: func(s *v2RecoveryScenario) {
				s.jobsPage = strings.Replace(exactV2JobsPage, `"name":"publish"`, `"name":"unexpected"`, 1)
			},
			want: "source job conclusions are not exact",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			scenario := exactV2RecoveryScenario()
			test.mutate(&scenario)
			output, calls, err := runV2RecoveryScenario(t, scenario)
			if err == nil || !strings.Contains(output, test.want) {
				t.Fatalf("failure = %q, err=%v, want %q", output, err, test.want)
			}
			assertNoV2RecoveryMutation(t, calls)
		})
	}
}

func TestV2RecoveryHelperRejectsUnexpectedArtifactArchiveFilesBeforeMutation(t *testing.T) {
	if _, err := exec.LookPath("unzip"); err != nil {
		t.Skip("unzip is required to exercise the recovery archive boundary")
	}
	archive := filepath.Join(t.TempDir(), "artifact.zip")
	var contents bytes.Buffer
	writer := zip.NewWriter(&contents)
	for name, body := range map[string]string{
		"ssm-linux-amd64":               "binary",
		"ssm-linux-amd64.sigstore.json": "bundle",
		"unexpected.txt":                "unexpected",
	} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, contents.Bytes(), 0o600); err != nil { //nolint:gosec // test-owned archive
		t.Fatal(err)
	}
	scenario := exactV2RecoveryScenario()
	scenario.artifactArchive = archive
	output, calls, err := runV2RecoveryScenario(t, scenario)
	if err == nil || !strings.Contains(output, "has unexpected files") {
		t.Fatalf("unexpected archive failure = %q, err=%v", output, err)
	}
	assertNoV2RecoveryMutation(t, calls)
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
			scenario := exactV2RecoveryScenario()
			scenario.artifactsPage = fixture
			output, calls, err := runV2RecoveryScenario(t, scenario)
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

func runV2RecoveryScenario(t *testing.T, scenario v2RecoveryScenario) (string, string, error) {
	t.Helper()
	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "gh.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
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

const releasesPage = ` + strconv.Quote(scenario.releasesPage) + `
const release = ` + strconv.Quote(scenario.release) + `
const latest = ` + strconv.Quote(scenario.latest) + `
const tag = ` + strconv.Quote(scenario.tag) + `
const run = ` + strconv.Quote(scenario.run) + `
const jobsPage = ` + strconv.Quote(scenario.jobsPage) + `
const artifactsPage = ` + strconv.Quote(scenario.artifactsPage) + `

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
		fmt.Println(releasesPage)
	case strings.Contains(call, "actions/runs/31057964128/jobs?per_page=100"):
		fmt.Println(jobsPage)
	case strings.Contains(call, "actions/runs/31057964128/artifacts?per_page=100"):
		fmt.Println(artifactsPage)
	case call == "api repos/Cd1s/ssm/releases/365897243":
		fmt.Println(release)
	case call == "api repos/Cd1s/ssm/releases/latest":
		fmt.Println(latest)
	case call == "api repos/Cd1s/ssm/git/ref/tags/v2.0.1":
		fmt.Println(tag)
	case call == "api repos/Cd1s/ssm/contents/RELEASE_NOTES.md?ref=379ce2d91825a4d651117e13ec59d9c9baa686f5":
		fmt.Println(` + strconv.Quote(`{"type":"file","encoding":"base64","size":34,"content":"IyBOb3RlcwoKIyMgdjIuMC4xCnJlY292ZXJ5IG5vdGVzCg=="}`) + `)
	case call == "api repos/Cd1s/ssm/actions/runs/31057964128":
		fmt.Println(run)
	case call == "api repos/Cd1s/ssm/actions/artifacts/8951330070/zip":
		archive := os.Getenv("GH_FAKE_ARCHIVE")
		if archive == "" { os.Exit(88) }
		data, err := os.ReadFile(archive)
		if err != nil { panic(err) }
		_, _ = os.Stdout.Write(data)
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
	if scenario.artifactArchive != "" {
		writeFakeSHA256Sum(t, bin)
	}
	root := filepath.Join("..", "..")
	command := exec.Command("bash", filepath.Join(root, "scripts", "recover-v2.0.1-release.sh")) //nolint:gosec // fixed repository helper
	command.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GH_FAKE_LOG="+logPath,
		"GITHUB_REPOSITORY=Cd1s/ssm",
		"GITHUB_REF=refs/heads/agent-headless-sync",
		"GH_TOKEN=test-only",
		"RUNNER_TEMP="+t.TempDir(),
		"EXPECTED_REPOSITORY=Cd1s/ssm",
		"EXPECTED_SOURCE_SHA=379ce2d91825a4d651117e13ec59d9c9baa686f5",
		"EXPECTED_RELEASE_ID=365897243",
		"EXPECTED_SOURCE_RUN_ID=31057964128",
		"REQUIRED_LATEST_ID=364882535",
		"REQUIRED_LATEST_TAG=v2.0.0",
		"GH_FAKE_ARCHIVE="+scenario.artifactArchive,
	)
	output, err := command.CombinedOutput()
	calls, readErr := os.ReadFile(logPath) //nolint:gosec // test-owned log
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(output), string(calls), err
}

func writeFakeSHA256Sum(t *testing.T, bin string) {
	t.Helper()
	path := filepath.Join(bin, "sha256sum")
	if runtime.GOOS == "windows" {
		path += ".exe"
	}
	source := filepath.Join(bin, "fake-sha256sum.go")
	program := `package main

import (
	"fmt"
	"os"
)

func main() {
	name := "-"
	if len(os.Args) > 1 { name = os.Args[len(os.Args)-1] }
	fmt.Printf("32da0ec46f51df83dcf534f9b2d7bbdd2a870b59d5ccc9399fcda10001428b6e  %s\n", name)
}
`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil { //nolint:gosec // test-owned fake source
		t.Fatal(err)
	}
	goExecutable, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command(goExecutable, "build", "-buildvcs=false", "-o", path, source) //nolint:gosec // fixed test-owned compiler and source
	build.Env = append(os.Environ(), "GO111MODULE=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake sha256sum: %v: %s", err, output)
	}
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
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "recover-v2.0.1.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for description, required := range map[string]string{
		"manual trigger":         "  workflow_dispatch:\n",
		"repository and branch":  "github.repository == 'Cd1s/ssm' && github.ref == 'refs/heads/agent-headless-sync'",
		"fixed concurrency":      "group: recover-Cd1s-ssm-v2.0.1-365897243",
		"no cancellation":        "cancel-in-progress: false",
		"exact checkout action":  "uses: actions/checkout@v7",
		"implementation":         "ref: REPLACE_WITH_COMMIT_A_SHA",
		"credential isolation":   "persist-credentials: false",
		"reviewed Go toolchain":  "go-version: \"1.25.12\"",
		"reviewed prerequisites": "sudo apt-get update && sudo apt-get install -y jq unzip",
		"source SHA":             "379ce2d91825a4d651117e13ec59d9c9baa686f5",
		"release ID":             "365897243",
		"source run":             "31057964128",
		"latest ID":              "364882535",
		"latest tag":             "v2.0.0",
		"one-time helper":        "./scripts/recover-v2.0.1-release.sh",
		"script hash gate":       "scripts/recover-v2.0.1-release.sh",
		"verifier hash gate":     "cmd/recoveryverify/main.go",
		"hash verification":      "sha256sum -c -",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("recovery workflow lacks %s %q", description, required)
		}
	}
	for _, forbidden := range []string{"schedule:", "push:\n", "pull_request:", "pull_request_target:", "workflow_call:", "--method PATCH", "--method DELETE", "gh release upload", "--clobber"} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("recovery workflow contains forbidden behavior %q", forbidden)
		}
	}
}

func TestV2RecoveryHelperHasExactClosedContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "recover-v2.0.1-release.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for description, required := range map[string]string{
		"exact repository":         `expected_repository="Cd1s/ssm"`,
		"exact tag":                `expected_tag="v2.0.1"`,
		"exact SHA":                `expected_source_sha="379ce2d91825a4d651117e13ec59d9c9baa686f5"`,
		"fixed release ID":         `expected_release_id="365897243"`,
		"source run ID":            `expected_run_id="31057964128"`,
		"latest release ID":        `required_latest_id="364882535"`,
		"latest tag":               `required_latest_tag="v2.0.0"`,
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
	for _, binding := range []string{
		"8951330070", "8951337800", "8951339181", "8951335502", "8951336933", "8951336159",
		"32da0ec46f51df83dcf534f9b2d7bbdd2a870b59d5ccc9399fcda10001428b6e",
		"7b44b39067a145d79c2cf302b1d3e6164d5e9982ef2afa41627f6d261e1a9d7d",
		"b388f87c932b2bad588fe3ca6e2f3144dbee0765e79e6ec663bdbe8ecbc893ab",
		"45dc3a18b03dbd71512dac1a3f7be4d38111a998681871e9168a9766272fcaf0",
		"a05ef33de51e6b243aa830eb3d2ca4e8629f8cf9552dafe15a940f94010004fa",
		"048f338f6f05c49ad73c04c99c1594adca46e8897df4ba9978c94d939ce94ea0",
	} {
		if !strings.Contains(script, binding) {
			t.Errorf("recovery helper lacks exact artifact binding %q", binding)
		}
	}
	for _, forbidden := range []string{"--method PATCH", "--method DELETE", "gh release upload", "--clobber", "releases/tags/", "make_latest", "repos/$expected_repository/releases\""} {
		if strings.Contains(script, forbidden) {
			t.Errorf("recovery helper contains forbidden mutation/resolution %q", forbidden)
		}
	}
	if got := strings.Count(script, "--method POST"); got != 1 {
		t.Errorf("recovery helper contains %d POST call sites, want only the fixed asset upload", got)
	}
}

func TestV2RecoveryVerifierHasExactProvenanceContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "cmd", "recoveryverify", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	verifier := string(data)
	for _, required := range []string{
		"v2.0.1",
		"379ce2d91825a4d651117e13ec59d9c9baa686f5",
		"https://github.com/Cd1s/ssm/actions/runs/31057964128/attempts/1",
		"refs/tags/v2.0.1",
		"https://github.com/Cd1s/ssm",
		".github/workflows/release.yml",
		"gitCommit",
		"VerifyPublicGoodBundle",
		"AssetName",
		"Digest",
	} {
		if !strings.Contains(verifier, required) {
			t.Errorf("recovery verifier lacks exact binding %q", required)
		}
	}
}
