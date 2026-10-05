#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

go_version="$(grep -m1 '^go ' go.mod | awk '{print $2}')"
export GOTOOLCHAIN="go${go_version}"
lint_version="$(grep -m1 'GOLANGCI_LINT_VERSION' .github/workflows/ci.yml | sed -E 's/.*GOLANGCI_LINT_VERSION:[[:space:]]*"([^"]+)".*/\1/')"

golangci_lint_path() {
	local candidate version_output version
	if [ -n "${GOLANGCI_LINT:-}" ]; then
		candidate="$GOLANGCI_LINT"
	else
		candidate="$(command -v golangci-lint 2>/dev/null || true)"
	fi
	if [ -z "$candidate" ] || [ ! -x "$candidate" ]; then
		echo "需要 golangci-lint ${lint_version}；官方安装方式见 .github/workflows/ci.yml 里 'Install official golangci-lint prebuilt' 一步，或设置 GOLANGCI_LINT=<路径>" >&2
		return 1
	fi
	if ! version_output="$("$candidate" --version 2>/dev/null)"; then
		echo "需要 golangci-lint ${lint_version}；官方安装方式见 .github/workflows/ci.yml 里 'Install official golangci-lint prebuilt' 一步，或设置 GOLANGCI_LINT=<路径>" >&2
		return 1
	fi
	version="$(printf '%s\n' "$version_output" | sed -nE 's/.*version ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -1)"
	if [ "$version" != "$lint_version" ]; then
		echo "需要 golangci-lint ${lint_version}；找到版本 ${version:-unknown}。官方安装方式见 .github/workflows/ci.yml 里 'Install official golangci-lint prebuilt' 一步，或设置 GOLANGCI_LINT=<路径>" >&2
		return 1
	fi
	printf '%s\n' "$candidate"
}

usage() {
	echo "usage: $0 {fmt-check|vet|lint|vuln|build|test|race|json-check|ssh-matrix|fast|all}" >&2
}

run_check() {
	local name="$1"
	shift
	echo "== $name =="
	if ! "$@"; then
		echo "FAILED: $name" >&2
		return 1
	fi
}

fmt_check() {
	local goroot files
	if ! goroot="$(GOTOOLCHAIN="go${go_version}" go env GOROOT 2>/dev/null)" ||
		[ -z "$goroot" ] || [ ! -x "$goroot/bin/gofmt" ]; then
		echo "需要 Go ${go_version} 的 gofmt；运行 GOTOOLCHAIN=go${go_version} go env GOROOT 查看" >&2
		return 1
	fi
	files="$("$goroot"/bin/gofmt -l .)"
	if [ -n "$files" ]; then
		echo "gofmt required for:" >&2
		echo "$files" >&2
		return 1
	fi
}

vet_check() {
	go vet ./...
}

lint_check() {
	local os lint_bin
	lint_bin="$(golangci_lint_path)"
	for os in linux darwin windows; do
		echo "lint ($os)"
		GOOS="$os" "$lint_bin" run --new-from-rev=origin/main ./...
	done
}

vuln_check() {
	go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
}

build_check() {
	go build -buildvcs=false -o /dev/null ./cmd/ssm
}

test_check() {
	go test -timeout=30m ./...
}

race_check() {
	go test -race -timeout=15m ./...
}

json_check() {
	if ! command -v jq >/dev/null 2>&1; then
		echo "jq is required for json-check" >&2
		return 1
	fi
	jq empty skills/agent-ssm/test-prompts.json
	jq empty skills/agent-ssm/references/request-v1.schema.json
}

ssh_matrix_check() {
	local tool path
	bash -n scripts/ssh_matrix_test.sh
	if [ "$(id -u)" -eq 0 ]; then
		echo "SKIPPED: ssh-matrix requires non-root execution (sshd rejects root in this environment)"
		return 0
	fi
	for tool in awk bash cat chmod cp dd dirname find go grep head id ln mkdir mktemp nohup printenv rm script sed seq sh sha256sum sleep sshd tr wc; do
		if ! command -v "$tool" >/dev/null 2>&1; then
			echo "SKIPPED: ssh-matrix missing prerequisite tool: $tool"
			return 0
		fi
	done
	for path in /run/sshd /usr/lib/openssh/sftp-server; do
		if [ ! -e "$path" ]; then
			echo "SKIPPED: ssh-matrix missing prerequisite path: $path"
			return 0
		fi
	done
	bash scripts/ssh_matrix_test.sh
}

fast_check() {
	run_check fmt-check fmt_check
	run_check vet vet_check
	run_check test test_check
}

all_checks() {
	run_check fmt-check fmt_check
	run_check vet vet_check
	run_check lint lint_check
	run_check vuln vuln_check
	run_check build build_check
	run_check test test_check
	run_check json-check json_check
	run_check ssh-matrix ssh_matrix_check
	run_check race race_check
}

if [ "$#" -ne 1 ]; then
	usage
	exit 2
fi

case "$1" in
	fmt-check) run_check fmt-check fmt_check ;;
	vet) run_check vet vet_check ;;
	lint) run_check lint lint_check ;;
	vuln) run_check vuln vuln_check ;;
	build) run_check build build_check ;;
	test) run_check test test_check ;;
	race) run_check race race_check ;;
	json-check) run_check json-check json_check ;;
	ssh-matrix) run_check ssh-matrix ssh_matrix_check ;;
	fast) fast_check ;;
	all) all_checks ;;
	*) usage; exit 2 ;;
esac
