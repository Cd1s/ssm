## 1. Project Context

- [x] 1.1 Update `openspec/config.yaml` with SSM's Go tech stack, package boundaries, verification commands, and secret-handling constraints. (`openspec/config.yaml`)
- [x] 1.2 Ensure `AGENTS.md` points future agents to the OpenSpec workflow and stays aligned with the project context. (`AGENTS.md`)

## 2. Workflow Guidance

- [x] 2.1 Add review guidance that requires scoped summaries, verification evidence, security notes, and reviewer navigation. (`AGENTS.md`, `openspec/config.yaml`, `.github/workflows/ci.yml`)
- [x] 2.2 Add bug-investigation guidance that requires reproducible context, secret-safe diagnostics, regression coverage, and root cause notes. (`internal/*/*_test.go`, `scripts/ssh_matrix_test.sh`, `RELEASE_NOTES.md`)
- [x] 2.3 Add feature-extension guidance that requires capability boundaries, backward compatibility notes, package-level test plans, and documentation updates. (`openspec/config.yaml`, `AGENTS.md`, `README.md`, `README.en.md`)

## 3. Validation

- [x] 3.1 Run OpenSpec status for the change and confirm all required artifacts are complete. (`openspec status --change improve-review-debug-feature-workflow`)
- [x] 3.2 Run `go test ./...` to confirm workflow-only changes did not affect the Go baseline. (`go test ./...`)
- [x] 3.3 Run `go build ./cmd/ssm` to confirm the repository still builds. (`go build ./cmd/ssm`)
