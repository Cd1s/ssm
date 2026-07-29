package update

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ssm/internal/config"
	"ssm/internal/synctransaction"
)

type BreakingChange struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

type MigrationCheck struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Automated   bool   `json:"automated"`
	Description string `json:"description"`
	Remediation string `json:"remediation,omitempty"`
}

type MigrationReview struct {
	OK                 bool             `json:"ok"`
	Error              string           `json:"error,omitempty"`
	Message            string           `json:"message,omitempty"`
	Hint               string           `json:"hint,omitempty"`
	Stage              string           `json:"stage,omitempty"`
	Exit               int              `json:"exit,omitempty"`
	Current            string           `json:"current"`
	Target             string           `json:"target"`
	ReleaseName        string           `json:"release_name,omitempty"`
	ReleaseNotes       string           `json:"release_notes"`
	BreakingChanges    []BreakingChange `json:"breaking_changes"`
	AutomatedChecks    []MigrationCheck `json:"automated_checks"`
	ManualChecks       []MigrationCheck `json:"manual_consumer_checks"`
	Authorized         bool             `json:"authorized"`
	AuthorizationState string           `json:"authorization_state"`
	Installed          bool             `json:"installed"`
	RollbackGuidance   string           `json:"rollback_guidance"`
	Remediation        string           `json:"remediation"`
}

var approvedBreakingChanges = []BreakingChange{
	{"BC-1", "Invalid or unreadable cloud configuration is fatal for online inventory."},
	{"BC-2", "Scoped publication rejects unsatisfied cross-alias saved-key dependencies."},
	{"BC-3", "Stream startup failures use compact NDJSON."},
	{"BC-4", "Legacy mutations create pending transactions and do not auto-publish."},
	{"BC-5", "Bare push is rejected and empty-ledger push --all performs no PUT."},
	{"BC-6", "Online streams require a positive refresh interval."},
	{"BC-7", "Directory transfer output uses the truthful common transfer contract."},
	{"BC-8", "Ordinary automatic and manual replacement cannot cross a major boundary."},
	{"BC-9", "Update artifacts require pinned keyless provenance in addition to digests."},
	{"BC-10", "make check is non-mutating and CI-equivalent."},
}

var manualMigrationChecks = []MigrationCheck{
	{ID: "legacy_bare_push_consumers", Status: "review_required", Automated: false, Description: "Review external callers that use bare ssm push; migrate to --only or deliberate non-empty --all."},
	{ID: "zero_refresh_online_streams", Status: "review_required", Automated: false, Description: "Review external online stream callers using --refresh=0; choose a positive interval or explicit --offline."},
	{ID: "directory_transfer_consumers", Status: "review_required", Automated: false, Description: "Review external consumers of directory transfer fields and omissions against the v2 field contract."},
}

func ReviewMajor(current string, authorize bool, masterPassPath string) (MigrationReview, error) {
	review := MigrationReview{
		Current: current, BreakingChanges: append([]BreakingChange(nil), approvedBreakingChanges...),
		ManualChecks: append([]MigrationCheck(nil), manualMigrationChecks...),
		Authorized:   authorize, Installed: false,
		RollbackGuidance: "Keep the prior v1 executable until v2 validation completes; restore that preserved executable if rollout checks fail.",
		Remediation:      "Resolve every failed automated check, complete the external-consumer reviews, then rerun ssm update --major --yes.",
	}
	if authorize {
		review.AuthorizationState = "authorized"
	} else {
		review.AuthorizationState = "not_authorized"
	}
	releases, err := listReleases()
	if err != nil {
		return review, err
	}
	_, target := SelectRelease(releases, current)
	if target == nil {
		return review, fmt.Errorf("no supported cross-major release found")
	}
	review.Target = target.TagName
	review.ReleaseName = target.Name
	review.ReleaseNotes = strings.TrimSpace(target.Body)
	review.AutomatedChecks = migrationPreflight(*target, masterPassPath)
	review.OK = review.ReleaseNotes != "" && checksPassed(review.AutomatedChecks)
	if review.ReleaseNotes == "" {
		return review, fmt.Errorf("release %s is missing migration release notes", target.TagName)
	}
	if !review.OK {
		return review, fmt.Errorf("migration preflight failed")
	}
	return review, nil
}

func checksPassed(checks []MigrationCheck) bool {
	for _, check := range checks {
		if check.Status != "passed" {
			return false
		}
	}
	return true
}

func migrationPreflight(release Release, masterPassPath string) []MigrationCheck {
	localFacts, localErr := synctransaction.New(synctransaction.Options{}).InspectLocal()
	checks := []MigrationCheck{
		checkCloudConfiguration(localFacts, localErr),
		checkPendingRecovery(masterPassPath),
		checkDivergence(localFacts),
		checkReleaseAsset(release),
		checkRollbackReadiness(),
	}
	return checks
}

func passedCheck(id, description string) MigrationCheck {
	return MigrationCheck{ID: id, Status: "passed", Automated: true, Description: description}
}

func failedCheck(id, description, remediation string) MigrationCheck {
	return MigrationCheck{ID: id, Status: "failed", Automated: true, Description: description, Remediation: remediation}
}

func checkCloudConfiguration(facts synctransaction.Facts, err error) MigrationCheck {
	if err == nil && facts.Configuration == synctransaction.ConfigurationUnconfigured {
		return passedCheck("cloud_configuration", "Synchronization is unconfigured; no invalid cloud configuration was found.")
	}
	if err == nil && facts.Configuration == synctransaction.ConfigurationConfigured {
		return passedCheck("cloud_configuration", "Cloud configuration is readable and valid.")
	}
	return failedCheck("cloud_configuration", "Cloud configuration is invalid or unreadable.", "Repair or deliberately remove cloud.json before migration.")
}

func checkPendingRecovery(masterPassPath string) MigrationCheck {
	for _, name := range []string{"publishing-intent.json", "publication-intent.json"} {
		if _, err := os.Stat(filepath.Join(config.Dir(), name)); err == nil || !os.IsNotExist(err) {
			return failedCheck("pending_recovery", "A pending publication recovery intent exists or cannot be inspected.", "Complete reviewed recovery with the current executable before migration.")
		}
	}
	if !config.Exists() {
		return passedCheck("pending_recovery", "No local vault or publication recovery intent exists.")
	}
	passwordPath := strings.TrimSpace(masterPassPath)
	if passwordPath == "" {
		passwordPath = strings.TrimSpace(os.Getenv("SSM_MASTER_PASS_FILE"))
	}
	if passwordPath == "" {
		return failedCheck("pending_recovery", "The encrypted vault cannot be checked non-interactively without SSM_MASTER_PASS_FILE.", "Provide the existing permission-restricted master-pass file and rerun.")
	}
	password, err := os.ReadFile(passwordPath) //nolint:gosec // explicit non-interactive operator path from SSM_MASTER_PASS_FILE
	if err != nil {
		return failedCheck("pending_recovery", "The master-pass file is unreadable.", "Repair master-pass file access and rerun.")
	}
	vault, err := config.Load(strings.TrimRight(string(password), "\r\n"))
	if err != nil {
		return failedCheck("pending_recovery", "The encrypted vault cannot be inspected.", "Use the correct master-pass file and repair the vault before migration.")
	}
	if len(vault.PendingMutations) != 0 {
		return failedCheck("pending_recovery", "Pending inventory transactions require review.", "Publish the exact reviewed scopes or deliberately retain v1 until they are resolved.")
	}
	return passedCheck("pending_recovery", "No pending inventory transactions or recovery intent were found.")
}

func checkDivergence(facts synctransaction.Facts) MigrationCheck {
	if facts.Conflict != nil {
		return failedCheck("untracked_divergence", "A recorded local/remote synchronization conflict exists.", "Resolve the preserved conflict through reviewed pull, repair, or import before migration.")
	}
	return passedCheck("untracked_divergence", "No safely observable local/remote divergence record was found.")
}

func checkReleaseAsset(release Release) MigrationCheck {
	want := assetName()
	for _, asset := range release.Assets {
		if asset.Name == want {
			return passedCheck("platform_asset", "The target release contains the supported platform asset "+want+".")
		}
	}
	return failedCheck("platform_asset", "The target release does not declare the required platform asset "+want+".", "Install only after the release publishes the exact supported asset and digest.")
}

func checkRollbackReadiness() MigrationCheck {
	executable, err := executablePath()
	if err != nil {
		return failedCheck("rollback_readiness", "The current executable path cannot be determined.", "Run from a stable writable installation path.")
	}
	executable, err = evalSymlinks(executable)
	if err != nil {
		return failedCheck("rollback_readiness", "The current executable symlink cannot be resolved.", "Repair the installation path before migration.")
	}
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() {
		return failedCheck("rollback_readiness", "The current executable is not a readable regular file.", "Restore a regular v1 executable before migration.")
	}
	probe, err := os.CreateTemp(filepath.Dir(executable), "."+filepath.Base(executable)+".rollback-probe-*")
	if err != nil {
		return failedCheck("rollback_readiness", "The executable directory cannot stage an atomic replacement.", "Repair directory permissions or choose a writable installation path.")
	}
	probePath := probe.Name()
	closeErr := probe.Close()
	removeErr := os.Remove(probePath)
	if closeErr != nil || removeErr != nil {
		return failedCheck("rollback_readiness", "Rollback staging cleanup failed.", "Repair the installation directory before migration.")
	}
	return passedCheck("rollback_readiness", "The prior executable is readable and atomic replacement can be staged beside it.")
}
