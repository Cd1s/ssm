package ssh

import (
	"testing"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

func TestAliasMissContractMatchesMapAndDoctor(t *testing.T) {
	vault := &config.Vault{}
	mapResult := runMapJob(vault, MapJob{RequestedAlias: "missing", Command: "true"}, false)
	doctorResult := Doctor(vault, "missing", false)

	if mapResult.Error != machinecontract.CodeAliasNotFound || doctorResult.Error != machinecontract.CodeAliasNotFound {
		t.Fatalf("map=%q doctor=%q", mapResult.Error, doctorResult.Error)
	}
	if mapResult.Message == "" || mapResult.Hint == "" || mapResult.Exit != machinecontract.ExitConnectionFailed || mapResult.Stage != "lookup" {
		t.Fatalf("map contract = %+v", mapResult)
	}
	if doctorResult.Message == "" || doctorResult.Hint == "" || doctorResult.Exit != machinecontract.ExitConnectionFailed || doctorResult.Stage != "lookup" {
		t.Fatalf("doctor contract = %+v", doctorResult)
	}
	if len(doctorResult.Candidates) != 0 {
		t.Fatalf("unexpected candidates = %v", doctorResult.Candidates)
	}
}

func TestDoctorSuggestsButNeverSelectsAmbiguousAlias(t *testing.T) {
	vault := &config.Vault{Connections: []config.Connection{{Name: "web-prod-a"}, {Name: "web-prod-b"}}}
	report := Doctor(vault, "web-prod", false)
	if report.OK || report.ResolvedAlias != "web-prod" || len(report.Candidates) != 2 {
		t.Fatalf("report = %+v", report)
	}
	if report.Check != nil {
		t.Fatal("doctor connected after an ambiguous alias suggestion")
	}
}

func TestDoctorReportsPersistedMergeConflictWithoutSecrets(t *testing.T) {
	setTestHome(t, t.TempDir())
	report := config.MergeReport{Conflicts: []config.MergeConflict{{Name: "prod", Kind: "alias", Winner: "remote"}}}
	if err := config.SaveMergeReport(report); err != nil {
		t.Fatal(err)
	}
	doctor := Doctor(&config.Vault{}, "", false)
	if len(doctor.MergeReport.Conflicts) != 1 || doctor.MergeReport.Conflicts[0].Name != "prod" {
		t.Fatalf("doctor = %+v", doctor)
	}
}

func TestCanonicalErrorTaxonomyValuesAreStable(t *testing.T) {
	want := map[string]string{
		"alias":       machinecontract.CodeAliasNotFound,
		"arguments":   machinecontract.CodeInvalidArgs,
		"request":     machinecontract.CodeInvalidRequest,
		"sync_pull":   machinecontract.CodeSyncPull,
		"sync_push":   machinecontract.CodeSyncPush,
		"host_key":    machinecontract.CodeHostKey,
		"auth":        machinecontract.CodeAuth,
		"interpreter": machinecontract.CodeInterpreter,
		"syntax":      machinecontract.CodeScriptSyntax,
		"remote":      machinecontract.CodeRemote,
		"transfer":    machinecontract.CodeTransfer,
	}
	for name, value := range want {
		if value == "" {
			t.Fatalf("%s code is empty", name)
		}
	}
}
