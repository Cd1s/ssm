package ssh

import (
	"testing"

	"ssm/internal/config"
)

func TestAliasMissContractMatchesMapAndDoctor(t *testing.T) {
	vault := &config.Vault{}
	mapResult := runMapJob(vault, MapJob{RequestedAlias: "missing", Command: "true"}, false)
	doctorResult := Doctor(vault, "missing", false)

	if mapResult.Error != ErrCodeAliasNotFound || doctorResult.Error != ErrCodeAliasNotFound {
		t.Fatalf("map=%q doctor=%q", mapResult.Error, doctorResult.Error)
	}
	if mapResult.Message == "" || mapResult.Hint == "" || mapResult.Exit != ExitConnectionFailed || mapResult.Stage != "lookup" {
		t.Fatalf("map contract = %+v", mapResult)
	}
	if doctorResult.Message == "" || doctorResult.Hint == "" || doctorResult.Exit != ExitConnectionFailed || doctorResult.Stage != "lookup" {
		t.Fatalf("doctor contract = %+v", doctorResult)
	}
}

func TestCanonicalErrorTaxonomyValuesAreStable(t *testing.T) {
	want := map[string]string{
		"alias":       ErrCodeAliasNotFound,
		"arguments":   ErrCodeInvalidArgs,
		"request":     ErrCodeInvalidReq,
		"sync_pull":   ErrCodeSyncPull,
		"sync_push":   ErrCodeSyncPush,
		"host_key":    ErrCodeHostKey,
		"auth":        ErrCodeAuth,
		"interpreter": ErrCodeInterpreter,
		"syntax":      ErrCodeScriptSyntax,
		"remote":      ErrCodeRemote,
		"transfer":    ErrCodeTransfer,
	}
	for name, value := range want {
		if value == "" {
			t.Fatalf("%s code is empty", name)
		}
	}
}
