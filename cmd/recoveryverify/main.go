// Command recoveryverify is a temporary, exact-purpose verifier for the v2.0.1
// release recovery. It is removed with the recovery workflow after publication.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"ssm/internal/provenance"
)

const (
	expectedCommit = "379ce2d91825a4d651117e13ec59d9c9baa686f5"
	expectedRun    = "https://github.com/Cd1s/ssm/actions/runs/31057964128/attempts/1"
	expectedRef    = "refs/tags/v2.0.1"
)

type envelope struct {
	DSSEEnvelope struct {
		Payload string `json:"payload"`
	} `json:"dsseEnvelope"`
}

type statement struct {
	Predicate struct {
		BuildDefinition struct {
			BuildType          string `json:"buildType"`
			ExternalParameters struct {
				Workflow struct {
					Ref        string `json:"ref"`
					Repository string `json:"repository"`
					Path       string `json:"path"`
				} `json:"workflow"`
			} `json:"externalParameters"`
			ResolvedDependencies []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
			Metadata struct {
				InvocationID string `json:"invocationId"`
			} `json:"metadata"`
		} `json:"runDetails"`
	} `json:"predicate"`
}

func main() {
	if len(os.Args) != 3 {
		fatal(errors.New("usage: recoveryverify ASSET BUNDLE"))
	}
	asset, err := os.ReadFile(os.Args[1]) //nolint:gosec // fixed recovery workflow supplies runner-temporary artifact paths
	if err != nil {
		fatal(fmt.Errorf("read asset: %w", err))
	}
	bundle, err := os.ReadFile(os.Args[2]) //nolint:gosec // fixed recovery workflow supplies runner-temporary bundle paths
	if err != nil {
		fatal(fmt.Errorf("read bundle: %w", err))
	}
	digest := sha256.Sum256(asset)
	if err := provenance.VerifyPublicGoodBundle(context.Background(), bundle, provenance.Request{
		AssetName: baseName(os.Args[1]), Version: "v2.0.1", Digest: digest,
	}); err != nil {
		fatal(err)
	}
	if err := verifyPredicate(bundle); err != nil {
		fatal(err)
	}
}

func verifyPredicate(bundle []byte) error {
	var outer envelope
	if err := json.Unmarshal(bundle, &outer); err != nil {
		return fmt.Errorf("decode bundle envelope: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(outer.DSSEEnvelope.Payload)
	if err != nil {
		return fmt.Errorf("decode signed statement: %w", err)
	}
	var s statement
	if err := json.Unmarshal(payload, &s); err != nil {
		return fmt.Errorf("decode signed predicate: %w", err)
	}
	b := s.Predicate.BuildDefinition
	w := b.ExternalParameters.Workflow
	r := s.Predicate.RunDetails
	if b.BuildType != "https://actions.github.io/buildtypes/workflow/v1" ||
		w.Ref != expectedRef || w.Repository != "https://github.com/Cd1s/ssm" || w.Path != ".github/workflows/release.yml" ||
		r.Builder.ID != "https://github.com/Cd1s/ssm/.github/workflows/release.yml@refs/tags/v2.0.1" || r.Metadata.InvocationID != expectedRun ||
		len(b.ResolvedDependencies) != 1 || b.ResolvedDependencies[0].URI != "git+https://github.com/Cd1s/ssm@refs/tags/v2.0.1" ||
		len(b.ResolvedDependencies[0].Digest) != 1 || b.ResolvedDependencies[0].Digest["gitCommit"] != expectedCommit {
		return errors.New("signed provenance predicate is not the exact authorized v2.0.1 build")
	}
	return nil
}

func baseName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	return path
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
