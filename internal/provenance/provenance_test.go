package provenance_test

import (
	"bytes"
	"strings"
	"testing"

	"ssm/internal/provenance"
	"ssm/internal/provenancefixture"
)

func TestOversizedBundleIsRejectedBeforeParsing(t *testing.T) {
	payload := []byte("test-owned release asset")
	claims, err := provenancefixture.DefaultClaims("ssm-linux-amd64", "v9.9.9", payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		t.Fatal(err)
	}
	bundle := append([]byte(nil), fixture.Bundle...)
	bundle = append(bundle, bytes.Repeat([]byte(" "), provenance.MaxBundleBytes+1-len(bundle))...)

	err = provenance.VerifyBundle(bundle, provenance.Request{
		AssetName: "ssm-linux-amd64",
		Version:   "v9.9.9",
		Digest:    claims.SubjectDigest,
	}, provenance.Options{TrustedMaterial: fixture.TrustedMaterial})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized provenance error = %v, want size rejection", err)
	}
}

func TestSelectedReleaseTagBindsExactWorkflowIdentity(t *testing.T) {
	const asset = "ssm-linux-amd64"
	payload := []byte("exact selected-tag provenance")
	for _, test := range []struct {
		name           string
		selectedTag    string
		certificateTag string
		wantSuccess    bool
	}{
		{
			name:           "unprefixed exact form",
			selectedTag:    "1.2.3",
			certificateTag: "1.2.3",
			wantSuccess:    true,
		},
		{
			name:           "prefixed exact form",
			selectedTag:    "v1.2.3",
			certificateTag: "v1.2.3",
			wantSuccess:    true,
		},
		{
			name:           "unprefixed selection cannot use prefixed provenance",
			selectedTag:    "1.2.3",
			certificateTag: "v1.2.3",
		},
		{
			name:           "prefixed selection cannot use unprefixed provenance",
			selectedTag:    "v1.2.3",
			certificateTag: "1.2.3",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims, err := provenancefixture.DefaultClaims(asset, test.selectedTag, payload)
			if err != nil {
				t.Fatal(err)
			}
			claims.Ref = "refs/tags/" + test.certificateTag
			fixture, err := provenancefixture.Generate(claims)
			if err != nil {
				t.Fatal(err)
			}
			err = provenance.VerifyBundle(fixture.Bundle, provenance.Request{
				AssetName: asset,
				Version:   test.selectedTag,
				Digest:    claims.SubjectDigest,
			}, provenance.Options{TrustedMaterial: fixture.TrustedMaterial})
			if test.wantSuccess && err != nil {
				t.Fatalf("exact selected tag was rejected: %v", err)
			}
			if !test.wantSuccess && err == nil {
				t.Fatal("distinct Git tag was accepted as the selected provenance identity")
			}
		})
	}
}
