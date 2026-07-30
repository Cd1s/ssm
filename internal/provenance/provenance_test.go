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
