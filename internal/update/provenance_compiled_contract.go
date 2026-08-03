//go:build compiled_cli_contract

package update

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/root"

	"ssm/internal/provenance"
)

const compiledContractProvenanceRootEnv = "SSM_TEST_COMPILED_PROVENANCE_ROOT"

type compiledContractTrustedMaterial struct {
	root.BaseTrustedMaterial
	certificateAuthority *root.FulcioCertificateAuthority
}

func (material *compiledContractTrustedMaterial) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return []root.CertificateAuthority{material.certificateAuthority}
}

func init() {
	encodedRoot := os.Getenv(compiledContractProvenanceRootEnv)
	if encodedRoot == "" {
		return
	}
	rootDER, decodeErr := base64.StdEncoding.DecodeString(encodedRoot)
	var rootCertificate *x509.Certificate
	var parseErr error
	if decodeErr == nil {
		rootCertificate, parseErr = x509.ParseCertificate(rootDER)
	}
	verifyProvenance = func(
		_ context.Context,
		bundle []byte,
		request provenance.Request,
	) error {
		if decodeErr != nil {
			return fmt.Errorf("decode compiled-contract provenance root: %w", decodeErr)
		}
		if parseErr != nil {
			return fmt.Errorf("parse compiled-contract provenance root: %w", parseErr)
		}
		material := &compiledContractTrustedMaterial{
			certificateAuthority: &root.FulcioCertificateAuthority{
				Root:                rootCertificate,
				ValidityPeriodStart: rootCertificate.NotBefore,
				ValidityPeriodEnd:   rootCertificate.NotAfter,
			},
		}
		return provenance.VerifyBundle(bundle, request, provenance.Options{
			TrustedMaterial: material,
		})
	}
}
