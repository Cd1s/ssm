// Package provenancefixture creates synthetic, test-owned keyless provenance.
// It is used by tests and cmd/verify only, never by the shipped ssm binary.
package provenancefixture

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"time"

	bundlev1 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	commonv1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	dssev1 "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"google.golang.org/protobuf/encoding/protojson"

	"ssm/internal/provenance"
)

const payloadType = "application/vnd.in-toto+json"

// Claims contains the signed identity and subject inputs for a synthetic bundle.
type Claims struct {
	Repository               string
	Workflow                 string
	Ref                      string
	Issuer                   string
	Runner                   string
	PredicateType            string
	SubjectName              string
	SubjectDigest            [sha256.Size]byte
	AdditionalSubjectNames   []string
	AdditionalDigestValues   map[string]string
	ExcludeSHA256SubjectHash bool
	NotBefore                time.Time
	NotAfter                 time.Time
}

// Fixture contains a serialized Sigstore bundle and its independent test root.
type Fixture struct {
	Bundle          []byte
	TrustedMaterial root.TrustedMaterial
	TrustedRootDER  []byte
}

// DefaultClaims returns the currently accepted release identity for a tag.
func DefaultClaims(asset, version string, payload []byte) (Claims, error) {
	_, err := provenance.AcceptedIdentities(version)
	if err != nil {
		return Claims{}, err
	}
	now := time.Now()
	return Claims{
		Repository:    provenance.ExpectedRepository,
		Workflow:      provenance.ExpectedWorkflow,
		Ref:           "refs/tags/" + version,
		Issuer:        provenance.ExpectedIssuer,
		Runner:        "github-hosted",
		PredicateType: provenance.PredicateType,
		SubjectName:   asset,
		SubjectDigest: sha256.Sum256(payload),
		NotBefore:     now.Add(-time.Minute),
		NotAfter:      now.Add(time.Minute),
	}, nil
}

// Generate creates a DSSE in-toto bundle signed by a short-lived test
// certificate rooted in newly generated test-owned trust material.
func Generate(claims Claims) (Fixture, error) {
	signerURI := fmt.Sprintf(
		"https://github.com/%s/%s@%s",
		claims.Repository,
		claims.Workflow,
		claims.Ref,
	)
	identity, err := url.Parse(signerURI)
	if err != nil {
		return Fixture{}, fmt.Errorf("parse synthetic identity: %w", err)
	}

	rootCertificate, rootKey, err := newRootCertificate()
	if err != nil {
		return Fixture{}, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Fixture{}, fmt.Errorf("generate synthetic leaf key: %w", err)
	}
	leafCertificate, err := newLeafCertificate(rootCertificate, rootKey, leafKey, identity, claims)
	if err != nil {
		return Fixture{}, err
	}

	subjectDigest := make(map[string]string, len(claims.AdditionalDigestValues)+1)
	if !claims.ExcludeSHA256SubjectHash {
		subjectDigest["sha256"] = fmt.Sprintf("%x", claims.SubjectDigest)
	}
	for algorithm, value := range claims.AdditionalDigestValues {
		subjectDigest[algorithm] = value
	}
	subjects := []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	}{{
		Name:   claims.SubjectName,
		Digest: subjectDigest,
	}}
	for _, name := range claims.AdditionalSubjectNames {
		subjects = append(subjects, struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		}{
			Name: name,
			Digest: map[string]string{
				"sha256": fmt.Sprintf("%x", claims.SubjectDigest),
			},
		})
	}

	statement, err := json.Marshal(struct {
		Type    string `json:"_type"`
		Subject []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		PredicateType string         `json:"predicateType"`
		Predicate     map[string]any `json:"predicate"`
	}{
		Type:          "https://in-toto.io/Statement/v1",
		Subject:       subjects,
		PredicateType: claims.PredicateType,
		Predicate:     map[string]any{"buildDefinition": map[string]any{"buildType": "synthetic-test-owned"}},
	})
	if err != nil {
		return Fixture{}, fmt.Errorf("marshal synthetic statement: %w", err)
	}
	payload := dssePAE(payloadType, statement)
	payloadDigest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, leafKey, payloadDigest[:])
	if err != nil {
		return Fixture{}, fmt.Errorf("sign synthetic statement: %w", err)
	}

	protobufBundle := &bundlev1.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &bundlev1.VerificationMaterial{
			Content: &bundlev1.VerificationMaterial_Certificate{
				Certificate: &commonv1.X509Certificate{RawBytes: leafCertificate.Raw},
			},
		},
		Content: &bundlev1.Bundle_DsseEnvelope{
			DsseEnvelope: &dssev1.Envelope{
				Payload:     statement,
				PayloadType: payloadType,
				Signatures:  []*dssev1.Signature{{Sig: signature}},
			},
		},
	}
	bundleJSON, err := protojson.Marshal(protobufBundle)
	if err != nil {
		return Fixture{}, fmt.Errorf("marshal synthetic bundle: %w", err)
	}
	material := &trustedMaterial{
		certificateAuthority: &root.FulcioCertificateAuthority{
			Root:                rootCertificate,
			ValidityPeriodStart: rootCertificate.NotBefore,
			ValidityPeriodEnd:   rootCertificate.NotAfter,
		},
	}
	return Fixture{
		Bundle:          bundleJSON,
		TrustedMaterial: material,
		TrustedRootDER:  append([]byte(nil), rootCertificate.Raw...),
	}, nil
}

type trustedMaterial struct {
	root.BaseTrustedMaterial
	certificateAuthority *root.FulcioCertificateAuthority
}

func (material *trustedMaterial) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return []root.CertificateAuthority{material.certificateAuthority}
}

func newRootCertificate() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate synthetic root key: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SSM synthetic provenance root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certificate, err := createCertificate(template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create synthetic root certificate: %w", err)
	}
	return certificate, key, nil
}

func newLeafCertificate(
	rootCertificate *x509.Certificate,
	rootKey crypto.Signer,
	leafKey *ecdsa.PrivateKey,
	identity *url.URL,
	claims Claims,
) (*x509.Certificate, error) {
	extraExtensions := make([]pkix.Extension, 0, 5)
	for _, extension := range []struct {
		oid   asn1.ObjectIdentifier
		value string
	}{
		{certificate.OIDIssuerV2, claims.Issuer},
		{certificate.OIDBuildSignerURI, identity.String()},
		{certificate.OIDRunnerEnvironment, claims.Runner},
		{certificate.OIDSourceRepositoryURI, "https://github.com/" + claims.Repository},
		{certificate.OIDBuildConfigURI, identity.String()},
	} {
		value, err := asn1.Marshal(extension.value)
		if err != nil {
			return nil, fmt.Errorf("marshal synthetic certificate extension: %w", err)
		}
		extraExtensions = append(extraExtensions, pkix.Extension{Id: extension.oid, Value: value})
	}
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "SSM synthetic keyless builder"},
		URIs:            []*url.URL{identity},
		NotBefore:       claims.NotBefore,
		NotAfter:        claims.NotAfter,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: extraExtensions,
	}
	certificate, err := createCertificate(template, rootCertificate, &leafKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("create synthetic leaf certificate: %w", err)
	}
	return certificate, nil
}

func createCertificate(
	template, parent *x509.Certificate,
	publicKey crypto.PublicKey,
	signer crypto.Signer,
) (*x509.Certificate, error) {
	raw, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(raw)
}

func dssePAE(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	return append([]byte(prefix), payload...)
}
