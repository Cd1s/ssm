package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	bundlev1 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	sigstorebundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	sigstoreverify "github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	ExpectedRepository = "Cd1s/ssm"
	ExpectedIssuer     = "https://token.actions.githubusercontent.com"
	ExpectedWorkflow   = ".github/workflows/release.yml"
	PredicateType      = "https://slsa.dev/provenance/v1"
	MaxBundleBytes     = 1 << 20

	repositoryURI = "https://github.com/" + ExpectedRepository
	statementType = "https://in-toto.io/Statement/v1"
)

var initialIdentityAcceptance = time.Date(2026, time.July, 30, 0, 0, 0, 0, time.UTC)

// Identity is one explicitly reviewed release-workflow identity form.
type Identity struct {
	Version   string
	SAN       string
	NotBefore time.Time
	NotAfter  time.Time
}

// Request binds verification to one exact supported release artifact.
type Request struct {
	AssetName string
	Version   string
	Digest    [sha256.Size]byte
}

// Options supplies the trust root and selects production or synthetic
// timestamp verification. Synthetic mode is used only with test-owned roots.
type Options struct {
	TrustedMaterial     root.TrustedMaterial
	RequireTransparency bool
	Identities          []Identity
}

// PublicGoodTrustedMaterial loads Sigstore public-good trust through its
// TUF-rooted client. Failure to load current trust material fails verification.
func PublicGoodTrustedMaterial(ctx context.Context) (root.TrustedMaterial, error) {
	client, err := tuf.New(tuf.DefaultOptions().WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("initialize Sigstore trust: %w", err)
	}
	material, err := root.GetTrustedRoot(client)
	if err != nil {
		return nil, fmt.Errorf("load Sigstore trust: %w", err)
	}
	return material, nil
}

// VerifyPublicGoodBundle verifies a production GitHub Actions attestation.
func VerifyPublicGoodBundle(ctx context.Context, data []byte, request Request) error {
	if _, err := parseBundle(data); err != nil {
		return err
	}
	material, err := PublicGoodTrustedMaterial(ctx)
	if err != nil {
		return err
	}
	return VerifyBundle(data, request, Options{
		TrustedMaterial:     material,
		RequireTransparency: true,
	})
}

// VerifyBundle cryptographically verifies one Sigstore bundle and then
// enforces SSM's exact subject, identity, and identity-rotation policy.
func VerifyBundle(data []byte, request Request, options Options) error {
	if len(data) == 0 {
		return errors.New("provenance bundle is empty")
	}
	if options.TrustedMaterial == nil {
		return errors.New("provenance trusted material is required")
	}
	identities := append([]Identity(nil), options.Identities...)
	if len(identities) == 0 {
		var err error
		identities, err = AcceptedIdentities(request.Version)
		if err != nil {
			return err
		}
	}

	entity, err := parseBundle(data)
	if err != nil {
		return err
	}
	version, err := entity.Version()
	if err != nil {
		return fmt.Errorf("read provenance bundle version: %w", err)
	}
	if version != "v0.3" {
		return fmt.Errorf("unsupported provenance bundle version %q", version)
	}

	verifierOptions := []sigstoreverify.VerifierOption{sigstoreverify.WithCurrentTime()}
	if options.RequireTransparency {
		verifierOptions = []sigstoreverify.VerifierOption{
			sigstoreverify.WithTransparencyLog(1),
			sigstoreverify.WithObserverTimestamps(1),
			sigstoreverify.WithSignedCertificateTimestamps(1),
		}
	}
	verifier, err := sigstoreverify.NewVerifier(options.TrustedMaterial, verifierOptions...)
	if err != nil {
		return fmt.Errorf("configure provenance verifier: %w", err)
	}

	policyOptions := make([]sigstoreverify.PolicyOption, 0, len(identities))
	for _, identity := range identities {
		sanMatcher, matcherErr := sigstoreverify.NewSANMatcher(identity.SAN, "")
		if matcherErr != nil {
			return fmt.Errorf("configure provenance identity %s: %w", identity.Version, matcherErr)
		}
		issuerMatcher, matcherErr := sigstoreverify.NewIssuerMatcher(ExpectedIssuer, "")
		if matcherErr != nil {
			return fmt.Errorf("configure provenance issuer: %w", matcherErr)
		}
		certificateIdentity, identityErr := sigstoreverify.NewCertificateIdentity(
			sanMatcher,
			issuerMatcher,
			certificate.Extensions{
				BuildSignerURI:      identity.SAN,
				RunnerEnvironment:   "github-hosted",
				SourceRepositoryURI: repositoryURI,
				BuildConfigURI:      identity.SAN,
			},
		)
		if identityErr != nil {
			return fmt.Errorf("configure provenance identity %s: %w", identity.Version, identityErr)
		}
		policyOptions = append(policyOptions, sigstoreverify.WithCertificateIdentity(certificateIdentity))
	}

	result, err := verifier.Verify(
		entity,
		sigstoreverify.NewPolicy(
			sigstoreverify.WithArtifactDigest("sha256", request.Digest[:]),
			policyOptions...,
		),
	)
	if err != nil {
		return fmt.Errorf("verify provenance: %w", err)
	}
	if result.Statement == nil {
		return errors.New("provenance has no in-toto statement")
	}
	if result.Statement.GetType() != statementType {
		return fmt.Errorf("provenance statement type %q is not accepted", result.Statement.GetType())
	}
	if result.Statement.GetPredicateType() != PredicateType {
		return fmt.Errorf("provenance predicate type %q is not accepted", result.Statement.GetPredicateType())
	}
	subjects := result.Statement.GetSubject()
	if len(subjects) != 1 {
		return fmt.Errorf("provenance has %d subjects, want exactly one", len(subjects))
	}
	subject := subjects[0]
	if subject.GetName() != request.AssetName {
		return fmt.Errorf("provenance subject name %q does not match %q", subject.GetName(), request.AssetName)
	}
	digests := subject.GetDigest()
	expectedDigest := hex.EncodeToString(request.Digest[:])
	if len(digests) != 1 || strings.ToLower(digests["sha256"]) != expectedDigest {
		return fmt.Errorf("provenance subject digest does not exactly match %s", expectedDigest)
	}
	if result.VerifiedIdentity == nil {
		return errors.New("provenance identity was not verified")
	}
	identity, ok := identityForSAN(identities, result.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName)
	if !ok {
		return errors.New("provenance identity is not in the reviewed rotation set")
	}
	if len(result.VerifiedTimestamps) == 0 {
		return errors.New("provenance has no verified timestamp")
	}
	for _, timestamp := range result.VerifiedTimestamps {
		if timestamp.Timestamp.Before(identity.NotBefore) {
			return fmt.Errorf("provenance identity %s is not yet valid", identity.Version)
		}
		if !identity.NotAfter.IsZero() && timestamp.Timestamp.After(identity.NotAfter) {
			return fmt.Errorf("provenance identity %s is expired", identity.Version)
		}
	}
	return nil
}

func parseBundle(data []byte) (*sigstorebundle.Bundle, error) {
	if len(data) > MaxBundleBytes {
		return nil, fmt.Errorf("provenance bundle exceeds %d-byte limit", MaxBundleBytes)
	}
	protobufBundle := &bundlev1.Bundle{}
	if err := protojson.Unmarshal(data, protobufBundle); err != nil {
		return nil, fmt.Errorf("parse provenance bundle: %w", err)
	}
	entity, err := sigstorebundle.NewBundle(protobufBundle, sigstorebundle.AllowCertificateChain())
	if err != nil {
		return nil, fmt.Errorf("validate provenance bundle: %w", err)
	}
	return entity, nil
}

// AcceptedIdentities returns the immutable current release identity set.
func AcceptedIdentities(version string) ([]Identity, error) {
	tag, err := releaseTag(version)
	if err != nil {
		return nil, err
	}
	base := repositoryURI + "/" + ExpectedWorkflow + "@"
	return []Identity{
		{
			Version:   "release-tag-v1",
			SAN:       base + "refs/tags/" + tag,
			NotBefore: initialIdentityAcceptance,
		},
	}, nil
}

func identityForSAN(identities []Identity, san string) (Identity, bool) {
	for _, identity := range identities {
		if identity.SAN == san {
			return identity, true
		}
	}
	return Identity{}, false
}

func releaseTag(version string) (string, error) {
	value := strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("release version %q is not accepted", version)
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return "", fmt.Errorf("release version %q is not accepted", version)
		}
		for index := range len(part) {
			if part[index] < '0' || part[index] > '9' {
				return "", fmt.Errorf("release version %q is not accepted", version)
			}
		}
	}
	return "v" + value, nil
}
