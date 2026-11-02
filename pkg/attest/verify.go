// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/policylabs/attestation"
	"github.com/policylabs/signer"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/policylabs/signer/options"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type VerificationOptions struct {
	// ExpectedIssuer is the OIDC issuer of the certificates signing the
	// attestations. It is required, no identity is accepted without it.
	ExpectedIssuer string

	// ExpectedSan pins the signer identity to an exact subject alternative
	// name. When set, ExpectedSanPrefix is ignored.
	ExpectedSan string

	// ExpectedSanPrefix accepts any signer identity starting with the
	// prefix. Users pin the provenance workflow to different tags and
	// digests, so the git reference ending its identity varies.
	ExpectedSanPrefix string

	// AlternateSans lists additional signer identities accepted (exactly)
	// when verifying attestations. It carries the identities of the
	// workflows that signed attestations before the actions moved to their
	// current repository.
	//
	// See https://github.com/slsa-framework/source-tool/issues/255
	AlternateSans []string
}

const (
	// ExpectedIssuer is the OIDC issuer found in the sigstore bundles
	ExpectedIssuer = "https://token.actions.githubusercontent.com"

	// ExpectedSanPrefix is the prefix of the identity of the reusable workflow
	// signing the provenance and VSAs. The full identity ends with the git
	// reference the workflow was pinned to, which varies across users and
	// releases.
	ExpectedSanPrefix = "https://github.com/slsa-framework/actions/.github/workflows/compute_slsa_source.yml@"

	// LegacySourceActionsSan is the identity of the workflow that signed
	// attestations while the actions lived in slsa-framework/source-actions.
	LegacySourceActionsSan = "https://github.com/slsa-framework/source-actions/.github/workflows/compute_slsa_source.yml@refs/heads/main"

	// LegacyPocSan is the identity of the workflow that signed attestations
	// before the actions were split out of the slsa-source-poc repository.
	//
	// See https://github.com/slsa-framework/source-tool/issues/255
	LegacyPocSan = "https://github.com/slsa-framework/slsa-source-poc/.github/workflows/compute_slsa_source.yml@refs/heads/main"
)

// DefaultVerifierOptions accept attestations signed by the current provenance
// workflow, whatever reference it is pinned to, and by the legacy workflows
// while repositories still carry attestations signed by them.
var DefaultVerifierOptions = VerificationOptions{
	ExpectedIssuer:    ExpectedIssuer,
	ExpectedSanPrefix: ExpectedSanPrefix,
	AlternateSans:     []string{LegacySourceActionsSan, LegacyPocSan},
}

// expectedIdentities returns the signer identities accepted by the options.
// Without an issuer no identity is accepted.
func (vo *VerificationOptions) expectedIdentities() []*sapi.Identity {
	if vo.ExpectedIssuer == "" {
		return nil
	}

	ids := []*sapi.Identity{}
	switch {
	case vo.ExpectedSan != "":
		ids = append(ids, exactIdentity(vo.ExpectedIssuer, vo.ExpectedSan))
	case vo.ExpectedSanPrefix != "":
		ids = append(ids, &sapi.Identity{
			Sigstore: &sapi.IdentitySigstore{
				Issuer: vo.ExpectedIssuer,
				IdentityMatch: &sapi.StringMatcher{
					Kind: &sapi.StringMatcher_Prefix{Prefix: vo.ExpectedSanPrefix},
				},
			},
		})
	}

	for _, san := range vo.AlternateSans {
		if san == "" {
			continue
		}
		ids = append(ids, exactIdentity(vo.ExpectedIssuer, san))
	}
	return ids
}

// exactIdentity builds a sigstore identity matching the issuer and SAN exactly
func exactIdentity(issuer, san string) *sapi.Identity {
	return &sapi.Identity{
		Sigstore: &sapi.IdentitySigstore{
			Issuer:   issuer,
			Identity: san,
		},
	}
}

// String describes the accepted identities for error messages
func (vo *VerificationOptions) String() string {
	sans := []string{}
	switch {
	case vo.ExpectedSan != "":
		sans = append(sans, vo.ExpectedSan)
	case vo.ExpectedSanPrefix != "":
		sans = append(sans, vo.ExpectedSanPrefix+"*")
	}
	for _, san := range vo.AlternateSans {
		if san != "" {
			sans = append(sans, san)
		}
	}
	return fmt.Sprintf("issuer %q identities %q", vo.ExpectedIssuer, sans)
}

type Verifier interface {
	Verify(data string) (*verify.VerificationResult, error)

	// VerifyEnvelope checks the cryptographic signature of a parsed
	// attestation envelope and ensures the signer matches the expected
	// identity. Envelopes that carry no verifiable signature (eg bare
	// statements) must return an error.
	VerifyEnvelope(env attestation.Envelope) error
}

type BndVerifier struct {
	Options VerificationOptions
}

// Verify checks a signed bundle, ensuring the signer matches the expected
// identity. Note that this method does not accept the alternate identities,
// only the expected SAN (or prefix) is checked.
func (bv *BndVerifier) Verify(data string) (*verify.VerificationResult, error) {
	verifier := signer.NewVerifier()

	identityOpts := []options.VerificationOptFunc{
		options.WithExpectedIdentity(bv.Options.ExpectedIssuer, bv.Options.ExpectedSan),
	}
	if bv.Options.ExpectedSan == "" && bv.Options.ExpectedSanPrefix != "" {
		identityOpts = append(identityOpts, options.WithExpectedIdentityRegex(
			"", "^"+regexp.QuoteMeta(bv.Options.ExpectedSanPrefix),
		))
	}

	// Verify the signed bundle
	vr, err := verifier.VerifyInlineBundle([]byte(data), identityOpts...)
	if err != nil {
		return nil, err
	}
	return vr, nil
}

// VerifyEnvelope verifies the signature of an attestation envelope fetched
// by the collector and checks that the signer matches one of the expected
// identities.
func (bv *BndVerifier) VerifyEnvelope(env attestation.Envelope) error {
	if env == nil {
		return errors.New("unable to verify, envelope is nil")
	}

	// Verify the envelope signatures. Note that this call only checks the
	// cryptographic integrity of the envelope, identity verification is
	// done below by matching the verification data.
	if err := env.Verify(); err != nil {
		return fmt.Errorf("verifying envelope signature: %w", err)
	}

	// Bare statements and unsigned envelopes return a nil verification (or
	// one that is not verified). Reject them, we only trust signed bundles.
	verification := env.GetVerification()
	if verification == nil || !verification.GetVerified() {
		return errors.New("envelope carries no verified signature")
	}

	// Check the signer identity against the expected identities
	for _, id := range bv.Options.expectedIdentities() {
		if verification.MatchesIdentity(id) {
			return nil
		}
	}

	return fmt.Errorf(
		"envelope signer does not match any expected identity (%s)", bv.Options.String(),
	)
}

func NewBndVerifier(opts VerificationOptions) *BndVerifier {
	return &BndVerifier{Options: opts}
}

func GetDefaultVerifier() Verifier {
	return NewBndVerifier(DefaultVerifierOptions)
}
