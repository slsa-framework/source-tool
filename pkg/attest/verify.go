// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/signer"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/options"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type VerificationOptions struct {
	ExpectedIssuer string
	ExpectedSan    string

	// AlternateSans lists additional signer identities accepted when
	// verifying attestations. It carries the pre-rename workflow identity
	// while repositories still have attestations signed with it.
	//
	// See https://github.com/slsa-framework/source-tool/issues/255
	AlternateSans []string
}

const (
	// ExpectedIssuer is the OIDC issuer found in the sigstore bundles
	ExpectedIssuer = "https://token.actions.githubusercontent.com"

	// Expected SAN is the expected identity of the workflow signing the
	// provenance and VSAs.
	ExpectedSan = "https://github.com/slsa-framework/source-actions/.github/workflows/compute_slsa_source.yml@refs/heads/main"

	// OldExpectedSan is the old singer identity before splitting out the actions to their own repo
	// this constant is part of a compatibility hack that should be reverted once the latests attestations
	// of the repos are signed with the new identity.
	//
	// See https://github.com/slsa-framework/source-tool/issues/255
	OldExpectedSan = "https://github.com/slsa-framework/slsa-source-poc/.github/workflows/compute_slsa_source.yml@refs/heads/main"
)

// TODO: Update ExpectedSan to support regex so we can get the branches/tags we really think
// folks should be using (they won't all run from main).
var DefaultVerifierOptions = VerificationOptions{
	ExpectedIssuer: ExpectedIssuer,
	ExpectedSan:    ExpectedSan,
	AlternateSans:  []string{OldExpectedSan},
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

func (bv *BndVerifier) Verify(data string) (*verify.VerificationResult, error) {
	// TODO: There's more for us to do here... but what?
	// Maybe check to make sure it's from the identity we expect (the workflow?)
	verifier := signer.NewVerifier()

	// Verify the signed bundle
	vr, err := verifier.VerifyInlineBundle(
		[]byte(data),
		options.WithExpectedIdentity(
			bv.Options.ExpectedIssuer, bv.Options.ExpectedSan,
		),
	)
	if err != nil {
		return nil, err
	}
	return vr, nil
}

// VerifyEnvelope verifies the signature of an attestation envelope fetched
// by the collector and checks that the signer matches the expected identity
// (issuer + SAN) or one of the accepted alternate identities.
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

	// Check the signer identity against the expected SANs
	for _, san := range append([]string{bv.Options.ExpectedSan}, bv.Options.AlternateSans...) {
		if san == "" {
			continue
		}
		if verification.MatchesIdentity(&sapi.Identity{
			Sigstore: &sapi.IdentitySigstore{
				Issuer:   bv.Options.ExpectedIssuer,
				Identity: san,
			},
		}) {
			return nil
		}
	}

	return fmt.Errorf(
		"envelope signer does not match the expected identity (issuer %q identity %q)",
		bv.Options.ExpectedIssuer, bv.Options.ExpectedSan,
	)
}

func NewBndVerifier(opts VerificationOptions) *BndVerifier {
	return &BndVerifier{Options: opts}
}

func GetDefaultVerifier() Verifier {
	return NewBndVerifier(DefaultVerifierOptions)
}
