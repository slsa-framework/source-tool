package attest

import (
	"github.com/carabiner-dev/bnd/pkg/bnd"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type VerificationOptions struct {
	ExpectedIssuer string
	ExpectedSan    string
}

// TODO: Update ExpectedSan to support regex so we can get the branches/tags we really think
// folks should be using (they won't all run from main).
var DefaultVerifierOptions = VerificationOptions{
	ExpectedIssuer: "https://token.actions.githubusercontent.com",
	ExpectedSan:    "https://github.com/slsa-framework/slsa-source-poc/.github/workflows/create_slsa_source_vsa.yml@refs/heads/main",
}

func Verify(data string, options VerificationOptions) (*verify.VerificationResult, error) {
	// TODO: There's more for us to do here... but what?
	// Maybe check to make sure it's from the identity we expect (the workflow?)
	verifier := bnd.NewVerifier()
	verifier.Options.ExpectedIssuer = options.ExpectedIssuer
	verifier.Options.ExpectedSan = options.ExpectedSan
	vr, err := verifier.VerifyInlineBundle([]byte(data))
	if err != nil {
		return nil, err
	}
	return vr, nil
}
