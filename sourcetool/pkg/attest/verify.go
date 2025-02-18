package attest

import (
	"github.com/carabiner-dev/bnd/pkg/bnd"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

func Verify(data string) (*verify.VerificationResult, error) {
	// TODO: There's more for us to do here... but what?
	// Maybe check to make sure it's from the identity we expect (the workflow?)
	verifier := bnd.NewVerifier()
	vr, err := verifier.VerifyInlineBundle([]byte(data))
	if err != nil {
		return nil, err
	}
	return vr, nil
}
