package testsupport

import (
	"fmt"

	spb "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

type MockVerifier struct{}

func NewMockVerifier() *MockVerifier {
	return &MockVerifier{}
}

func (mv *MockVerifier) Verify(data string) (*verify.VerificationResult, error) {
	var statement spb.Statement
	err := protojson.Unmarshal([]byte(data), &statement)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling %s into statement", data)
	}

	var vr verify.VerificationResult
	vr.MediaType = "mockverifiermediatype"
	vr.Statement = &statement
	return &vr, nil
}
