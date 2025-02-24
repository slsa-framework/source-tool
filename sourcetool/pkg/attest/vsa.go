package attest

import (
	"fmt"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"
	spb "github.com/in-toto/attestation/go/v1"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/gh_control"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func CreateUnsignedSourceVsa(gh_connection *gh_control.GitHubConnection, commit string, sourceLevel string, policy string) (string, error) {
	resourceUri := fmt.Sprintf("git+%s", gh_connection.GetRepoUri())
	vsaPred := &vpb.VerificationSummary{
		Verifier: &vpb.VerificationSummary_Verifier{
			Id: "https://github.com/slsa-framework/slsa-source-poc"},
		TimeVerified:       timestamppb.Now(),
		ResourceUri:        resourceUri,
		Policy:             &vpb.VerificationSummary_Policy{Uri: policy},
		VerificationResult: "PASSED",
		VerifiedLevels:     []string{sourceLevel},
	}

	predJson, err := protojson.Marshal(vsaPred)
	if err != nil {
		return "", err
	}

	branchAnnotation := map[string]any{"source_branches": []any{gh_connection.GetFullBranch()}}
	annotationStruct, err := structpb.NewStruct(branchAnnotation)
	if err != nil {
		return "", fmt.Errorf("creating struct from map: %w", err)
	}
	sub := []*spb.ResourceDescriptor{{
		Digest:      map[string]string{"gitCommit": commit},
		Annotations: annotationStruct,
	}}

	var predPb structpb.Struct
	err = protojson.Unmarshal(predJson, &predPb)
	if err != nil {
		return "", err
	}

	statementPb := spb.Statement{
		Type:          spb.StatementTypeUri,
		Subject:       sub,
		PredicateType: "https://slsa.dev/verification_summary/v1",
		Predicate:     &predPb,
	}

	statement, err := protojson.Marshal(&statementPb)
	if err != nil {
		return "", err
	}
	return string(statement), nil
}
