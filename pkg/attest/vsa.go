// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"fmt"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"
	spb "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

const (
	VsaPredicateType = "https://slsa.dev/verification_summary/v1"
	VsaVerifierId    = "https://github.com/slsa-framework/source-actions"
)

func CreateUnsignedSourceVsa(branch *models.Branch, commit *models.Commit, verifiedLevels slsa.SourceVerifiedLevels, policy string) (string, error) {
	return createUnsignedSourceVsaAllParams(branch, commit, verifiedLevels, policy, VsaVerifierId, "PASSED")
}

// createUnsignedSourceVsaAllParams generates a VSA
func createUnsignedSourceVsaAllParams(branch *models.Branch, commit *models.Commit, verifiedLevels slsa.SourceVerifiedLevels, policy, verifiedId, result string) (string, error) {
	// The attestation records a VCS locator
	resourceUri := fmt.Sprintf("git+%s", branch.Repository.GetHttpURL())
	vsaPred := &vpb.VerificationSummary{
		Verifier: &vpb.VerificationSummary_Verifier{
			Id: verifiedId,
		},
		TimeVerified:       timestamppb.Now(),
		ResourceUri:        resourceUri,
		Policy:             &vpb.VerificationSummary_Policy{Uri: policy},
		VerificationResult: result,
		VerifiedLevels:     slsa.ControlNamesToStrings(verifiedLevels),
	}

	predJson, err := protojson.Marshal(vsaPred)
	if err != nil {
		return "", err
	}

	branchAnnotation := map[string]any{slsa.SourceRefsAnnotation: []any{branch.FullRef()}}
	annotationStruct, err := structpb.NewStruct(branchAnnotation)
	if err != nil {
		return "", fmt.Errorf("creating struct from map: %w", err)
	}
	sub := []*spb.ResourceDescriptor{{
		Digest:      map[string]string{"gitCommit": commit.SHA},
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
		PredicateType: VsaPredicateType,
		Predicate:     &predPb,
	}

	statement, err := protojson.Marshal(&statementPb)
	if err != nil {
		return "", err
	}
	return string(statement), nil
}
