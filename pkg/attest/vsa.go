package attest

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"
	spb "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slsa-framework/slsa-source-poc/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/pkg/slsa"
)

const (
	VsaPredicateType = "https://slsa.dev/verification_summary/v1"
	VsaVerifierId    = "https://github.com/slsa-framework/slsa-source-poc"
)

func CreateUnsignedSourceVsa(repoUri, ref, commit string, verifiedLevels slsa.SourceVerifiedLevels, policy string) (string, error) {
	return createUnsignedSourceVsaAllParams(repoUri, ref, commit, verifiedLevels, policy, VsaVerifierId, "PASSED")
}

func createUnsignedSourceVsaAllParams(repoUri, ref, commit string, verifiedLevels slsa.SourceVerifiedLevels, policy, verifiedId, result string) (string, error) {
	resourceUri := fmt.Sprintf("git+%s", repoUri)
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

	branchAnnotation := map[string]any{slsa.SourceRefsAnnotation: []any{ref}}
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
		PredicateType: VsaPredicateType,
		Predicate:     &predPb,
	}

	statement, err := protojson.Marshal(&statementPb)
	if err != nil {
		return "", err
	}
	return string(statement), nil
}

// Gets a VSA for the commit from git notes.
func GetVsa(ctx context.Context, ghc *ghcontrol.GitHubConnection, verifier Verifier, commit, ref string) (*spb.Statement, *vpb.VerificationSummary, error) {
	notes, err := ghc.GetNotesForCommit(ctx, commit)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching commit note: %w", err)
	}

	if notes == "" {
		Debugf("didn't find notes for commit %s", commit)
		return nil, nil, nil
	}

	return getVsaFromReader(NewBundleReader(bufio.NewReader(strings.NewReader(notes)), verifier), commit, ref, ghc.GetRepoUri())
}

func getVsaPred(statement *spb.Statement) (*vpb.VerificationSummary, error) {
	predJson, err := protojson.Marshal(statement.GetPredicate())
	if err != nil {
		return nil, err
	}

	var predStruct vpb.VerificationSummary
	// Using regular json.Unmarshal because this is just a regular struct.
	err = protojson.Unmarshal(predJson, &predStruct)
	if err != nil {
		return nil, err
	}
	return &predStruct, nil
}

func MatchesTypeCommitAndRef(predicateType, commit, targetRef string) StatementMatcher {
	return func(statement *spb.Statement) bool {
		if statement.GetPredicateType() != predicateType {
			Debugf("statement predicate type (%s) doesn't match %s", statement.GetPredicateType(), predicateType)
			return false
		}
		refs, err := GetSourceRefsForCommit(statement, commit)
		if err != nil {
			Debugf("statement \n%v\n does not match commit %s: %v", StatementToString(statement), commit, err)
			return false
		}
		for _, ref := range refs {
			if targetRef == ghcontrol.AnyReference || ref == targetRef {
				Debugf("statement \n%v\n matches commit '%s' on ref '%s'", StatementToString(statement), commit, targetRef)
				return true
			}
		}
		Debugf("source_refs (%v) in VSA does not contain %s", refs, targetRef)
		return false
	}
}

func getVsaFromReader(reader *BundleReader, commit, ref, repoUri string) (*spb.Statement, *vpb.VerificationSummary, error) {
	// We want to return the first valid VSA.
	// We should follow instructions from
	// https://slsa.dev/spec/draft/verifying-source#how-to-verify-slsa-a-source-revision

	for {
		stmt, err := reader.ReadStatement(MatchesTypeCommitAndRef(VsaPredicateType, commit, ref))
		if err != nil {
			// Ignore errors, we want to check all the lines.
			Debugf("error while processing line: %v", err)
			continue
		}

		if stmt == nil {
			// No statements left.
			break
		}

		vsaPred, err := getVsaPred(stmt)
		if err != nil {
			return nil, nil, err
		}

		// Is it the verifier ID we expect?
		if vsaPred.GetVerifier().GetId() != VsaVerifierId {
			Debugf("we do not accept Verifier.Id %s", vsaPred.GetVerifier().GetId())
			continue
		}

		// Does repo match?
		// remove git+http:// from resourceUri
		cleanResourceUri := strings.TrimPrefix(vsaPred.GetResourceUri(), "git+")
		if cleanResourceUri != repoUri {
			Debugf("ResourceUri is %s but we want %s", cleanResourceUri, repoUri)
			continue
		}

		// Is the result PASSED?
		if vsaPred.GetVerificationResult() != "PASSED" {
			Debugf("verificationResult is %s but must be PASSED", vsaPred.GetVerificationResult())
			continue
		}

		return stmt, vsaPred, nil
	}

	Debugf("didn't find commit %s for ref %s", commit, ref)
	return nil, nil, nil
}
