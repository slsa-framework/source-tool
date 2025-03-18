package attest

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"slices"
	"strings"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"
	spb "github.com/in-toto/attestation/go/v1"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/gh_control"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa_types"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const VsaPredicateType = "https://slsa.dev/verification_summary/v1"

func CreateUnsignedSourceVsa(gh_connection *gh_control.GitHubConnection, commit string, verifiedLevels slsa_types.SourceVerifiedLevels, policy string) (string, error) {
	resourceUri := fmt.Sprintf("git+%s", gh_connection.GetRepoUri())
	vsaPred := &vpb.VerificationSummary{
		Verifier: &vpb.VerificationSummary_Verifier{
			Id: "https://github.com/slsa-framework/slsa-source-poc"},
		TimeVerified:       timestamppb.Now(),
		ResourceUri:        resourceUri,
		Policy:             &vpb.VerificationSummary_Policy{Uri: policy},
		VerificationResult: "PASSED",
		VerifiedLevels:     verifiedLevels,
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
		PredicateType: VsaPredicateType,
		Predicate:     &predPb,
	}

	statement, err := protojson.Marshal(&statementPb)
	if err != nil {
		return "", err
	}
	return string(statement), nil
}

// Gets provenance for the commit from git notes.
func (pa ProvenanceAttestor) GetVsa(ctx context.Context, commit string) (*spb.Statement, *vpb.VerificationSummary, error) {
	notes, err := pa.gh_connection.GetNotesForCommit(ctx, commit)
	if notes == "" {
		log.Printf("didn't find notes for commit %s", commit)
		return nil, nil, nil
	}

	if err != nil {
		log.Fatal(err)
	}
	return pa.getVsaFromReader(NewBundleReader(bufio.NewReader(strings.NewReader(notes)), pa.verification_options), commit)
}

func getVsaPred(statement *spb.Statement) (*vpb.VerificationSummary, error) {
	predJson, err := protojson.Marshal(statement.Predicate)
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

func MatchesTypeCommitAndBranch(predicateType, commit, branch string) StatementMatcher {
	return func(statement *spb.Statement) bool {
		if statement.PredicateType != predicateType {
			log.Printf("statement predicate type (%s) doesn't match %s", statement.PredicateType, predicateType)
			return false
		}
		subject := GetSubjectForCommit(statement, commit)
		if subject == nil {
			log.Printf("statement %v does not match commit %s", statement, commit)
			return false
		}
		branches, ok := subject.Annotations.AsMap()["source_branches"]
		if !ok {
			log.Printf("statement has no branches: %v", statement)
			return false
		}
		branches_str, _ := branches.([]string)
		if !slices.Contains(branches_str, branch) {
			log.Printf("source_branches (%v) does not contain %s", branches, branch)
			return false
		}
		return true
	}
}

func (pa ProvenanceAttestor) getVsaFromReader(reader *BundleReader, commit string) (*spb.Statement, *vpb.VerificationSummary, error) {
	for {
		stmt, err := reader.ReadStatement(MatchesTypeCommitAndBranch(VsaPredicateType, commit, pa.gh_connection.GetFullBranch()))
		if err != nil {
			// Ignore errors, we want to check all the lines.
			log.Printf("error while processing line: %v", err)
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

		return stmt, vsaPred, nil
	}

	log.Printf("didn't find commit %s for branch %s", commit, pa.gh_connection.Branch)
	return nil, nil, nil
}
