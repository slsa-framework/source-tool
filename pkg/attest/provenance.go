package attest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	spb "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slsa-framework/slsa-source-poc/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/pkg/provenance"
	"github.com/slsa-framework/slsa-source-poc/pkg/slsa"
)

type ProvenanceAttestor struct {
	verifier      Verifier
	gh_connection *ghcontrol.GitHubConnection
}

func NewProvenanceAttestor(gh_connection *ghcontrol.GitHubConnection, verifier Verifier) *ProvenanceAttestor {
	return &ProvenanceAttestor{verifier: verifier, gh_connection: gh_connection}
}

func GetSourceProvPred(statement *spb.Statement) (*provenance.SourceProvenancePred, error) {
	if statement == nil {
		return nil, errors.New("nil statement")
	}
	if statement.GetPredicateType() != provenance.SourceProvPredicateType {
		return nil, fmt.Errorf("unsupported predicate type: %s", statement.GetPredicateType())
	}
	if statement.GetPredicate() == nil {
		return nil, errors.New("nil predicate in statement")
	}
	predJson, err := protojson.Marshal(statement.GetPredicate())
	if err != nil {
		return nil, fmt.Errorf("cannot marshal predicate to JSON: %w", err)
	}

	var predStruct provenance.SourceProvenancePred
	// Using regular json.Unmarshal because this is just a regular struct.
	err = protojson.Unmarshal(predJson, &predStruct)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling predicate: %w", err)
	}
	// It's valid for Controls to be empty if no controls are reported.
	// The policy evaluation logic will determine if this is acceptable.
	// For example, a policy might only require SLSA Level 1, which has no specific control requirements from this predicate.
	return &predStruct, nil
}

func GetTagProvPred(statement *spb.Statement) (*provenance.TagProvenancePred, error) {
	if statement == nil {
		return nil, errors.New("nil statement")
	}
	if statement.GetPredicateType() != provenance.TagProvPredicateType {
		return nil, fmt.Errorf("unsupported predicate type: %s", statement.GetPredicateType())
	}
	if statement.GetPredicate() == nil {
		return nil, errors.New("nil predicate in statement")
	}
	predJson, err := protojson.Marshal(statement.GetPredicate())
	if err != nil {
		return nil, fmt.Errorf("cannot marshal predicate to JSON: %w", err)
	}

	var predStruct provenance.TagProvenancePred
	// Using regular json.Unmarshal because this is just a regular struct.
	err = protojson.Unmarshal(predJson, &predStruct)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling predicate: %w", err)
	}
	// It's valid for Controls to be empty if no controls are reported.
	// The policy evaluation logic will determine if this is acceptable.
	// For example, a policy might only require SLSA Level 1, which has no specific control requirements from this predicate.
	return &predStruct, nil
}

func addPredToStatement(provPred any, predicateType, commit string) (*spb.Statement, error) {
	msg, ok := provPred.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("unable to serialize predicate as proto message")
	}
	predJson, err := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshaling predicate proto: %w", err)
	}

	sub := []*spb.ResourceDescriptor{{
		Digest: map[string]string{"gitCommit": commit},
	}}

	var predPb structpb.Struct
	err = protojson.Unmarshal(predJson, &predPb)
	if err != nil {
		return nil, err
	}

	statementPb := spb.Statement{
		Type:          spb.StatementTypeUri,
		Subject:       sub,
		PredicateType: predicateType,
		Predicate:     &predPb,
	}

	return &statementPb, nil
}

// Create provenance for the current commit without any context from the previous provenance (if any).
func (pa ProvenanceAttestor) createCurrentProvenance(ctx context.Context, commit, prevCommit, ref string) (*spb.Statement, error) {
	controlStatus, err := pa.gh_connection.GetBranchControlsAtCommit(ctx, commit, ref)
	if err != nil {
		return nil, err
	}

	curTime := time.Now()

	var curProvPred provenance.SourceProvenancePred
	curProvPred.PrevCommit = prevCommit
	curProvPred.RepoUri = pa.gh_connection.GetRepoUri()
	curProvPred.Actor = controlStatus.ActorLogin
	curProvPred.ActivityType = controlStatus.ActivityType
	curProvPred.Branch = ref
	curProvPred.CreatedOn = timestamppb.New(curTime)
	curProvPred.Controls = controlStatus.Controls

	// At the very least provenance is available starting now. :)
	curProvPred.AddControl(&provenance.Control{Name: slsa.ProvenanceAvailable.String(), Since: timestamppb.New(curTime)})

	return addPredToStatement(&curProvPred, provenance.SourceProvPredicateType, commit)
}

// Gets provenance for the commit from git notes.
func (pa ProvenanceAttestor) GetProvenance(ctx context.Context, commit, ref string) (*spb.Statement, *provenance.SourceProvenancePred, error) {
	notes, err := pa.gh_connection.GetNotesForCommit(ctx, commit)
	if notes == "" {
		Debugf("didn't find notes for commit %s", commit)
		return nil, nil, nil
	}

	if err != nil {
		log.Fatal(err)
	}

	bundleReader := NewBundleReader(bufio.NewReader(strings.NewReader(notes)), pa.verifier)

	return pa.getProvFromReader(bundleReader, commit, ref)
}

func (pa ProvenanceAttestor) getProvFromReader(reader *BundleReader, commit, ref string) (*spb.Statement, *provenance.SourceProvenancePred, error) {
	for {
		stmt, err := reader.ReadStatement(MatchesTypeAndCommit(provenance.SourceProvPredicateType, commit))
		if err != nil {
			// Ignore errors, we want to check all the lines.
			Debugf("error while processing line: %v", err)
			continue
		}

		if stmt == nil {
			// No statements left.
			break
		}

		// We know the statement is good, what about the predicate?
		provPred, err := GetSourceProvPred(stmt)
		if err != nil {
			return nil, nil, err
		}
		if pa.gh_connection.GetRepoUri() == provPred.GetRepoUri() && (ref == ghcontrol.AnyReference || provPred.GetBranch() == ref) {
			// Should be good!
			return stmt, provPred, nil
		} else {
			Debugf("prov '%v' does not reference commit '%s' for branch '%s', skipping", stmt, commit, ref)
		}
	}

	Debugf("didn't find commit %s for ref %s", commit, ref)
	return nil, nil, nil
}

func (pa ProvenanceAttestor) getPrevProvenance(ctx context.Context, prevAttPath, prevCommit, ref string) (*spb.Statement, *provenance.SourceProvenancePred, error) {
	if prevAttPath != "" {
		f, err := os.Open(prevAttPath)
		if err != nil {
			return nil, nil, err
		}
		return pa.getProvFromReader(NewBundleReader(bufio.NewReader(f), pa.verifier), prevCommit, ref)
	}

	// Try to get the previous bundle ourselves...
	return pa.GetProvenance(ctx, prevCommit, ref)
}

func (pa ProvenanceAttestor) CreateSourceProvenance(ctx context.Context, prevAttPath, commit, prevCommit, ref string) (*spb.Statement, error) {
	// Source provenance is based on
	// 1. The current control situation (we assume 'commit' has _just_ occurred).
	// 2. How long the properties have been enforced according to the previous provenance.

	curProv, err := pa.createCurrentProvenance(ctx, commit, prevCommit, ref)
	if err != nil {
		return nil, err
	}

	prevProvStmt, prevProvPred, err := pa.getPrevProvenance(ctx, prevAttPath, prevCommit, ref)
	if err != nil {
		return nil, err
	}

	// No prior provenance found, so we just go with current.
	if prevProvStmt == nil || prevProvPred == nil {
		Debugf("No previous provenance found, have to bootstrap\n")
		return curProv, nil
	}

	curProvPred, err := GetSourceProvPred(curProv)
	if err != nil {
		return nil, err
	}

	// There was prior provenance, so update the Since field for each property
	// to the oldest encountered.
	for i, curControl := range curProvPred.GetControls() {
		prevControl := prevProvPred.GetControl(curControl.GetName())
		// No prior version of this control
		if prevControl == nil {
			continue
		}
		curControl.Since = timestamppb.New(slsa.EarlierTime(curControl.GetSince().AsTime(), prevControl.GetSince().AsTime()))
		// Update the value.
		curProvPred.Controls[i] = curControl
	}

	return addPredToStatement(curProvPred, provenance.SourceProvPredicateType, commit)
}

func (pa ProvenanceAttestor) CreateTagProvenance(ctx context.Context, commit, ref, actor string) (*spb.Statement, error) {
	// 1. Check that the tag hygiene control is still enabled and how long it's been enabled, store it in the prov.
	// 2. Get a VSA associated with this commit, if any.
	// 3. Record the levels and branches covered by that VSA in the provenance.

	controlStatus, err := pa.gh_connection.GetTagControls(ctx, commit, ref)
	if err != nil {
		return nil, err
	}

	// Find the most recent VSA for this commit. Any reference is OK.
	// TODO: in the future get all of them.
	// TODO: we should actually verify this vsa: https://github.com/slsa-framework/slsa-source-poc/issues/148
	vsaStatement, vsaPred, err := GetVsa(ctx, pa.gh_connection, pa.verifier, commit, ghcontrol.AnyReference)
	if err != nil {
		return nil, fmt.Errorf("error fetching VSA when creating tag provenance %w", err)
	}
	if vsaPred == nil {
		// TODO: If there's not a VSA should we still issue provenance?
		return nil, nil
	}

	vsaRefs, err := GetSourceRefsForCommit(vsaStatement, commit)
	if err != nil {
		return nil, fmt.Errorf("error getting source refs from vsa %w", err)
	}

	curProvPred := provenance.TagProvenancePred{
		RepoUri:   pa.gh_connection.GetRepoUri(),
		Actor:     actor,
		Tag:       ref,
		CreatedOn: timestamppb.Now(),
		Controls:  controlStatus.Controls,
		VsaSummaries: []*provenance.VsaSummary{
			{
				SourceRefs:     vsaRefs,
				VerifiedLevels: vsaPred.GetVerifiedLevels(),
			},
		},
	}

	return addPredToStatement(&curProvPred, provenance.TagProvPredicateType, commit)
}
