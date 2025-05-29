package attest

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	spb "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/gh_control"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa_types"
)

const SourceProvPredicateType = "https://github.com/slsa-framework/slsa-source-poc/source-provenance/v1-draft"
const TagProvPredicateType = "https://github.com/slsa-framework/slsa-source-poc/tag-provenance/v1-draft"

// The predicate that encodes source provenance data.
// The git commit this corresponds to is encoded in the surrounding statement.
type SourceProvenancePred struct {
	// The commit preceding 'Commit' in the current context.
	PrevCommit   string    `json:"prev_commit"`
	RepoUri      string    `json:"repo_uri"`
	ActivityType string    `json:"activity_type"`
	Actor        string    `json:"actor"`
	Branch       string    `json:"branch"`
	CreatedOn    time.Time `json:"created_on"`
	// TODO: get the author of the PR (if this was from a PR).

	// The controls enabled at the time this commit was pushed.
	Controls slsa_types.Controls `json:"controls"`
}

// Summary of a summary
type VsaSummary struct {
	SourceRefs     []string `json:"source_refs"`
	VerifiedLevels []string `json:"verifiedLevels"`
}

type TagProvenancePred struct {
	RepoUri   string    `json:"repo_uri"`
	Actor     string    `json:"actor"`
	Tag       string    `json:"tag"`
	CreatedOn time.Time `json:"created_on"`
	// The tag related controls enabled at the time this tag was created/updated.
	Controls     slsa_types.Controls `json:"controls"`
	VsaSummaries []VsaSummary        `json:"vsa_summaries"`
}

type ProvenanceAttestor struct {
	verifier      Verifier
	gh_connection *gh_control.GitHubConnection
}

func NewProvenanceAttestor(gh_connection *gh_control.GitHubConnection, verifier Verifier) *ProvenanceAttestor {
	return &ProvenanceAttestor{verifier: verifier, gh_connection: gh_connection}
}

func GetSourceProvPred(statement *spb.Statement) (*SourceProvenancePred, error) {
	if statement == nil {
		return nil, errors.New("nil statement")
	}
	if statement.PredicateType != SourceProvPredicateType {
		return nil, fmt.Errorf("unsupported predicate type: %s", statement.PredicateType)
	}
	if statement.Predicate == nil {
		return nil, errors.New("nil predicate in statement")
	}
	predJson, err := protojson.Marshal(statement.Predicate)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal predicate to JSON: %w", err)
	}

	var predStruct SourceProvenancePred
	// Using regular json.Unmarshal because this is just a regular struct.
	err = json.Unmarshal(predJson, &predStruct)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling predicate: %w", err)
	}
	// It's valid for Controls to be empty if no controls are reported.
	// The policy evaluation logic will determine if this is acceptable.
	// For example, a policy might only require SLSA Level 1, which has no specific control requirements from this predicate.
	return &predStruct, nil
}

func GetTagProvPred(statement *spb.Statement) (*TagProvenancePred, error) {
	if statement == nil {
		return nil, errors.New("nil statement")
	}
	if statement.PredicateType != TagProvPredicateType {
		return nil, fmt.Errorf("unsupported predicate type: %s", statement.PredicateType)
	}
	if statement.Predicate == nil {
		return nil, errors.New("nil predicate in statement")
	}
	predJson, err := protojson.Marshal(statement.Predicate)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal predicate to JSON: %w", err)
	}

	var predStruct TagProvenancePred
	// Using regular json.Unmarshal because this is just a regular struct.
	err = json.Unmarshal(predJson, &predStruct)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling predicate: %w", err)
	}
	// It's valid for Controls to be empty if no controls are reported.
	// The policy evaluation logic will determine if this is acceptable.
	// For example, a policy might only require SLSA Level 1, which has no specific control requirements from this predicate.
	return &predStruct, nil
}

func addPredToStatement(provPred any, predicateType, commit string) (*spb.Statement, error) {
	// Using regular json.Marshal because this is just a regular struct and not from a proto.
	predJson, err := json.Marshal(provPred)
	if err != nil {
		return nil, err
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
	controlStatus, err := pa.gh_connection.GetBranchControls(ctx, commit, ref)
	if err != nil {
		return nil, err
	}

	curTime := time.Now()

	var curProvPred SourceProvenancePred
	curProvPred.PrevCommit = prevCommit
	curProvPred.RepoUri = pa.gh_connection.GetRepoUri()
	curProvPred.Actor = controlStatus.ActorLogin
	curProvPred.ActivityType = controlStatus.ActivityType
	curProvPred.Branch = ref
	curProvPred.CreatedOn = curTime
	curProvPred.Controls = controlStatus.Controls

	// At the very least provenance is available starting now. :)
	curProvPred.Controls.AddControl(&slsa_types.Control{Name: slsa_types.ProvenanceAvailable, Since: curTime})

	return addPredToStatement(&curProvPred, SourceProvPredicateType, commit)
}

// Gets provenance for the commit from git notes.
func (pa ProvenanceAttestor) GetProvenance(ctx context.Context, commit, ref string) (*spb.Statement, *SourceProvenancePred, error) {
	notes, err := pa.gh_connection.GetNotesForCommit(ctx, commit)
	if notes == "" {
		log.Printf("didn't find notes for commit %s", commit)
		return nil, nil, nil
	}

	if err != nil {
		log.Fatal(err)
	}

	bundleReader := NewBundleReader(bufio.NewReader(strings.NewReader(notes)), pa.verifier)

	return pa.getProvFromReader(bundleReader, commit, ref)
}

func (pa ProvenanceAttestor) getProvFromReader(reader *BundleReader, commit, ref string) (*spb.Statement, *SourceProvenancePred, error) {
	for {
		stmt, err := reader.ReadStatement(MatchesTypeAndCommit(SourceProvPredicateType, commit))
		if err != nil {
			return nil, nil, err
		}
		if err != nil {
			// Ignore errors, we want to check all the lines.
			log.Printf("error while processing line: %v", err)
			continue
		}

		if stmt == nil {
			// No statements left.
			break
		}

		prevProdPred, err := GetSourceProvPred(stmt)
		if err != nil {
			return nil, nil, err
		}
		if ref == gh_control.AnyReference || prevProdPred.Branch == ref {
			// Should be good!
			return stmt, prevProdPred, nil
		} else {
			log.Printf("prov '%v' does not reference commit '%s' for branch '%s', skipping", stmt, commit, ref)
		}
	}

	log.Printf("didn't find commit %s for ref %s", commit, ref)
	return nil, nil, nil
}

func (pa ProvenanceAttestor) getPrevProvenance(ctx context.Context, prevAttPath, prevCommit, ref string) (*spb.Statement, *SourceProvenancePred, error) {
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
		log.Printf("No previous provenance found, have to bootstrap\n")
		return curProv, nil
	}

	curProvPred, err := GetSourceProvPred(curProv)
	if err != nil {
		return nil, err
	}

	// There was prior provenance, so update the Since field for each property
	// to the oldest encountered.
	for i, curControl := range curProvPred.Controls {
		prevControl := prevProvPred.Controls.GetControl(curControl.Name)
		// No prior version of this control
		if prevControl == nil {
			continue
		}
		curControl.Since = slsa_types.EarlierTime(curControl.Since, prevControl.Since)
		// Update the value.
		curProvPred.Controls[i] = curControl
	}

	return addPredToStatement(curProvPred, SourceProvPredicateType, commit)
}

func (pa ProvenanceAttestor) CreateTagProvenance(ctx context.Context, commit, ref, actor string) (*spb.Statement, error) {
	// 1. Check that the immutable tags control is still enabled and how long it's been enabled, store it in the prov.
	// 2. Get a VSA associated with this commit, if any.
	// 3. Record the levels and branches covered by that VSA in the provenance.

	controlStatus, err := pa.gh_connection.GetTagControls(ctx, commit, ref)
	if err != nil {
		return nil, err
	}

	// Find the most recent VSA for this commit. Any reference is OK.
	// TODO: in the future get all of them.
	// TODO: we should actually verify this vsa: https://github.com/slsa-framework/slsa-source-poc/issues/148
	vsaStatement, vsaPred, err := GetVsa(ctx, pa.gh_connection, pa.verifier, commit, gh_control.AnyReference)
	if err != nil {
		return nil, fmt.Errorf("error fetching VSA when creating tag provenance %w", err)
	}
	if vsaPred == nil {
		// TODO: If there's not a VSA should we still issue provenance?
		return nil, nil
	}

	curTime := time.Now()

	vsaRefs, err := GetSourceRefsForCommit(vsaStatement, commit)
	if err != nil {
		return nil, fmt.Errorf("error getting source refs from vsa %w", err)
	}

	curProvPred := TagProvenancePred{
		RepoUri:   pa.gh_connection.GetRepoUri(),
		Actor:     actor,
		Tag:       ref,
		CreatedOn: curTime,
		Controls:  controlStatus.Controls,
		VsaSummaries: []VsaSummary{
			{
				SourceRefs:     vsaRefs,
				VerifiedLevels: vsaPred.VerifiedLevels,
			},
		},
	}

	return addPredToStatement(&curProvPred, TagProvPredicateType, commit)
}
