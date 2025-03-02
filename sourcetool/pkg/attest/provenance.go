package attest

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

type ProvenanceAttestor struct {
	verification_options VerificationOptions
	gh_connection        *gh_control.GitHubConnection
}

func NewProvenanceAttestor(gh_connection *gh_control.GitHubConnection, verification_options VerificationOptions) *ProvenanceAttestor {
	return &ProvenanceAttestor{verification_options: verification_options, gh_connection: gh_connection}
}

func GetProvPred(statement *spb.Statement) (*SourceProvenancePred, error) {
	predJson, err := protojson.Marshal(statement.Predicate)
	if err != nil {
		return nil, err
	}

	var predStruct SourceProvenancePred
	// Using regular json.Unmarshal because this is just a regular struct.
	err = json.Unmarshal(predJson, &predStruct)
	if err != nil {
		return nil, err
	}
	if len(predStruct.Controls) == 0 {
		return nil, fmt.Errorf("expected %v to have non-zero properties", predStruct)
	}
	return &predStruct, nil
}

func addPredToStatement(provPred *SourceProvenancePred, commit string) (*spb.Statement, error) {
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
		PredicateType: SourceProvPredicateType,
		Predicate:     &predPb,
	}

	return &statementPb, nil
}

func doesSubjectIncludeCommit(statement *spb.Statement, commit string) bool {
	for _, subject := range statement.Subject {
		if subject.Digest["gitCommit"] == commit {
			return true
		}
	}
	return false
}

// Create provenance for the current commit without any context from the previous provenance (if any).
func (pa ProvenanceAttestor) createCurrentProvenance(ctx context.Context, commit, prevCommit string) (*spb.Statement, error) {
	controlStatus, err := pa.gh_connection.GetControls(ctx, commit)
	if err != nil {
		return nil, err
	}

	curTime := time.Now()

	var curProvPred SourceProvenancePred
	curProvPred.PrevCommit = prevCommit
	curProvPred.RepoUri = pa.gh_connection.GetRepoUri()
	curProvPred.Actor = controlStatus.ActorLogin
	curProvPred.ActivityType = controlStatus.ActivityType
	curProvPred.Branch = pa.gh_connection.GetFullBranch()
	curProvPred.CreatedOn = curTime
	curProvPred.Controls = controlStatus.Controls

	// At the very least provenance is available starting now. :)
	curProvPred.Controls.AddControl(&slsa_types.Control{Name: slsa_types.ProvenanceAvailable, Since: curTime})

	return addPredToStatement(&curProvPred, commit)
}

func (pa ProvenanceAttestor) convertLineToStatement(line string) (*spb.Statement, error) {
	// Is this a sigstore bundle with a statement?
	vr, err := Verify(line, pa.verification_options)
	if err == nil {
		// This is it.
		return vr.Statement, nil
	} else {
		// We ignore errors because there could be other stuff in the
		// bundle this line came from.
		log.Printf("Line %s failed verification: %v", line, err)
	}

	// TODO: add support for 'regular' DSSEs.

	return nil, errors.New("could not convert line to statement")
}

// Gets provenance for the commit from git notes.
func (pa ProvenanceAttestor) GetProvenance(ctx context.Context, commit string) (*spb.Statement, *SourceProvenancePred, error) {
	notes, err := pa.gh_connection.GetNotesForCommit(ctx, commit)
	if notes == "" {
		log.Printf("didn't find prev commit %s for branch %s", commit, pa.gh_connection.Branch)
		return nil, nil, nil
	}

	if err != nil {
		log.Fatal(err)
	}
	return pa.getProvFromReader(bufio.NewReader(strings.NewReader(notes)), commit)
}

func (pa ProvenanceAttestor) getProvFromReader(reader *bufio.Reader, commit string) (*spb.Statement, *SourceProvenancePred, error) {
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// Handle end of file gracefully
			if err != io.EOF {
				return nil, nil, err
			}
			if line == "" {
				// Nothing to see here.
				break
			}
		}
		// Is this source provenance?
		sp, err := pa.convertLineToStatement(line)
		if err == nil {
			if sp.PredicateType != SourceProvPredicateType {
				log.Printf("statement %v isn't source provenance", sp)
				continue
			}
			prevProdPred, err := GetProvPred(sp)
			if err != nil {
				return nil, nil, err
			}
			if doesSubjectIncludeCommit(sp, commit) && prevProdPred.Branch == pa.gh_connection.GetFullBranch() {
				// Should be good!
				return sp, prevProdPred, nil
			} else {
				log.Printf("prov '%v' does not reference commit '%s' for branch '%s', skipping", sp, commit, pa.gh_connection.GetFullBranch())
			}
		}
	}

	log.Printf("didn't find commit %s for branch %s", commit, pa.gh_connection.Branch)
	return nil, nil, nil
}

func (pa ProvenanceAttestor) getPrevProvenance(ctx context.Context, prevAttPath, prevCommit string) (*spb.Statement, *SourceProvenancePred, error) {
	if prevAttPath != "" {
		f, err := os.Open(prevAttPath)
		if err != nil {
			return nil, nil, err
		}
		return pa.getProvFromReader(bufio.NewReader(f), prevCommit)
	}

	// Try to get the previous bundle ourselves...
	return pa.GetProvenance(ctx, prevCommit)
}

func (pa ProvenanceAttestor) CreateSourceProvenance(ctx context.Context, prevAttPath, commit, prevCommit string) (*spb.Statement, error) {
	// Source provenance is based on
	// 1. The current control situation (we assume 'commit' has _just_ occurred).
	// 2. How long the properties have been enforced according to the previous provenance.

	curProv, err := pa.createCurrentProvenance(ctx, commit, prevCommit)
	if err != nil {
		return nil, err
	}

	prevProvStmt, prevProvPred, err := pa.getPrevProvenance(ctx, prevAttPath, prevCommit)
	if err != nil {
		return nil, err
	}

	// No prior provenance found, so we just go with current.
	if prevProvStmt == nil || prevProvPred == nil {
		log.Printf("No previous provenance found, have to bootstrap\n")
		return curProv, nil
	}

	curProvPred, err := GetProvPred(curProv)
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

	return addPredToStatement(curProvPred, commit)
}
