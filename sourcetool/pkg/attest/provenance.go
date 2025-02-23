package attest

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"time"

	spb "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/gh_control"

	"github.com/google/go-github/v68/github"
)

type SourceProvenanceProperty struct {
	// The time from which this property has been continuously enforced.
	Since time.Time `json:"since"`
}

const SourceProvPredicateType = "https://github.com/slsa-framework/slsa-source-poc/source-provenance/v1"

// The predicate that encodes source provenance data.
// The git commit this corresponds to is encoded in the surrounding statement.
type SourceProvenancePred struct {
	// The commit preceeding 'Commit' in the current context.
	PrevCommit string `json:"prev_commit"`
	// TODO: What else should we store? The actor that triggered this change?

	// The properties observed for this commit.
	// For now we're just storing the level here, but later we'll add other stuff
	Properties map[string]SourceProvenanceProperty `json:"properties"`
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
	return &predStruct, nil
}

func addPredToStatement(provPred *SourceProvenancePred, commit string) (*spb.Statement, error) {
	// Using regular json.Marhsal because this is just a regular struct and not from a proto.
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

func createCurrentProvenance(ctx context.Context, gh_client *github.Client, commit, prevCommit, owner, repo, branch string) (*spb.Statement, error) {
	controlStatus, err := gh_control.DetermineSourceLevelControlOnly(ctx, gh_client, commit, owner, repo, branch)
	if err != nil {
		return nil, err
	}

	levelProp := SourceProvenanceProperty{Since: time.Now()}
	var curProvPred SourceProvenancePred
	curProvPred.PrevCommit = prevCommit
	curProvPred.Properties = make(map[string]SourceProvenanceProperty)
	curProvPred.Properties[controlStatus.ControlLevel] = levelProp

	return addPredToStatement(&curProvPred, commit)
}

func convertLineToProv(line string) (*spb.Statement, error) {
	var sp spb.Statement

	// Did they just give us an unsigned, unwrapped provenance?
	// TODO: Add signature verification and stop supporting this!
	err := protojson.Unmarshal([]byte(line), &sp)
	if err == nil {
		return &sp, nil
	} else {
		log.Println("Line is not a bare statement")
	}

	// Did they give us the provenance as a sigstore bundle?
	vr, err := Verify(line)
	if err == nil {
		// This is it.
		return vr.Statement, nil
	} else {
		log.Printf("Line %s is not a sigstore bundle: %v", line, err)
	}

	return nil, errors.New("Could not convert line to statement.")
}

func getPrevProvenance(prevAttPath, prevCommit string) (*spb.Statement, error) {
	if prevAttPath == "" {
		// There is no prior provenance
		return nil, nil
	}

	f, err := os.Open(prevAttPath)
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReader(f)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// Handle end of file gracefully
				if line != "" {
					// Is this source provenance?
					sp, err := convertLineToProv(line)
					if err == nil {
						// Should be good!
						return sp, nil
					}
				}
				break
			}
			return nil, err
		}
		// Is this source provenance?
		sp, err := convertLineToProv(line)
		if err == nil {
			if doesSubjectIncludeCommit(sp, prevCommit) {
				// Should be good!
				return sp, nil
			}
		}
	}

	return nil, nil
}

func CreateSourceProvenance(ctx context.Context, gh_client *github.Client, prevAttPath, commit, prevCommit, owner, repo, branch string) (*spb.Statement, error) {
	// Source provenance is based on
	// 1. The current control situation (we assume 'commit' has _just_ occurred).
	// 2. How long the properties have been enforced according to the previous provenance.

	curProv, err := createCurrentProvenance(ctx, gh_client, commit, prevCommit, owner, repo, branch)
	if err != nil {
		return nil, err
	}

	prevProv, err := getPrevProvenance(prevAttPath, prevCommit)
	if err != nil {
		return nil, err
	}

	// No prior provenance found, so we just go with current.
	if prevProv == nil {
		return curProv, nil
	}

	prevProvPred, err := GetProvPred(prevProv)
	if err != nil {
		return nil, err
	}

	curProvPred, err := GetProvPred(curProv)
	if err != nil {
		return nil, err
	}

	// There was prior provenance, so update the Since field for each property
	// to the oldest encountered.
	for propName, curProp := range curProvPred.Properties {
		prevProp, ok := prevProvPred.Properties[propName]
		if !ok {
			continue
		}
		if prevProp.Since.Before(curProp.Since) {
			curProp.Since = prevProp.Since
			curProvPred.Properties[propName] = curProp
		}
	}

	return addPredToStatement(curProvPred, commit)
}
