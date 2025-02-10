package attest

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/gh_control"

	"github.com/google/go-github/v68/github"
)

type SourceProvenanceProperty struct {
	// The time from which this property has been continuously enforced.
	Since time.Time `json:"since"`
}

// TODO replace with an in-toto attestation.
type SourceProvenance struct {
	// The commit this provenance documents.
	Commit string `json:"commit"`
	// The commit preceeding 'Commit' in the current context.
	PrevCommit string `json:"prev_commit"`
	// TODO: What else should we store? The actor that triggered this change?

	// The properties observed for this commit.
	Properties map[string]SourceProvenanceProperty `json:"properties"`
}

func createCurrentProvenance(ctx context.Context, gh_client *github.Client, commit, prevCommit, owner, repo, branch string) (*SourceProvenance, error) {
	controlStatus, err := gh_control.DetermineSourceLevelControlOnly(ctx, gh_client, commit, owner, repo, branch)
	if err != nil {
		return nil, err
	}

	levelProp := SourceProvenanceProperty{Since: time.Now()}
	var curProv SourceProvenance
	curProv.Commit = commit
	curProv.PrevCommit = prevCommit
	curProv.Properties = make(map[string]SourceProvenanceProperty)
	curProv.Properties[controlStatus.ControlLevel] = levelProp

	return &curProv, nil
}

func convertLineToProv(line string) (*SourceProvenance, error) {
	var sp SourceProvenance
	err := json.Unmarshal([]byte(line), sp)
	if err != nil {
		return nil, err
	}
	return &sp, nil
}

func getPrevProvenance(ctx context.Context, gh_client *github.Client, prevAttPath, prevCommit string) (*SourceProvenance, error) {
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
			// Should be good!
			return sp, nil
		}
	}

	return nil, nil
}

func CreateSourceProvenance(ctx context.Context, gh_client *github.Client, prevAttPath, commit, prevCommit, owner, repo, branch string) (*SourceProvenance, error) {
	// Source provenance is based on
	// 1. The current control situation (we assume 'commit' has _just_ occurred).
	// 2. How long the properties have been enforced according to the previous provenance.

	curProv, err := createCurrentProvenance(ctx, gh_client, commit, prevCommit, owner, repo, branch)
	if err != nil {
		return nil, err
	}

	prevProv, err := getPrevProvenance(ctx, gh_client, prevAttPath, prevCommit)
	if err != nil {
		return nil, err
	}

	// No prior provenance found, so we just go with current.
	if prevProv == nil {
		return curProv, nil
	}

	// There was prior provenance, so update the Since field for each property
	// to the oldest encountered.
	for propName, curProp := range curProv.Properties {
		prevProp, ok := prevProv.Properties[propName]
		if !ok {
			continue
		}
		if prevProp.Since.Before(curProp.Since) {
			curProp.Since = prevProp.Since
			curProv.Properties[propName] = curProp
		}
	}

	return curProv, nil
}
