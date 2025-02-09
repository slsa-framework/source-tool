package provenance

import (
	"context"
	"log"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/go-github/v68/github"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/checklevel"
)

type SourceProvenanceProperty struct {
	// The time from which this property has been continuously enforced.
	Since time.Time
}
type SourceProvenance struct {
	// The commit this provenance documents.
	Commit string `json:"commit"`
	// The commit preceeding 'Commit' in the current context.
	PrevCommit string `json:"prev_commit"`
	// The properties observed for this commit.
	Properties map[string]SourceProvenanceProperty `json:"properties"`
}

func createCurrentProvenance(ctx context.Context, gh_client *github.Client, commit, prevCommit, owner, repo, branch string) (*SourceProvenance, error) {
	sourceLevel, err := checklevel.DetermineSourceLevelControlOnly(ctx, gh_client, commit, owner, repo, branch)
	if err != nil {
		return nil, err
	}

	levelProp := SourceProvenanceProperty{Since: time.Now()}
	var curProv SourceProvenance
	curProv.Commit = commit
	curProv.PrevCommit = prevCommit
	curProv.Properties[sourceLevel] = levelProp

	return &curProv, nil
}

func getPrevProvenance(ctx context.Context, gh_client *github.Client, repoPath, prevCommit string) (*SourceProvenance, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, err
	}

	notes, err := repo.Notes()
	if err != nil {
		return nil, err
	}

	err = notes.ForEach(func(r *plumbing.Reference) error {
		log.Printf("ref: %v", r)
		return nil
	})

	// note, err := notes.Get(prevCommit)
	// if err != nil {
	// 	return nil, err
	// }
	// log.Printf("Got note: %v", note)

	return nil, nil
}

func CreateSourceProvenance(ctx context.Context, gh_client *github.Client, repoPath, commit, prevCommit, owner, repo, branch string) (*SourceProvenance, error) {
	// Source provenance is based on
	// 1. The current control situation (we assume 'commit' has _just_ occurred).
	// 2. How long the properties have been enforced according to the previous provenance.

	curProv, err := createCurrentProvenance(ctx, gh_client, commit, prevCommit, owner, repo, branch)
	if err != nil {
		return nil, err
	}
	log.Printf("curProv.commit %v", curProv.Commit)

	prevProv, err := getPrevProvenance(ctx, gh_client, repoPath, prevCommit)
	if err != nil {
		return nil, err
	}
	log.Printf("prevProv.commit %v", prevProv.Commit)

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
