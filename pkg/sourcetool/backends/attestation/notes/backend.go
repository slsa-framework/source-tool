// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package notes implements an attestation storage backend that reads from
// git commit notes
package notes

import (
	"context"
	"fmt"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"
	attestation "github.com/in-toto/attestation/go/v1"

	"github.com/slsa-framework/slsa-source-poc/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/pkg/auth"
	"github.com/slsa-framework/slsa-source-poc/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/pkg/provenance"
	"github.com/slsa-framework/slsa-source-poc/pkg/sourcetool/models"
)

type Backend struct {
	authenticator *auth.Authenticator
}

func New() *Backend {
	return &Backend{
		authenticator: auth.New(),
	}
}

// getGitHubConnection gets a github connector to the specified branch
func (b *Backend) getGitHubConnection(branch *models.Branch) (*ghcontrol.GitHubConnection, error) {
	if branch.Repository == nil {
		return nil, fmt.Errorf("branch does not have its repository set")
	}

	client, err := b.authenticator.GetGitHubClient()
	if err != nil {
		return nil, fmt.Errorf("creating GitHub client: %w", err)
	}

	repoOwner, repoName, err := branch.Repository.PathAsGitHubOwnerName()
	if err != nil {
		return nil, err
	}

	return ghcontrol.NewGhConnectionWithClient(repoOwner, repoName, branch.FullRef(), client), nil
}

// GetCommitVsa retrieves a VSA by looking into the specified commit notes
func (b *Backend) GetCommitVsa(ctx context.Context, branch *models.Branch, commit *models.Commit) (*attestation.Statement, *vpb.VerificationSummary, error) {
	gcx, err := b.getGitHubConnection(branch)
	if err != nil {
		return nil, nil, err
	}
	statement, predicate, err := attest.GetVsa(ctx, gcx, attest.GetDefaultVerifier(), commit.SHA, branch.FullRef())
	if err != nil {
		return nil, nil, fmt.Errorf("reading VSA: %w", err)
	}

	return statement, predicate, nil
}

// GetCommitProvenance gets the provenance attestation of a commit in a branch
func (b *Backend) GetCommitProvenance(ctx context.Context, branch *models.Branch, commit *models.Commit) (*attestation.Statement, *provenance.SourceProvenancePred, error) {
	gcx, err := b.getGitHubConnection(branch)
	if err != nil {
		return nil, nil, err
	}

	pa := attest.NewProvenanceAttestor(gcx, attest.GetDefaultVerifier())
	statement, predicate, err := pa.GetProvenance(ctx, commit.SHA, branch.FullRef())
	if err != nil {
		return nil, nil, fmt.Errorf("reading provenance attestation: %w", err)
	}

	return statement, predicate, nil
}
