package github

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-github/v69/github"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/repo"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/repo/options"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/models"
)

const (
	workflowPath   = ".github/workflows/compute_slsa_source.yaml"
	workflowSource = "git+https://github.com/slsa-"

	// workflowCommitMessage will be used as the commit message and the PR title
	workflowCommitMessage = "Add SLSA Source Provenance Workflow"

	// workflowPRBody is the body of the pull request that adds the provenance workflow
	workflowPRBody = `This pull request adds a new workflow to the repository to generate ` +
		`[SLSA](https://slsa.dev/) Source provenance data on every push.` + "\n\n" +
		`Every time a new commit merges to the specified branch, attestations will ` +
		`be automatically signed and stored in git notes in this repository.` + "\n\n" +
		`Note: This is an automated PR created using the ` +
		`[SLSA sourcetool](https://github.com/slsa-framework/slsa-source-poc) utility.` + "\n"

	workflowData = `---
name: SLSA Source
on:
  push:
    branches: [ %s ]
permissions: {}

jobs:
  # Whenever new source is pushed recompute the slsa source information.
  generate-provenance:
    permissions:
      contents: write # needed for storing the vsa in the repo.
      id-token: write # meeded to mint yokens for signing
    uses: slsa-framework/slsa-source-poc/.github/workflows/compute_slsa_source.yml@main
`
)

// CreateWorkflowPR creates the pull request to add the provenance workflow
// to the specified repository.
func (b *Backend) CreateWorkflowPR(r *models.Repository, branches []*models.Branch) (*models.PullRequest, error) {
	if len(branches) == 0 {
		return nil, errors.New("no branches specified")
	}

	// Populate the branches in the workflow template
	quotedBranchesList := []string{}
	for _, b := range branches {
		quotedBranchesList = append(quotedBranchesList, fmt.Sprintf("%q", b.Name))
	}
	workflowYAML := fmt.Sprintf(workflowData, strings.Join(quotedBranchesList, ", "))

	// Create a PAR manager
	prManager := repo.NewPullRequestManager(repo.WithAuthenticator(b.authenticator))

	// TODO(puerco): Honor forks settings, etc

	// Open the pull request
	pr, err := prManager.PullRequestFileList(
		r,
		&options.PullRequestFileListOptions{
			Title: workflowCommitMessage,
			Body:  workflowPRBody,
		},
		[]*repo.PullRequestFileEntry{
			{
				Path:   workflowPath,
				Reader: strings.NewReader(workflowYAML),
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("creating workflow pull request: %w", err)
	}

	// Success!
	return pr, nil
}

// CheckWorkflowFork verifies that the user has a fork of the repository
// we are configuring.
func (b *Backend) CheckWorkflowFork(r *models.Repository) error {
	// Create a PAR manager
	prManager := repo.NewPullRequestManager(repo.WithAuthenticator(b.authenticator))

	// TODO(puerco): Support forkname from options
	_, err := prManager.CheckFork(r, "")
	return err
}

// searchPullRequestsByTitlet searches the last pull requests on a repo for one whose
// title matches the query string
func (b *Backend) searchPullRequestsByTitle(ctx context.Context, r *models.Repository, query string) (*github.PullRequest, error) {
	owner, repoName, err := r.PathAsGitHubOwnerName()
	if err != nil {
		return nil, err
	}
	client, err := b.authenticator.GetGitHubClient()
	if err != nil {
		return nil, err
	}

	prs, _, err := client.PullRequests.List(
		ctx, owner, repoName, &github.PullRequestListOptions{
			State: "open",
			// Search only the last 100
			ListOptions: github.ListOptions{
				Page:    0,
				PerPage: 100,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("listing pull requests: %w", err)
	}

	for _, pr := range prs {
		if strings.Contains(pr.GetTitle(), query) {
			return pr, nil
		}
	}
	return nil, nil
}

func (b *Backend) FindWorkflowPR(ctx context.Context, r *models.Repository) (*models.PullRequest, error) {
	pr, err := b.searchPullRequestsByTitle(ctx, r, workflowCommitMessage)
	if err != nil {
		return nil, fmt.Errorf("searching for provenance workflow pull request: %w", err)
	}

	if pr == nil {
		return nil, nil
	}

	return &models.PullRequest{
		Title:  pr.GetTitle(),
		Body:   pr.GetBody(),
		Number: pr.GetNumber(),
		Repo:   r,
	}, nil
}

func (b *Backend) CreateRepoRuleset(r *models.Repository, branches []*models.Branch) error {
	if r == nil {
		return errors.New("unable to create repo ruleset, repository not defined")
	}

	if branches == nil {
		return errors.New("unable to create repo ruleset, branch not set")
	}

	if len(branches) > 0 {
		return errors.New("protecting more than one branch at a time is not yet supported")
	}

	ghc, err := b.getGitHubConnection(r, branches[0].FullRef())
	if err != nil {
		return err
	}

	if err := ghc.EnableBranchRules(context.Background()); err != nil {
		return fmt.Errorf("enabling branch protection rules: %w", err)
	}

	return nil
}

func (b *Backend) ConfigureControls(r *models.Repository, branches []*models.Branch, configs []models.ControlConfiguration) error {
	for _, config := range configs {
		switch config {
		case models.CONFIG_BRANCH_RULES:
			if err := b.CreateRepoRuleset(r, branches); err != nil {
				return fmt.Errorf("creating rules in the repository: %w", err)
			}
		case models.CONFIG_GEN_PROVENANCE:
			if err := b.CheckWorkflowFork(r); err != nil {
				return fmt.Errorf("checking repository fork: %w", err)
			}
			if _, err := b.CreateWorkflowPR(r, branches); err != nil {
				return fmt.Errorf("opening SLSA source workflow pull request: %w", err)
			}
		case models.CONFIG_POLICY:
			// Noop, this is not handled by the VCS handler
		default:
			return fmt.Errorf("unknown configuration flag: %q", config)
		}
	}
	return nil
}
