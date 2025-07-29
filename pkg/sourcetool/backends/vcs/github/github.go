// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/slsa-framework/slsa-source-poc/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/pkg/auth"
	"github.com/slsa-framework/slsa-source-poc/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/pkg/provenance"
	"github.com/slsa-framework/slsa-source-poc/pkg/slsa"
	"github.com/slsa-framework/slsa-source-poc/pkg/sourcetool/models"
)

func New() *Backend {
	return &Backend{
		authenticator: auth.New(),
	}
}

// Backend implemets the GitHub sourcetool backend
type Backend struct {
	authenticator *auth.Authenticator
}

// getGitHubConnection builds a github connector to a repository
func (b *Backend) getGitHubConnection(repository *models.Repository, ref string) (*ghcontrol.GitHubConnection, error) {
	if repository == nil {
		return nil, fmt.Errorf("unable to build GitHub connection, repository is nil")
	}

	if repository.Path == "" {
		return nil, errors.New("repository  path not set")
	}

	owner, name, err := repository.PathAsGitHubOwnerName()
	if err != nil {
		return nil, err
	}

	client, err := b.authenticator.GetGitHubClient()
	if err != nil {
		return nil, err
	}

	return ghcontrol.NewGhConnectionWithClient(owner, name, ref, client), nil
}

func (b *Backend) GetBranchControls(ctx context.Context, r *models.Repository, branch *models.Branch) (*slsa.ControlSetStatus, error) {
	// get latest commit
	ghc, err := b.getGitHubConnection(branch.Repository, branch.FullRef())
	if err != nil {
		return nil, fmt.Errorf("getting github connection: %w", err)
	}

	// Get the latest commit from the branch
	commit, err := ghc.GetLatestCommit(ctx, branch.FullRef())
	if err != nil {
		return nil, fmt.Errorf("fetching latest commit from %q: %w", branch.FullRef(), err)
	}

	return b.GetBranchControlsAtCommit(ctx, r, branch, &models.Commit{SHA: commit})
}

// GetBranchControlsAtCommit
func (b *Backend) GetBranchControlsAtCommit(ctx context.Context, r *models.Repository, branch *models.Branch, commit *models.Commit) (*slsa.ControlSetStatus, error) {
	if commit == nil {
		return nil, errors.New("commit is not set")
	}
	ghc, err := b.getGitHubConnection(branch.Repository, branch.FullRef())
	if err != nil {
		return nil, fmt.Errorf("getting github connection: %w", err)
	}

	// Get the active controls
	activeControls, err := ghc.GetBranchControls(ctx, branch.FullRef())
	if err != nil {
		return nil, fmt.Errorf("checking status: %w", err)
	}

	// We need to manually check for PROVENANCE_AVAILABLE which is not
	// handled by ghcontrol
	attestor := attest.NewProvenanceAttestor(
		ghc, attest.GetDefaultVerifier(),
	)

	// Fetch the attestation. If found, then add the control:
	attestation, _, err := attestor.GetProvenance(ctx, commit.SHA, branch.FullRef())
	if err != nil {
		return nil, fmt.Errorf("attempting to read provenance from commit %q: %w", commit.SHA, err)
	}
	if attestation != nil {
		activeControls.AddControl(&provenance.Control{
			Name: slsa.ProvenanceAvailable.String(),
		})
	} else {
		log.Printf("No provenance attestation found on %s", commit.SHA)
	}

	status := slsa.NewControlSetStatus()
	for i, ctrl := range status.Controls {
		if c := activeControls.GetControl(ctrl.Name); c != nil {
			t := c.GetSince().AsTime()
			status.Controls[i].Since = &t
			status.Controls[i].State = slsa.StateActive
			status.Controls[i].Message = b.controlImplementationMessage(slsa.ControlName(c.GetName()))
		}
	}

	// The only control which can be in in_progress state in GitHub is
	// provenance generation when the PR is open but not merged. We check
	// here and report back the status.
	switchProvCtlToInProgress := false
	var provenanceMessage string
	if c := activeControls.GetControl(slsa.ProvenanceAvailable); c == nil {
		pr, err := b.FindWorkflowPR(ctx, r)
		if err != nil {
			return nil, fmt.Errorf("looking for provenance workflow pull request: %w", err)
		}
		// PR found, check is in progress
		if pr != nil {
			// ... but do it below to save finding the control
			switchProvCtlToInProgress = true
			provenanceMessage = fmt.Sprintf("(PR %s#%d waiting to merge)", pr.Repo.Path, pr.Number)
		}
	}

	// Populate the recommended actions
	for i := range status.Controls {
		// Piggyback on this loop to switch the provenance status for efficiency
		if switchProvCtlToInProgress && status.Controls[i].Name == slsa.ProvenanceAvailable {
			status.Controls[i].State = slsa.StateInProgress
			status.Controls[i].Message = provenanceMessage
		}
		action := b.getRecommendedAction(r, branch, status.Controls[i].Name, status.Controls[i].State)
		status.Controls[i].RecommendedAction = action
	}

	return status, nil
}

// controlImplementationMessage returns an implementation message to populate the
// status message when controls are active.
func (b *Backend) controlImplementationMessage(ctrlName slsa.ControlName) string {
	switch ctrlName {
	case slsa.ProvenanceAvailable:
		return "Signed provenance metadata is being published on every commit"
	case slsa.TagHygiene:
		return "Tag protections are configured in the repository"
	case slsa.ReviewEnforced:
		return "Code review is enforced in the repository"
	case slsa.ContinuityEnforced:
		return "Push and delete protection is enabled on the branch"
	case slsa.PolicyAvailable:
		return "The repository has published a policy"
	default:
		return ""
	}
}

func (b *Backend) GetTagControls(context.Context, *models.Tag) (*slsa.Controls, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func (b *Backend) ControlConfigurationDescr(branch *models.Branch, config models.ControlConfiguration) string {
	repo := branch.Repository
	if repo == nil {
		repo = &models.Repository{
			// this is an invalid path but it is just a default used to
			// construct English sentences below:
			Path: "your repository",
		}
	}

	switch config {
	case models.CONFIG_BRANCH_RULES:
		return fmt.Sprintf(
			"Enable push and delete protection on %s for branch %s",
			repo.Path, branch.Name,
		)
	case models.CONFIG_GEN_PROVENANCE:
		return fmt.Sprintf(
			"Open a pull request on %s to add the provenance generation workflow",
			repo.Path,
		)
	case models.CONFIG_POLICY:
		return fmt.Sprintf(
			"Open a pull request on the SLSA policy repo to check-in %s SLSA source policy",
			repo.Path,
		)
	case models.CONFIG_TAG_RULES:
		return fmt.Sprintf(
			"Enable push/update/delete protection for all tags in %s",
			repo.Path,
		)
	default:
		return ""
	}
}

// GetLatestCommit returns the latest commit from a branch
func (b *Backend) GetLatestCommit(ctx context.Context, r *models.Repository, branch *models.Branch) (*models.Commit, error) {
	gcx, err := b.getGitHubConnection(r, branch.FullRef())
	if err != nil {
		return nil, fmt.Errorf("building GitHub connector: %w", err)
	}

	sha, err := gcx.GetLatestCommit(ctx, branch.FullRef())
	if err != nil {
		return nil, fmt.Errorf("reading latest commit: %w", err)
	}

	return &models.Commit{SHA: sha}, nil
}

// GetRecommendedAction returns the recommended action based on the
// status of a SLSA control
func (b *Backend) getRecommendedAction(r *models.Repository, _ *models.Branch, control slsa.ControlName, state slsa.ControlState) *slsa.ControlRecommendedAction {
	//nolint:exhaustive // Not all drivers handle all controls
	switch control {
	case slsa.ProvenanceAvailable:
		switch state {
		case slsa.StateInProgress:
			return &slsa.ControlRecommendedAction{
				Message: "Wait for provenance generator pull request to merge",
			}
		case slsa.StateNotEnabled:
			return &slsa.ControlRecommendedAction{
				Message: "Start generating provenance",
				Command: fmt.Sprintf("sourcetool setup controls --config=%s %s", models.CONFIG_GEN_PROVENANCE, r.Path),
			}
		default:
			return nil
		}
	case slsa.ContinuityEnforced:
		if state == slsa.StateNotEnabled {
			return &slsa.ControlRecommendedAction{
				Message: "Enable branch push/delete protection",
				Command: fmt.Sprintf("sourcetool setup controls --config=%s %s", models.CONFIG_BRANCH_RULES, r.Path),
			}
		}
		return nil
	case slsa.TagHygiene:
		if state == slsa.StateNotEnabled {
			return &slsa.ControlRecommendedAction{
				Message: "Enable tag push/update/delete protection",
				Command: fmt.Sprintf("sourcetool setup controls --config=%s %s", models.CONFIG_TAG_RULES, r.Path),
			}
		}
		return nil
	default:
		return nil
	}
}
