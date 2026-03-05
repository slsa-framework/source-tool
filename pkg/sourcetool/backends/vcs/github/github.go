// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/auth"
	"github.com/slsa-framework/source-tool/pkg/ghcontrol"
	"github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

// InherentControls are the controls that are always true because we are
// in git and/org GitHub.
var InherentControls = slsa.ControlSet{
	// GitHub uses git
	slsa.SLSA_SOURCE_ORG_SCS,

	// GitHub enforces access control
	slsa.SLSA_SOURCE_ORG_ACCESS_CONTROL,

	// There is no safe expunge in Git or GitHub but as long as users
	// cannot force push, then things cannot be expunged. So I think
	// it passes.
	// slsa.SLSA_SOURCE_ORG_SAFE_EXPUNGE,

	// All the org controls are default expect for expunge, so we tie
	// org continuity to the branch continuity
	// slsa.SLSA_SOURCE_ORG_CONTINUITY,

	// GitHub gives you a repo id/uri
	slsa.SLSA_SOURCE_SCS_REPO_ID,

	// Git commit
	slsa.SLSA_SOURCE_SCS_REVISION_ID,

	// git diff
	slsa.SLSA_SOURCE_SCS_DIFF_DISPLAY,

	// We disable VSA until checking we have one
	//	slsa.SLSA_SOURCE_SCS_VSA,

	// Git is change history
	slsa.SLSA_SOURCE_SCS_HISTORY,

	// We will compute continuity from the GH api
	// slsa.SLSA_SOURCE_SCS_CONTINUITY,

	// Both git and GitHub have user  identities
	slsa.SLSA_SOURCE_SCS_IDENTITY,

	// We disable provenance until we check we have an attestation
	// slsa.SLSA_SOURCE_SCS_PROVENANCE,

	// This depends on branch protection
	// slsa.SLSA_SOURCE_SCS_PROTECTED_REFS,

	// We will check for two party review in the API
	// slsa.SLSA_SOURCE_SCS_TWO_PARTY_REVIEW,
}

func New() *Backend {
	return &Backend{
		authenticator: auth.New(),
		Options:       Options{UseFork: true},
	}
}

type Options struct {
	UseFork bool
}

// Backend implemets the GitHub sourcetool backend
type Backend struct {
	authenticator *auth.Authenticator
	Options       Options
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

func (b *Backend) GetBranchControls(ctx context.Context, branch *models.Branch) (*slsa.ControlSetStatus, error) {
	if branch.Repository == nil {
		return nil, fmt.Errorf("branch has no repository")
	}
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

	return b.GetBranchControlsAtCommit(ctx, branch, &models.Commit{SHA: commit})
}

// GetBranchControlsAtCommit
func (b *Backend) GetBranchControlsAtCommit(ctx context.Context, branch *models.Branch, commit *models.Commit) (*slsa.ControlSetStatus, error) {
	if branch.Repository == nil {
		return nil, fmt.Errorf("branch has no repository")
	}

	if commit == nil {
		return nil, errors.New("commit is not set")
	}
	ghc, err := b.getGitHubConnection(branch.Repository, branch.FullRef())
	if err != nil {
		return nil, fmt.Errorf("getting github connection: %w", err)
	}

	// The branch controls returned from ghcontrol only include the 4
	// legacy checks sourcetool did (continuity, review, RequiredChecks, tag hygiene)
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
			Name: slsa.SLSA_SOURCE_SCS_PROVENANCE.String(),
		})

		// If we got the provenance attestaion, we assume we also have a VSA
		activeControls.AddControl(&provenance.Control{
			Name: slsa.SLSA_SOURCE_SCS_VSA.String(),
		})
	} else {
		log.Printf("No provenance attestation found on %s", commit.SHA)
	}

	// NewControlSetStatus returns all the controls for the framework in
	// StateNotEnabled.
	status := slsa.NewControlSetStatus()
	sinceForever := time.Unix(1, 0)
	for i, ctrl := range status.Controls {
		// Check if it's an inherent control, turn it on  and don't look back
		if c := InherentControls.GetControl(slsa.ControlName(ctrl.Name.String())); c != "" {
			status.Controls[i].Since = &sinceForever
			status.Controls[i].State = slsa.StateActive
			status.Controls[i].Message = "Inherent"
			continue
		}

		// Check if it's one of the active controls
		if c := activeControls.GetControl(ctrl.Name); c != nil {
			t := c.GetSince().AsTime()
			status.Controls[i].Since = &t
			status.Controls[i].State = slsa.StateActive
			status.Controls[i].Message = b.controlImplementationMessage(slsa.ControlName(c.GetName()))
		}

		// Enable ORG_SAFE_EXPUNGE when branch protection (protected refs) is active.
		// Without force push, content cannot be expunged.
		if ctrl.Name == slsa.SLSA_SOURCE_ORG_SAFE_EXPUNGE {
			if c := activeControls.GetControl(slsa.SLSA_SOURCE_SCS_PROTECTED_REFS); c != nil {
				t := c.GetSince().AsTime()
				status.Controls[i].Since = &t
				status.Controls[i].State = slsa.StateActive
				status.Controls[i].Message = b.controlImplementationMessage(ctrl.Name)
			}
		}

		// Enable ORG_CONTINUITY when SCS branch continuity is active.
		if ctrl.Name == slsa.SLSA_SOURCE_ORG_CONTINUITY {
			if c := activeControls.GetControl(slsa.SLSA_SOURCE_SCS_CONTINUITY); c != nil {
				t := c.GetSince().AsTime()
				status.Controls[i].Since = &t
				status.Controls[i].State = slsa.StateActive
				status.Controls[i].Message = b.controlImplementationMessage(ctrl.Name)
			}
		}
	}

	// The only control which can be in in_progress state in GitHub is
	// provenance generation when the PR is open but not merged. We check
	// here and report back the status.
	switchProvCtlToInProgress := false
	var provenanceMessage string
	if c := activeControls.GetControl(slsa.SLSA_SOURCE_SCS_PROVENANCE); c == nil {
		pr, err := b.FindWorkflowPR(ctx, branch.Repository)
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
		if switchProvCtlToInProgress && status.Controls[i].Name == slsa.SLSA_SOURCE_SCS_PROVENANCE {
			status.Controls[i].State = slsa.StateInProgress
			status.Controls[i].Message = provenanceMessage
		}
		action := b.getRecommendedAction(branch.Repository, branch, status.Controls[i].Name, status.Controls[i].State)
		status.Controls[i].RecommendedAction = action
	}

	return status, nil
}

// controlImplementationMessage returns an implementation message to populate the
// status message when controls are active.
func (b *Backend) controlImplementationMessage(ctrlName slsa.ControlName) string {
	//nolint:exhaustive
	switch ctrlName {
	case slsa.SLSA_SOURCE_SCS_PROVENANCE, slsa.DEPRECATED_ProvenanceAvailable:
		return "Signed provenance metadata is being published on every commit"
	case slsa.SLSA_SOURCE_SCS_PROTECTED_REFS, slsa.DEPRECATED_TagHygiene:
		return "Tag protections are configured in the repository"
	case slsa.DEPRECATED_ReviewEnforced:
		return "Code review is enforced in the repository"
	case slsa.SLSA_SOURCE_ORG_CONTINUITY, slsa.DEPRECATED_ContinuityEnforced:
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
			"Enable force push/update/delete protection for all tags in %s",
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
	case slsa.DEPRECATED_ProvenanceAvailable:
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
	case slsa.SLSA_SOURCE_ORG_CONTINUITY, slsa.DEPRECATED_ContinuityEnforced:
		if state == slsa.StateNotEnabled {
			return &slsa.ControlRecommendedAction{
				Message: "Enable branch push/delete protection",
				Command: fmt.Sprintf("sourcetool setup controls --config=%s %s", models.CONFIG_BRANCH_RULES, r.Path),
			}
		}
		return nil
	case slsa.SLSA_SOURCE_SCS_PROTECTED_REFS, slsa.DEPRECATED_TagHygiene:
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
