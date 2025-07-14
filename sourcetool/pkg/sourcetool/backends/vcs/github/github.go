package github

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/auth"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/models"
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

func (b *Backend) GetBranchControls(ctx context.Context, branch *models.Branch) (*slsa.Controls, error) {
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
func (b *Backend) GetBranchControlsAtCommit(ctx context.Context, branch *models.Branch, commit *models.Commit) (*slsa.Controls, error) {
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
		activeControls.AddControl(&slsa.Control{
			Name: slsa.ProvenanceAvailable,
		})
	} else {
		log.Printf("No provenance attestation found on %s", commit.SHA)
	}

	return activeControls, nil
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
