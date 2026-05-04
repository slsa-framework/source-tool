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
	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

// InherentControls are the controls that are always true because we are
// in git and/org GitHub.
var InherentControls = slsa.ControlNameSet{
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

func New(options *models.BackendOptions) *Backend {
	return &Backend{
		authenticator: auth.New(),
		Options:       options,
	}
}

type Options struct {
	UseFork bool
}

// Backend implemets the GitHub sourcetool backend
type Backend struct {
	authenticator *auth.Authenticator
	Options       *models.BackendOptions
}

// getGitHubConnection builds a github connector to a repository
func (b *Backend) getGitHubConnection(repository *models.Repository, ref string) (*ghcontrol.GitHubConnection, error) {
	
	return nil
}

func (b *Backend) GetBranchControls(ctx context.Context, branch *models.Branch) (*slsa.ControlSet, error) {
	return nil
}

// GetBranchControlsAtCommit
func (b *Backend) GetBranchControlsAtCommit(ctx context.Context, branch *models.Branch, commit *models.Commit) (*slsa.ControlSet, error) {
	return status, nil
}

// controlImplementationMessage returns an implementation message to populate the
// status message when controls are active.
func (b *Backend) controlImplementationMessage(ctrlName slsa.ControlName) string {
	return ""
}

func (b *Backend) GetTagControls(ctx context.Context, branch *models.Branch, tag *models.Tag) (*slsa.ControlSet, error) {
	return nil
}

func (b *Backend) ControlConfigurationDescr(branch *models.Branch, config models.ControlConfiguration) string {
	return ""
}

// GetLatestCommit returns the latest commit from a branch
func (b *Backend) GetLatestCommit(ctx context.Context, r *models.Repository, branch *models.Branch) (*models.Commit, error) {
	return nil
}

// GetRecommendedAction returns the recommended action based on the
// status of a SLSA control
func (b *Backend) getRecommendedAction(r *models.Repository, _ *models.Branch, control slsa.ControlName, state slsa.ControlState) *slsa.ControlRecommendedAction {
	return nil
}

// GetPreviousCommit takes a commit in
func (b *Backend) GetPreviousCommit(ctx context.Context, branch *models.Branch, commit *models.Commit) (*models.Commit, error) {
	return nil
}

// GetDefaultBranch returns the default branch
func (b *Backend) GetDefaultBranch(ctx context.Context, repo *models.Repository) (*models.Branch, error) {
	return nil
}

// GetRevisionCommit returns the commit of a revision (or error)
func (b *Backend) GetRevisionCommit(ctx context.Context, repo *models.Repository, rev models.Revision) (*models.Commit, error) {
	return nil
}