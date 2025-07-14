package sourcetool

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-github/v69/github"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/auth"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/policy"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/repo"
	roptions "github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/repo/options"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/backends/attestation/notes"
	ghbackend "github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/backends/vcs/github"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/models"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/options"
)

const (
	tokenVar = "GITHUB_TOKEN" //nolint:gosec // This are not creds, just the name
)

// toolImplementation defines the mockable implementation of source tool
//
//counterfeiter:generate . toolImplementation
type toolImplementation interface {
	VerifyOptionsForFullOnboard(*options.Options) error
	CheckPolicyFork(*options.Options) error
	CreatePolicyPR(*auth.Authenticator, *options.Options, *models.Repository, *policy.RepoPolicy) (*models.PullRequest, error)
	CheckForks(*options.Options) error
	SearchPullRequest(*auth.Authenticator, *models.Repository, string) (int, error)
	GetVcsBackend(*models.Repository) (models.VcsBackend, error)
	GetAttestationReader(*models.Repository) (models.AttestationStorageReader, error)
	GetBranchControls(context.Context, models.VcsBackend, *models.Branch) (*slsa.Controls, error)
	ConfigureControls(models.VcsBackend, *models.Repository, []*models.Branch, []models.ControlConfiguration) error
}

type defaultToolImplementation struct{}

func (impl *defaultToolImplementation) ConfigureControls(
	backend models.VcsBackend, r *models.Repository,
	branches []*models.Branch, configs []models.ControlConfiguration,
) error {
	return backend.ConfigureControls(r, branches, configs)
}

func (impl *defaultToolImplementation) GetBranchControls(
	ctx context.Context, backend models.VcsBackend, branch *models.Branch,
) (*slsa.Controls, error) {
	return backend.GetBranchControls(context.Background(), branch)
}

// GetAttestationReader returns the att reader object
func (impl *defaultToolImplementation) GetAttestationReader(_ *models.Repository) (models.AttestationStorageReader, error) {
	// We only have the notes backend for now
	return notes.New(), nil
}

// GetVcsBackend returns the VCS backend to handle the repository defined in the options
func (impl *defaultToolImplementation) GetVcsBackend(*models.Repository) (models.VcsBackend, error) {
	// for now we only support github, so there
	return ghbackend.New(), nil
}

// VerifyOptions checks options are in good shape to run
func (impl *defaultToolImplementation) VerifyOptionsForFullOnboard(opts *options.Options) error {
	errs := []error{}
	// if opts.Repo == "" {
	// 	errs = append(errs, errors.New("no repository name defined"))
	// }

	// if opts.Owner == "" {
	// 	errs = append(errs, errors.New("no repository owner defined"))
	// }

	if t := os.Getenv(tokenVar); t == "" {
		errs = append(errs, fmt.Errorf("$%s environment variable not set", tokenVar))
	}

	return errors.Join(errs...)
}

// CreatePolicyPR creates a pull request to push the policy
func (impl *defaultToolImplementation) CreatePolicyPR(a *auth.Authenticator, opts *options.Options, r *models.Repository, p *policy.RepoPolicy) (*models.PullRequest, error) {
	if p == nil {
		return nil, fmt.Errorf("policy is nil")
	}
	repoOwner, repoName, err := r.PathAsGitHubOwnerName()
	if err != nil {
		return nil, err
	}

	// Check the repository clone in the user's account is ready to push
	if err := impl.CheckPolicyFork(opts); err != nil {
		return nil, fmt.Errorf("checking policy repository fork: %w", err)
	}

	// MArshal the policy json
	policyJson, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling policy data: %w", err)
	}

	// Create a pull request manager
	prManager := repo.NewPullRequestManager(repo.WithAuthenticator(a))

	// TODO(puerco): Honor forks settings, etc

	// Open the pull request
	pr, err := prManager.PullRequestFileList(
		r,
		&roptions.PullRequestFileListOptions{
			Title: fmt.Sprintf("Add %s/%s SLSA Source policy file", repoOwner, repoName),
			Body:  fmt.Sprintf(`This pull request adds the SLSA source policy for github.com/%s/%s`, repoOwner, repoName),
		},
		[]*repo.PullRequestFileEntry{
			{
				Path:   fmt.Sprintf("policy/github.com/%s/%s/source-policy.json", repoOwner, repoName),
				Reader: bytes.NewReader(policyJson),
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("creating policy pull request: %w", err)
	}
	return pr, nil
}

// CheckForks checks that the user has forks of the required repositories
func (impl *defaultToolImplementation) CheckForks(opts *options.Options) error {
	errs := []error{}
	if err := impl.CheckPolicyFork(opts); err != nil {
		errs = append(errs, err)
	}

	// Here, we had the workflow fork but it does not belong here anymore

	return errors.Join(errs...)
}

func (impl *defaultToolImplementation) CheckPolicyFork(opts *options.Options) error {
	manager := repo.NewPullRequestManager()
	if _, err := manager.CheckFork(&models.Repository{
		Hostname: "github.com", Path: opts.PolicyRepo,
	}, ""); err != nil {
		return err
	}
	return nil
}

// SearchPullRequest searches the last pull requests on a repo for one whose
// title matches the query string
func (impl *defaultToolImplementation) SearchPullRequest(a *auth.Authenticator, r *models.Repository, query string) (int, error) {
	owner, repoName, err := r.PathAsGitHubOwnerName()
	if err != nil {
		return 0, err
	}

	client, err := a.GetGitHubClient()
	if err != nil {
		return 0, err
	}

	prs, _, err := client.PullRequests.List(
		context.Background(), owner, repoName, &github.PullRequestListOptions{
			State: "open",
		},
	)
	if err != nil {
		return 0, fmt.Errorf("listing pull requests: %w", err)
	}

	for _, pr := range prs {
		if strings.Contains(pr.GetTitle(), query) {
			return pr.GetNumber(), nil
		}
	}
	return 0, nil
}
