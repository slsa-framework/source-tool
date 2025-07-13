package sourcetool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v69/github"
	"github.com/sirupsen/logrus"
	kgithub "sigs.k8s.io/release-sdk/github"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/auth"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/policy"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/repo"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
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
	CreatePolicyPR(options.Options, *models.Repository, []*models.Branch) error
	CheckForks(*options.Options) error
	SearchPullRequest(*auth.Authenticator, *models.Repository, string) (int, error)
	GetVcsBackend(*models.Repository) (models.VcsBackend, error)
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

// FIXME: Port this to pullreq manager
// CreatePolicyPR creates a pull request to push the policy
func (impl *defaultToolImplementation) CreatePolicyPR(opts options.Options, r *models.Repository, branches []*models.Branch) error {
	// Branchname to be created on the user's fork
	branchname := fmt.Sprintf("slsa-source-policy-%d", time.Now().Unix())

	owner, repoName, err := r.PathAsGitHubOwnerName()
	if err != nil {
		return err
	}

	gh := kgithub.New()
	policyOrg, policyRepo, ok := strings.Cut(opts.PolicyRepo, "/")
	if !ok || policyRepo == "" {
		return fmt.Errorf("unable to parse policy repository slug")
	}

	userForkOrg := opts.UserForkOrg
	userForkRepo := policyRepo // For now we only support forks with the same name

	// Clone the slsa repo
	gitCloneOpts := &gogit.CloneOptions{Depth: 1}
	gitRepo, err := kgithub.PrepareFork(
		branchname, policyOrg, policyRepo,
		userForkOrg, userForkRepo,
		opts.UseSSH, opts.UpdateRepo, gitCloneOpts,
	)
	if err != nil {
		return fmt.Errorf("while preparing Slsa Source fork: %w", err)
	}

	defer func() {
		gitRepo.Cleanup() //nolint:errcheck,gosec
	}()

	// Create the policy in the local clone
	// FIXME: this needs fixing, the policy needs to handle all branches
	ghc := ghcontrol.NewGhConnection(owner, repoName, branches[0].Name).WithAuthToken(os.Getenv(tokenVar))
	outpath, err := policy.CreateLocalPolicy(context.Background(), ghc, gitRepo.Dir())
	if err != nil {
		return fmt.Errorf("creating local policy: %w", err)
	}

	// add the modified manifest to staging
	logrus.Debugf("Adding %s to staging area", outpath)
	if err := gitRepo.Add(strings.TrimPrefix(strings.TrimPrefix(outpath, gitRepo.Dir()), "/")); err != nil {
		return fmt.Errorf("adding new policy file to staging area: %w", err)
	}

	commitMessage := fmt.Sprintf("Add %s/%s SLSA Source policy file", owner, repoName)

	// Commit files
	if err := gitRepo.UserCommit(commitMessage); err != nil {
		return fmt.Errorf("creating commit in %s/%s: %w", policyOrg, policyRepo, err)
	}

	// Push to fork
	logrus.Infof("Pushing policy commit to %s/%s", userForkOrg, userForkRepo)
	if err := gitRepo.PushToRemote(kgithub.UserForkName, branchname); err != nil {
		return fmt.Errorf("pushing %s to %s/%s: %w", kgithub.UserForkName, userForkOrg, userForkRepo, err)
	}

	prBody := fmt.Sprintf(`This pull request adds the SLSA source policy for github.com/%s/%s`, owner, repoName)

	// Create the Pull Request
	pr, err := gh.CreatePullRequest(
		policyOrg, policyRepo, "main",
		fmt.Sprintf("%s:%s", userForkOrg, branchname),
		commitMessage, prBody, false,
	)
	if err != nil {
		logrus.Infof("%+v", err)
		return fmt.Errorf("creating the policy PR in %s/%s: %w", policyOrg, policyRepo, err)
	}
	logrus.Infof(
		"Successfully created PR: %s%s/%s/pull/%d",
		kgithub.GitHubURL, policyOrg, policyRepo, pr.GetNumber(),
	)

	// Success!
	return nil
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
