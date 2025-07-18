//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
package repo

import (
	"context"
	"fmt"
	"net/http"
	"os"

	billy "github.com/go-git/go-billy/v6"
	memfs "github.com/go-git/go-billy/v6/memfs"
	"github.com/go-git/go-billy/v6/osfs"
	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing/cache"
	ghttp "github.com/go-git/go-git/v6/plumbing/transport/http"
	"github.com/go-git/go-git/v6/storage"
	"github.com/go-git/go-git/v6/storage/filesystem"
	"github.com/go-git/go-git/v6/storage/memory"
	"github.com/google/go-github/v69/github"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/auth"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/repo/options"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/models"
)

//counterfeiter:generate . prManagerImplementation
type prManagerImplementation interface {
	CopyFilesToClone(*Clone, []*PullRequestFileEntry) error
	CloneRepo(*options.PullRequestManagerOptions, *auth.Authenticator, *models.Repository) (*Clone, error)
	CheckFork(*options.PullRequestManagerOptions, *auth.Authenticator, *models.Repository, string) (*models.Repository, error)
	CommitChanges(*options.PullRequestFileListOptions, *Clone) error
	PushFeatureBranch(*options.PullRequestManagerOptions, *Clone) error
	CreatePullRequest(*options.PullRequestManagerOptions, *auth.Authenticator, *models.Repository, *options.PullRequestOptions) (*models.PullRequest, error)
}

type defaultPrmImpl struct{}

func (impl *defaultPrmImpl) CopyFilesToClone(clone *Clone, files []*PullRequestFileEntry) error {
	return clone.AddFiles(clone, files)
}

// CloneRepo clones a repository and returns a clone object
func (impl *defaultPrmImpl) CloneRepo(opts *options.PullRequestManagerOptions, a *auth.Authenticator, repo *models.Repository) (*Clone, error) {
	var (
		tmpDir string
		storer storage.Storer
		fs     billy.Filesystem
	)

	// If using a fork, verify it exists
	var forkRepo *models.Repository
	if opts.UseFork {
		var err error
		forkRepo, err = impl.CheckFork(opts, a, repo, opts.ForkName)
		if err != nil {
			return nil, fmt.Errorf("verifying user fork: %w", err)
		}
	}

	token, err := a.ReadToken()
	if err != nil {
		return nil, err
	}

	// Depending on the options, we clone to memory or to disk
	if opts.CloneToMemory {
		storer = memory.NewStorage()
		fs = memfs.New()
	} else {
		tmpDir, err = os.MkdirTemp("", "pullrequest-")
		if err != nil {
			return nil, fmt.Errorf("creating a tmpdir: %w", err)
		}
		// Remove the directory to let the clone reacreate it
		if err := os.Remove(tmpDir); err != nil {
			return nil, fmt.Errorf("removing tmp dir: %w", err)
		}

		// This is the osfs where we'll clone all files
		fs = osfs.New(tmpDir)
		// Then we create chrooted copy of the FS to store the git data
		dotgit, err := fs.Chroot(".git")
		if err != nil {
			return nil, fmt.Errorf("creating chrooted git fs: %w", err)
		}
		storer = filesystem.NewStorageWithOptions(
			dotgit, cache.NewObjectLRUDefault(), filesystem.Options{},
		)
	}

	// Perform the clone operation
	gitRepo, err := git.Clone(storer, fs, &git.CloneOptions{
		Auth: &ghttp.BasicAuth{
			Username: "user",
			Password: token,
		},
		URL: repo.GetHttpURL(),
	})
	if err != nil {
		return nil, fmt.Errorf("cloning repo: %w", err)
	}

	// Return the clone options
	clone := &Clone{
		TmpDir:     tmpDir,
		Repository: *repo,
		repo:       gitRepo,
		fs:         fs,
	}

	// Get the name of the current branch which is the default
	head, err := clone.repo.Head()
	if err != nil {
		return nil, fmt.Errorf("unable to read HEAD from repository clone")
	}
	clone.DefaultBranch = head.Name().Short()

	// If we are using a fork, add it as remote, otherwise use the same
	// URL as origin to simplify pushing.
	//
	// Note that forkRepo could be nil when UseFork is set but the repo
	// is in the same org as the user.
	if opts.UseFork && forkRepo != nil {
		err = clone.AddRemote(
			opts.RemoteName, fmt.Sprintf("https://user:%s@%s/%s", token, forkRepo.Hostname, forkRepo.Path),
		)
	} else {
		err = clone.AddRemote(
			opts.RemoteName, fmt.Sprintf("https://user:%s@%s/%s", token, repo.Hostname, repo.Path),
		)
	}
	if err != nil {
		clone.Cleanup()
		return nil, fmt.Errorf("adding remote: %w", err)
	}

	return clone, nil
}

// CheckFork checks if the user has a fork of the repository
func (impl *defaultPrmImpl) CheckFork(opts *options.PullRequestManagerOptions, a *auth.Authenticator, repo *models.Repository, forkedRepoName string) (*models.Repository, error) {
	repoOwner, repoName, err := repo.PathAsGitHubOwnerName()
	if err != nil {
		return nil, err
	}

	// The fork name is by default the same as the source, unless there is
	// another name defined
	if forkedRepoName == "" {
		forkedRepoName = repoName
	}

	// Get the authenticated GitHub client
	client, err := a.GetGitHubClient()
	if err != nil {
		return nil, fmt.Errorf("creating authenticated GH client: %w", err)
	}

	// If we're using a fork, get the user's creds to look for the repo
	user, err := a.WhoAmI()
	if err != nil {
		return nil, fmt.Errorf("checking user from credentials: %w", err)
	}

	// If the repository owner is the sames as the logged in user, we dont
	// check for a fork as you cannot have a fork in the same org
	if repoOwner == user.GetLogin() {
		// At some point a warning here would be useful
		return nil, nil
	}

	// Query the user repo data from the GitHub API:
	r, resp, err := client.Repositories.Get(context.Background(), user.GetLogin(), forkedRepoName)
	if err != nil {
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf(
				"user %s does not have a fork of %s/%s",
				user.GetLogin(), repoOwner, repoName,
			)
		}
		return nil, fmt.Errorf("getting fork info: %w", err)
	}

	if !r.GetFork() {
		return nil, fmt.Errorf("%s/%s is not a fork", user.GetLogin(), forkedRepoName)
	}

	if r.GetSource() == nil {
		return nil, fmt.Errorf("unable to read source repo of %s/%s", user.GetLogin(), forkedRepoName)
	}

	if r.GetSource().GetFullName() != fmt.Sprintf("%s/%s", repoOwner, repoName) {
		return nil, fmt.Errorf(
			"%s/%s is a fork but not of %s/%s",
			user.GetLogin(), forkedRepoName, repoOwner, repoName,
		)
	}

	hname := repo.Hostname
	if hname == "" {
		hname = "github.com"
	}
	return &models.Repository{
		Hostname: hname,
		Path:     fmt.Sprintf("%s/%s", user.GetLogin(), forkedRepoName),
	}, nil
}

func (impl *defaultPrmImpl) CommitChanges(opts *options.PullRequestFileListOptions, clone *Clone) error {
	msg := opts.Title + "\n\n" + opts.Body
	if opts.CommitOptions.Message != "" {
		msg = opts.CommitOptions.Message
	}

	// Create the commit in the fork
	err := clone.Commit(&options.CommitOptions{
		UseGit:  opts.CommitOptions.UseGit,
		Message: msg,
		Name:    opts.CommitOptions.Name,
		Email:   opts.CommitOptions.Email,
	})
	if err != nil {
		return fmt.Errorf("creating commit: %w", err)
	}

	return nil
}

func (impl *defaultPrmImpl) PushFeatureBranch(opts *options.PullRequestManagerOptions, clone *Clone) error {
	return clone.PushRemote(opts.RemoteName)
}

func (impl *defaultPrmImpl) CreatePullRequest(
	opts *options.PullRequestManagerOptions, a *auth.Authenticator,
	repo *models.Repository, propts *options.PullRequestOptions,
) (*models.PullRequest, error) {
	owner, repoName, err := repo.PathAsGitHubOwnerName()
	if err != nil {
		return nil, err
	}

	// Get the authenticated GitHub client
	client, err := a.GetGitHubClient()
	if err != nil {
		return nil, fmt.Errorf("creating authenticated GH client: %w", err)
	}

	// Compute the head branch name
	headBranch := propts.Head
	if opts.UseFork {
		user, err := a.WhoAmI()
		if err != nil {
			return nil, fmt.Errorf("getting user identity: %w", err)
		}
		if owner != user.GetLogin() {
			headBranch = user.GetLogin() + ":" + propts.Head
		}
	}

	// Create the PR spec to give it to GitHub
	newPullRequest := &github.NewPullRequest{
		Title:               &propts.Title,
		Body:                &propts.Body,
		Head:                &headBranch, // Head must have the fork already
		Base:                &propts.Base,
		MaintainerCanModify: github.Ptr(true),
	}

	// Create the PR on the repo
	pr, _, err := client.PullRequests.Create(context.Background(), owner, repoName, newPullRequest)
	if err != nil {
		return nil, fmt.Errorf(
			"creating pull request to %s/%s@%s from %s: %w",
			owner, repoName, propts.Base, headBranch, err,
		)
	}

	return &models.PullRequest{
		Repo:   repo,
		Number: pr.GetNumber(),
		Title:  propts.Title,
		Body:   propts.Body,
		Head:   headBranch,
		Base:   propts.Head,
	}, nil
}
