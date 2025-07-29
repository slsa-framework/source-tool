package repo

import (
	"fmt"
	"io"

	"github.com/slsa-framework/slsa-source-poc/pkg/auth"
	"github.com/slsa-framework/slsa-source-poc/pkg/repo/options"
	"github.com/slsa-framework/slsa-source-poc/pkg/sourcetool/models"
)

func NewPullRequestManager(fn ...OptFn) *PullRequestManager {
	prm := &PullRequestManager{
		impl: &defaultPrmImpl{},
		Options: options.PullRequestManagerOptions{
			RemoteName: "destination",
		},
	}

	for _, f := range fn {
		f(prm)
	}

	if prm.authenticator == nil {
		prm.authenticator = auth.New()
	}
	return prm
}

type OptFn func(*PullRequestManager)

func WithAuthenticator(a *auth.Authenticator) OptFn {
	return func(prm *PullRequestManager) {
		if a == nil {
			return
		}
		prm.authenticator = a
	}
}

// PullRequestManager is a tool to create and manage pull requests on a GitHub
// repository.
type PullRequestManager struct {
	impl          prManagerImplementation
	Options       options.PullRequestManagerOptions
	authenticator *auth.Authenticator
}

// PullRequestFileEntry packs an io Reader and a path to write into a cloned repo
type PullRequestFileEntry struct {
	// Path is the path where the data will be wirtten, relative to the clone fs root
	Path string

	// io Reader to read the file data
	Reader io.Reader
}

// CloneRepo clones the remote repository either to disk or to a memory filesystem
func (prm *PullRequestManager) CloneRepo(repo *models.Repository) (*Clone, error) {
	// FIME: Check fork
	return prm.impl.CloneRepo(&prm.Options, prm.authenticator, repo)
}

// CheckFork verifies that the logged in user has a fork of the specified repo.
// If a name is specified, then the function will look for a repo with a different
// name than the forked source.
func (prm *PullRequestManager) CheckFork(repo *models.Repository, forkName string) (*models.Repository, error) {
	return prm.impl.CheckFork(&prm.Options, prm.authenticator, repo, forkName)
}

// CreatePullRequest opens a pull request in a repository
func (prm *PullRequestManager) CreatePullRequest(repo *models.Repository, opts *options.PullRequestOptions) (*models.PullRequest, error) {
	return prm.impl.CreatePullRequest(&prm.Options, prm.authenticator, repo, opts)
}

// PullRequestFiles gets a list of files and opens a pull request in a repo
// to check them in. If the files already exist in the repo they will be
// updated with the new versions.
func (prm *PullRequestManager) PullRequestFileList(
	repo *models.Repository, opts *options.PullRequestFileListOptions, files []*PullRequestFileEntry,
) (*models.PullRequest, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("no files specified")
	}

	// Clone the repository
	clone, err := prm.impl.CloneRepo(&prm.Options, prm.authenticator, repo)
	if err != nil {
		return nil, fmt.Errorf("cloning repo: %w", err)
	}
	// This should never happen but makes tests easier
	if clone != nil {
		defer clone.Cleanup()
	}

	// Create the branch in the clone
	if err := clone.CreateFeatureBranch(); err != nil {
		return nil, fmt.Errorf("creating feature branch: %w", err)
	}

	// Copy all the files into the clone filesystem
	if err := prm.impl.CopyFilesToClone(clone, files); err != nil {
		return nil, fmt.Errorf("copying files to cloned repo: %w", err)
	}

	if err := prm.impl.CommitChanges(opts, clone); err != nil {
		return nil, fmt.Errorf("committing changes to remote: %w", err)
	}

	if err := prm.impl.PushFeatureBranch(&prm.Options, clone); err != nil {
		return nil, fmt.Errorf("pushing feature branch to remote: %w", err)
	}

	// Use the base branch from the options, unless not set we use the default
	baseBranch := opts.BaseBranch
	if baseBranch == "" {
		baseBranch = clone.DefaultBranch
	}

	// Open the PR
	return prm.impl.CreatePullRequest(
		&prm.Options, prm.authenticator, repo,
		&options.PullRequestOptions{
			Title: opts.Title,
			Body:  opts.Body,
			Head:  clone.FeatureBranch,
			Base:  baseBranch,
		},
	)
}
