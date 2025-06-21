package sourcetool

import (
	"context"
	"errors"
	"fmt"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/ghcontrol"
)

type Options struct {
	Repo   string
	Owner  string
	Branch string
	Commit string
}

// DefaultOptions holds the default options the tool initializes with
var DefaultOptions = Options{}

// GetGitHubConnection creates a new github connection to the repository
// defined in the options set.
func (o *Options) GetGitHubConnection() (*ghcontrol.GitHubConnection, error) {
	if o.Owner == "" {
		return nil, errors.New("owner not set")
	}
	if o.Repo == "" {
		return nil, errors.New("repository not set")
	}

	return ghcontrol.NewGhConnection(o.Owner, o.Repo, o.Branch), nil
}

// EnsureCommit checks the options have a commit sha defined. If not, then
// the latest commit from the loaded branch is read from the GitHub API.
func (o *Options) EnsureCommit() error {
	if o.Commit != "" {
		return nil
	}

	if o.Branch == "" {
		return errors.New("unable to fetch latest commit, no branch defined")
	}

	ghc, err := o.GetGitHubConnection()
	if err != nil {
		return fmt.Errorf("getting GitHub connection: %w", err)
	}

	commit, err := ghc.GetLatestCommit(context.Background(), o.Branch)
	if err != nil {
		return fmt.Errorf("fetching latest commit: %w", err)
	}
	o.Commit = commit
	return nil
}

// EnsureBranch checks that the options set has a branch set and if not, it
// reads the repository's default branch from the GitHub API.
func (o *Options) EnsureBranch() error {
	if o.Branch != "" {
		return nil
	}

	ghc, err := o.GetGitHubConnection()
	if err != nil {
		return fmt.Errorf("getting GitHub connection: %w", err)
	}

	branch, err := ghc.GetDefaultBranch(context.Background())
	if err != nil {
		return fmt.Errorf("fetching default branch: %w", err)
	}
	o.Branch = branch
	return nil
}

type ooFn func(*Options) error

func WithRepo(repo string) ooFn {
	return func(o *Options) error {
		// TODO(puerco): Validate repo string
		o.Repo = repo
		return nil
	}
}

func WithOwner(repo string) ooFn {
	return func(o *Options) error {
		// TODO(puerco): Validate org string
		o.Owner = repo
		return nil
	}
}

func WithBranch(branch string) ooFn {
	return func(o *Options) error {
		o.Branch = branch
		return nil
	}
}

func WithCommit(commit string) ooFn {
	return func(o *Options) error {
		o.Commit = commit
		return nil
	}
}
