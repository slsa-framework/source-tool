package ghcontrol

import (
	"context"
	"fmt"
	"os"

	"github.com/google/go-github/v69/github"
)

const tokenEnvVar = "GITHUB_TOKEN" //nolint:gosec // These are not credentials

// Manages a connection to a GitHub repository.
type GitHubConnection struct {
	client           *github.Client
	Options          Options
	owner, repo, ref string
}

func NewGhConnection(owner, repo, ref string) *GitHubConnection {
	return NewGhConnectionWithClient(owner, repo, ref, github.NewClient(nil))
}

func NewGhConnectionWithClient(owner, repo, ref string, client *github.Client) *GitHubConnection {
	opts := defaultOptions

	// If the token is in the environment capture it now.
	if t := os.Getenv(tokenEnvVar); t != "" {
		opts.accessToken = t
		if client != nil {
			client = client.WithAuthToken(t)
		}
	}

	return &GitHubConnection{
		client:  client,
		owner:   owner,
		repo:    repo,
		ref:     ref,
		Options: opts,
	}
}

func (ghc *GitHubConnection) Client() *github.Client {
	return ghc.client
}

func (ghc *GitHubConnection) Owner() string {
	return ghc.owner
}

func (ghc *GitHubConnection) Repo() string {
	return ghc.repo
}

func (ghc *GitHubConnection) GetFullRef() string {
	return ghc.ref
}

// Uses the provide token for auth.
// If the token is the empty string this is a no-op.
func (ghc *GitHubConnection) WithAuthToken(token string) *GitHubConnection {
	if token != "" {
		ghc.Options.accessToken = token
		ghc.client = ghc.client.WithAuthToken(ghc.Options.accessToken)
	}
	return ghc
}

// Returns the URI of the repo this connection tracks.
func (ghc *GitHubConnection) GetRepoUri() string {
	return fmt.Sprintf("https://github.com/%s/%s", ghc.Owner(), ghc.Repo())
}

// Gets the previous commit to 'sha' if it has one.
// If there are more than one parents this fails with an error.
// (This tool generally operates in an environment of linear history)
func (ghc *GitHubConnection) GetPriorCommit(ctx context.Context, sha string) (string, error) {
	commit, _, err := ghc.Client().Git.GetCommit(ctx, ghc.Owner(), ghc.Repo(), sha)
	if err != nil {
		return "", fmt.Errorf("cannot get commit data for %s: %w", sha, err)
	}

	if len(commit.Parents) == 0 {
		return "", fmt.Errorf("there is no commit earlier than %s, that isn't yet supported", sha)
	}

	if len(commit.Parents) > 1 && !ghc.Options.AllowMergeCommits {
		return "", fmt.Errorf("commit %s has more than one parent (%v), which is not supported", sha, commit.Parents)
	}

	return *commit.Parents[0].SHA, nil
}

func (ghc *GitHubConnection) GetLatestCommit(ctx context.Context, targetBranch string) (string, error) {
	branch, _, err := ghc.Client().Repositories.GetBranch(ctx, ghc.Owner(), ghc.Repo(), targetBranch, 1)
	if err != nil {
		return "", fmt.Errorf("could not get info on specified branch %s: %w", targetBranch, err)
	}
	return *branch.Commit.SHA, nil
}

// GetDefaultBranch reads the default repository branch from the GitHub API
func (ghc *GitHubConnection) GetDefaultBranch(ctx context.Context) (string, error) {
	repo, _, err := ghc.Client().Repositories.Get(ctx, ghc.owner, ghc.repo)
	if err != nil {
		return "", fmt.Errorf("fetching repository data: %w", err)
	}

	return repo.GetDefaultBranch(), nil
}
