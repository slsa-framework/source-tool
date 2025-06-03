package gh_control

import (
	"context"
	"fmt"

	"github.com/google/go-github/v69/github"
)

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
	return &GitHubConnection{
		client:  client,
		owner:   owner,
		repo:    repo,
		ref:     ref,
		Options: defaultOptions,
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
		ghc.client = ghc.client.WithAuthToken(token)
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
