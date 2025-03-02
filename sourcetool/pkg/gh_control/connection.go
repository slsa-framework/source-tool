package gh_control

import (
	"context"
	"fmt"

	"github.com/google/go-github/v69/github"
)

type GitHubConnection struct {
	Client              *github.Client
	Owner, Repo, Branch string
}

func NewGhConnection(owner, repo, branch string) *GitHubConnection {
	return &GitHubConnection{
		Client: github.NewClient(nil),
		Owner:  owner,
		Repo:   repo,
		Branch: branch}
}

// Uses the provide token for auth.
// If the token is the empty string this is a no-op.
func (ghc *GitHubConnection) WithAuthToken(token string) *GitHubConnection {
	if token != "" {
		ghc.Client = ghc.Client.WithAuthToken(token)
	}
	return ghc
}

// Returns the fully qualified branch (e.g. 'refs/heads/main').
func (ghc *GitHubConnection) GetFullBranch() string {
	return fmt.Sprintf("refs/heads/%s", ghc.Branch)
}

// Returns the URI of the repo this connection tracks.
func (ghc *GitHubConnection) GetRepoUri() string {
	return fmt.Sprintf("https://github.com/%s/%s", ghc.Owner, ghc.Repo)
}

func (ghc *GitHubConnection) GetLatestCommit(ctx context.Context) (string, error) {
	branch, _, err := ghc.Client.Repositories.GetBranch(ctx, ghc.Owner, ghc.Repo, ghc.Branch, 1)
	if err != nil {
		return "", fmt.Errorf("could not get info on specified branch %s: %w", ghc.Branch, err)
	}
	return *branch.Commit.SHA, nil
}

// Gets the previous commit to 'sha' if it has one.
// If there are more than one parents this fails with an error.
// (This tool generally operates in an environment of linear history)
func (ghc *GitHubConnection) GetPriorCommit(ctx context.Context, sha string) (string, error) {
	commit, _, err := ghc.Client.Git.GetCommit(ctx, ghc.Owner, ghc.Repo, sha)
	if err != nil {
		return "", fmt.Errorf("cannot get commit data for %s: %w", sha, err)
	}

	if len(commit.Parents) == 0 {
		return "", fmt.Errorf("there is no commit earlier than %s, that isn't yet supported", sha)
	}

	if len(commit.Parents) > 1 {
		return "", fmt.Errorf("commit %s has more than one parent (%v), which is not supported", sha, commit.Parents)
	}

	return *commit.Parents[0].SHA, nil
}
