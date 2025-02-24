package gh_control

import (
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

// Returns the fully qualified branch (e.g. 'refs/heads/main').
func (ghc GitHubConnection) GetFullBranch() string {
	return fmt.Sprintf("refs/heads/%s", ghc.Branch)
}

// Returns the URI of the repo this connection tracks.
func (ghc GitHubConnection) GetRepoUri() string {
	return fmt.Sprintf("https://github.com/%s/%s", ghc.Owner, ghc.Repo)
}
