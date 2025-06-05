package gh_control

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/go-github/v69/github"
)

// GetNotesForCommit returns the unparsed notes blob for a commit as stored in git via the GitHub API.
func (ghc *GitHubConnection) GetNotesForCommit(ctx context.Context, commit string) (string, error) {
	// We can find the notes for a given commit fairly easily.
	// They'll be in the path <co/mmit> within ref `refs/notes/commits`
	// where the first two characters of the commit sha are separated from the
	// rest with a slash, eg e5/73149ab3e574abc2e5a151a04acfaf2a59b453.
	path := commit[0:2] + "/" + commit[2:]
	contents, _, resp, err := ghc.Client().Repositories.GetContents(
		ctx, ghc.Owner(), ghc.Repo(), path, &github.RepositoryContentGetOptions{Ref: "refs/notes/commits"})

	if resp.StatusCode == http.StatusNotFound {
		// Don't freak out if it's not there.
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("cannot get note contents for commit %s: %w", commit, err)
	}
	if contents == nil {
		// No notes stored for this commit.
		return "", nil
	}

	return contents.GetContent()
}
