package gh_control

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/go-github/v69/github"
)

func (ghc *GitHubConnection) GetNotesForCommit(ctx context.Context, commit string) (string, error) {
	// We can find the notes for a given commit fairly easily.
	// They'll be in the path <commit> within ref `refs/notes/commits`

	contents, _, resp, err := ghc.Client().Repositories.GetContents(
		ctx, ghc.Owner(), ghc.Repo(), commit, &github.RepositoryContentGetOptions{Ref: "refs/notes/commits"})

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
