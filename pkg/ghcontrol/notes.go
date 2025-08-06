// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package ghcontrol

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/go-github/v69/github"
)

// GetNotesForCommit returns the unparsed notes blob for a commit as stored in
// git via the GitHub API. If no notes data can be found at the specified commit
// GetNotesForCommit returns a blank string (and no error).
func (ghc *GitHubConnection) GetNotesForCommit(ctx context.Context, commit string) (string, error) {
	// We can find the notes for a given commit fairly easily.
	// They'll be in the path <co/mmit> within ref `refs/notes/commits`
	// where the first two characters of the commit sha are separated from the
	// rest with a slash, eg e5/73149ab3e574abc2e5a151a04acfaf2a59b453.
	if len(commit) != 40 {
		return "", fmt.Errorf("invalid commit string")
	}

	path := commit[0:2] + "/" + commit[2:]
	contents, _, resp, err := ghc.Client().Repositories.GetContents(
		ctx, ghc.Owner(), ghc.Repo(), path, &github.RepositoryContentGetOptions{Ref: "refs/notes/commits"})

	if resp.StatusCode == http.StatusNotFound {
		// If we got a 404, look for the note in a file at the top-level
		// directory of refs/notes/commits. We brute force this call after
		// trying the sharded path above as notes will be found using this
		// path only when there is a small number of notes in the repo.
		//
		// See  https://github.com/slsa-framework/source-tool/issues/215
		contents, _, resp, err = ghc.Client().Repositories.GetContents(
			ctx, ghc.Owner(), ghc.Repo(), commit,
			&github.RepositoryContentGetOptions{Ref: "refs/notes/commits"},
		)
		if resp.StatusCode == http.StatusNotFound {
			return "", nil
		}
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
