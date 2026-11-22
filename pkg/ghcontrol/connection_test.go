// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package ghcontrol

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/google/go-github/v88/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/require"
)

// Simple test to ensure the connector noops when the token passed is an empty string
func TestWithAuthToken(t *testing.T) {
	t.Parallel()
	t.Run("token-nil", func(t *testing.T) {
		t.Parallel()
		ghc := NewGhConnection("test", "test", "main")
		ghc.Options.accessToken = "abc"
		ghc.WithAuthToken("")
		require.Equal(t, "abc", ghc.Options.accessToken)
	})

	t.Run("token-not-nil", func(t *testing.T) {
		t.Parallel()
		ghc := NewGhConnection("test", "test", "main")
		ghc.Options.accessToken = "abc"
		ghc.WithAuthToken("abc1234")
		require.Equal(t, "abc1234", ghc.Options.accessToken)
	})
}

// mergeTestConnection returns a connection to a fake repository where the
// commit "merge" has the given parents and comparing them returns the pages
// of commits in compare.
func mergeTestConnection(t *testing.T, parents []string, total int, compare ...[]*github.RepositoryCommit) *GitHubConnection {
	t.Helper()

	commit := &github.Commit{SHA: github.Ptr("merge")}
	for _, p := range parents {
		commit.Parents = append(commit.Parents, &github.Commit{SHA: github.Ptr(p)})
	}

	compareHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := 1
		if p := r.URL.Query().Get("page"); p != "" {
			var err error
			page, err = strconv.Atoi(p)
			if err != nil {
				mock.WriteError(w, http.StatusBadRequest, "bad page")
				return
			}
		}
		if page < len(compare) {
			w.Header().Set("Link", fmt.Sprintf(`<https://api.github.com/compare?page=%d>; rel="next"`, page+1))
		}
		commits := []*github.RepositoryCommit{}
		if page <= len(compare) {
			commits = compare[page-1]
		}
		_, err := w.Write(mock.MustMarshal(&github.CommitsComparison{
			TotalCommits: github.Ptr(total),
			Commits:      commits,
		}))
		if err != nil {
			t.Errorf("writing response: %v", err)
		}
	})

	client, err := github.NewClient(github.WithHTTPClient(mock.NewMockedHTTPClient(
		mock.WithRequestMatch(mock.GetReposGitCommitsByOwnerByRepoByCommitSha, commit),
		mock.WithRequestMatchHandler(mock.GetReposCompareByOwnerByRepoByBasehead, compareHandler),
	)))
	require.NoError(t, err)

	ghc := NewGhConnectionWithClient("owner", "repo", "refs/heads/main", client)
	ghc.Options.AllowMergeCommits = true
	return ghc
}

// testCommits builds the commits of a compare response. Each commit gets the
// number of parents listed.
func testCommits(numParents ...int) []*github.RepositoryCommit {
	commits := make([]*github.RepositoryCommit, 0, len(numParents))
	for i, n := range numParents {
		c := &github.RepositoryCommit{SHA: github.Ptr(fmt.Sprintf("feature%d", i))}
		for j := range n {
			c.Parents = append(c.Parents, &github.Commit{SHA: github.Ptr(fmt.Sprintf("parent%d-%d", i, j))})
		}
		commits = append(commits, c)
	}
	return commits
}

func TestGetPriorCommit(t *testing.T) {
	t.Parallel()

	t.Run("single-parent", func(t *testing.T) {
		t.Parallel()
		ghc := mergeTestConnection(t, []string{"base"}, 0)
		prior, err := ghc.GetPriorCommit(t.Context(), "merge")
		require.NoError(t, err)
		require.Equal(t, "base", prior)
	})

	t.Run("no-parents", func(t *testing.T) {
		t.Parallel()
		ghc := mergeTestConnection(t, nil, 0)
		_, err := ghc.GetPriorCommit(t.Context(), "merge")
		require.Error(t, err)
	})

	t.Run("merge-of-linear-branch", func(t *testing.T) {
		t.Parallel()
		ghc := mergeTestConnection(t, []string{"base", "feature"}, 3, testCommits(1, 1, 1))
		prior, err := ghc.GetPriorCommit(t.Context(), "merge")
		require.NoError(t, err)
		require.Equal(t, "base", prior)
	})

	t.Run("merge-commits-disabled", func(t *testing.T) {
		t.Parallel()
		ghc := mergeTestConnection(t, []string{"base", "feature"}, 3, testCommits(1, 1, 1))
		ghc.Options.AllowMergeCommits = false
		_, err := ghc.GetPriorCommit(t.Context(), "merge")
		require.ErrorContains(t, err, "more than one parent")
	})

	t.Run("merge-inside-the-merged-branch", func(t *testing.T) {
		t.Parallel()
		ghc := mergeTestConnection(t, []string{"base", "feature"}, 3, testCommits(1, 2, 1))
		_, err := ghc.GetPriorCommit(t.Context(), "merge")
		require.ErrorContains(t, err, "not linear")
		require.ErrorContains(t, err, "feature1")
	})

	t.Run("merge-in-a-later-page", func(t *testing.T) {
		t.Parallel()
		ghc := mergeTestConnection(t, []string{"base", "feature"}, 4, testCommits(1, 1), testCommits(1, 2))
		_, err := ghc.GetPriorCommit(t.Context(), "merge")
		require.ErrorContains(t, err, "not linear")
	})

	t.Run("linear-over-several-pages", func(t *testing.T) {
		t.Parallel()
		ghc := mergeTestConnection(t, []string{"base", "feature"}, 4, testCommits(1, 1), testCommits(1, 1))
		_, err := ghc.GetPriorCommit(t.Context(), "merge")
		require.NoError(t, err)
	})

	t.Run("octopus-merge", func(t *testing.T) {
		t.Parallel()
		ghc := mergeTestConnection(t, []string{"base", "feature", "other"}, 2, testCommits(1, 1))
		_, err := ghc.GetPriorCommit(t.Context(), "merge")
		require.ErrorContains(t, err, "3 parents")
	})

	t.Run("merge-adds-no-commits", func(t *testing.T) {
		t.Parallel()
		ghc := mergeTestConnection(t, []string{"base", "feature"}, 0, testCommits())
		_, err := ghc.GetPriorCommit(t.Context(), "merge")
		require.ErrorContains(t, err, "adds no commits")
	})

	t.Run("incomplete-commit-list", func(t *testing.T) {
		t.Parallel()
		ghc := mergeTestConnection(t, []string{"base", "feature"}, 300, testCommits(1, 1))
		_, err := ghc.GetPriorCommit(t.Context(), "merge")
		require.ErrorContains(t, err, "2 of the 300")
	})
}
