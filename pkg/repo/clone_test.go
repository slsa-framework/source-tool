// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"strings"
	"testing"
	"time"

	memfs "github.com/go-git/go-billy/v6/memfs"
	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/storage/memory"

	"github.com/slsa-framework/source-tool/pkg/repo/options"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

// TestCloneAddFiles_CreatesValidCommit is an integration test that verifies
// the entire workflow of adding files and committing works correctly with timestamps.
func TestCloneAddFiles_CreatesValidCommit(t *testing.T) {
	// Create an in-memory repository
	storer := memory.NewStorage()
	fs := memfs.New()

	repo, err := git.Init(storer, git.WithWorkTree(fs))
	if err != nil {
		t.Fatalf("Failed to initialize test repository: %v", err)
	}

	clone := &Clone{
		Repository: models.Repository{
			Hostname: "github.com",
			Path:     "test/repo",
		},
		repo: repo,
		fs:   fs,
	}

	// Add files using the AddFiles method
	files := []*PullRequestFileEntry{
		{
			Path:   "workflow.yaml",
			Reader: strings.NewReader("name: Test Workflow\non: push\n"),
		},
	}

	err = clone.AddFiles(clone, files)
	if err != nil {
		t.Fatalf("AddFiles failed: %v", err)
	}

	// Create a commit
	useGit := false
	commitOpts := &options.CommitOptions{
		Name:    "Workflow Bot",
		Email:   "bot@example.com",
		Message: "Add SLSA Source Provenance Workflow",
		UseGit:  &useGit,
	}

	beforeCommit := time.Now()
	err = clone.Commit(commitOpts)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
	afterCommit := time.Now()

	// Verify the commit
	ref, err := repo.Head()
	if err != nil {
		t.Fatalf("Failed to get HEAD reference: %v", err)
	}

	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		t.Fatalf("Failed to get commit object: %v", err)
	}

	// Check the commit is not from epoch
	epochTime := time.Unix(0, 0)
	year1970 := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

	if commit.Author.When.Year() == 1970 {
		t.Errorf("Commit has 1970 timestamp: %v (this is the bug we're fixing)", commit.Author.When)
	}

	if commit.Author.When.Equal(epochTime) || commit.Author.When.Equal(year1970) {
		t.Errorf("Commit timestamp is epoch (Jan 1, 1970): %v", commit.Author.When)
	}

	// Verify timestamp is current
	if commit.Author.When.Before(beforeCommit.Add(-1*time.Minute)) ||
		commit.Author.When.After(afterCommit.Add(1*time.Minute)) {
		t.Errorf("Commit timestamp %v is not close to current time [%v, %v]",
			commit.Author.When, beforeCommit, afterCommit)
	}

	// Verify the file was added
	tree, err := commit.Tree()
	if err != nil {
		t.Fatalf("Failed to get commit tree: %v", err)
	}

	_, err = tree.File("workflow.yaml")
	if err != nil {
		t.Errorf("workflow.yaml not found in commit tree: %v", err)
	}
}
