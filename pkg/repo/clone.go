// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	billy "github.com/go-git/go-billy/v6"
	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/google/uuid"
	"sigs.k8s.io/release-utils/command"

	"github.com/slsa-framework/source-tool/pkg/repo/options"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

// Clone is a local clone of a repository
type Clone struct {
	models.Repository
	TmpDir        string
	repo          *git.Repository
	fs            billy.Filesystem
	FeatureBranch string
	DefaultBranch string
}

// CleanUp is intended to remove any temporary files lying around
func (c *Clone) Cleanup() {
	if c.TmpDir != "" {
		if err := os.RemoveAll(c.TmpDir); err != nil {
			log.Printf("error deleting temp dir %q: %v", c.TmpDir, err)
		}
	}
}

// CreateFeatureBranch creates a branch in the local clone and switches to it.
func (c *Clone) CreateFeatureBranch() error {
	// If the branch is already created, noop
	if c.FeatureBranch != "" {
		return nil
	}

	c.FeatureBranch = "pullreq-branch-" + uuid.NewString()

	// Get the current HEAD reference
	head, err := c.repo.Head()
	if err != nil {
		log.Fatalf("Failed to get HEAD reference: %v", err)
	}

	branchRef := plumbing.NewBranchReferenceName(c.FeatureBranch)

	// Check if branch already exists
	_, err = c.repo.Reference(branchRef, true)
	if err == nil {
		return fmt.Errorf("branch %q already exists", c.FeatureBranch)
	}

	newRef := plumbing.NewHashReference(branchRef, head.Hash())
	err = c.repo.Storer.SetReference(newRef)
	if err != nil {
		return fmt.Errorf("failed to create branch reference: %w", err)
	}

	// Get the worktree to checkout the new branch
	worktree, err := c.repo.Worktree()
	if err != nil {
		return fmt.Errorf("getting clone worktree: %w", err)
	}

	// Switch to the new branch
	err = worktree.Checkout(&git.CheckoutOptions{
		Branch: branchRef,
	})
	if err != nil {
		return fmt.Errorf("failed to checkout new branch: %w", err)
	}

	return nil
}

// AddRemote adds a remote to the clone
func (c *Clone) AddRemote(name, url string) error {
	_, err := c.repo.CreateRemote(&config.RemoteConfig{
		Name: name,
		URLs: []string{url},
	})
	if err != nil {
		return fmt.Errorf("creating remote: %w", err)
	}
	return nil
}

// PushToRemote pushes the active branch to the specified remote
func (c *Clone) PushRemote(remoteName string) error {
	refSpecs := []config.RefSpec{
		config.RefSpec(fmt.Sprintf(
			"+refs/heads/%s:refs/heads/%s", c.FeatureBranch, c.FeatureBranch,
		)),
	}
	err := c.repo.Push(&git.PushOptions{
		RemoteName: remoteName,
		RefSpecs:   refSpecs,
	})
	if err != nil {
		return fmt.Errorf("pushing to remote: %w", err)
	}
	return nil
}

// Add adds a modified file to the staging area
func (c *Clone) Add(path string) error {
	wtree, err := c.repo.Worktree()
	if err != nil {
		return fmt.Errorf("getting clone worktree: %w", err)
	}

	if _, err := wtree.Add(path); err != nil {
		return fmt.Errorf("adding file: %w", err)
	}
	return nil
}

// Add adds all modified files to the staging area
func (c *Clone) AddAll() error {
	wtree, err := c.repo.Worktree()
	if err != nil {
		return fmt.Errorf("getting clone worktree: %w", err)
	}

	if err := wtree.AddGlob("*"); err != nil {
		return fmt.Errorf("adding all modified files: %w", err)
	}
	return nil
}

// Commit creates a commit in the cloned repository. It expects files
// to be ready in the staging area.
func (c *Clone) Commit(opts *options.CommitOptions) error {
	var usegit bool
	if opts.UseGit == nil {
		// Check if the git binary can be invoked
		path, err := exec.LookPath("git")
		if path == "" || err != nil {
			usegit = false
		} else {
			usegit = true
		}
	} else {
		usegit = *opts.UseGit
	}
	if usegit {
		if err := c.gitCliCommit(opts); err != nil {
			// If signing is not defined and the commit failed
			// signing, try again with the pure go signature.
			if opts.Sign == nil && opts.UseGit == nil && strings.Contains(err.Error(), "gpg failed") {
				return c.puregoCommit(opts)
			}
			return err
		}
		return nil
	}
	return c.puregoCommit(opts)
}

func (c *Clone) gitCliCommit(opts *options.CommitOptions) error {
	if c.TmpDir == "" {
		return errors.New("committing using the git cli is only supported when cloning to disk")
	}

	// Pass the sign flag...
	signFlag := "-S"

	// .. unless specifically defined not to
	if opts.Sign != nil && !*opts.Sign {
		signFlag = "--no-gpg-sign"
	}

	// Run the git binary to commit as the user would do.
	cmd := command.NewWithWorkDir(c.TmpDir, "git", "commit", signFlag, "-sm", opts.Message)
	if err := cmd.RunSilentSuccess(); err != nil {
		return fmt.Errorf("git exec: %w", err)
	}
	return nil
}

// puregoCommit creates the commit in the repo using only go code. This method
// does not support
func (c *Clone) puregoCommit(opts *options.CommitOptions) error {
	if opts.Sign != nil && *opts.Sign {
		return fmt.Errorf("signing commits is not possible on memory clones")
	}

	wtree, err := c.repo.Worktree()
	if err != nil {
		return fmt.Errorf("getting clone worktree: %w", err)
	}

	copts := &git.CommitOptions{}
	if opts.Email != "" {
		copts.Author = &object.Signature{
			Name:  opts.Name,
			Email: opts.Email,
		}
	}
	_ = copts.Validate(c.repo) //nolint:errcheck // This just loads the user details

	// If the user details were successfully loaded add the signoff
	msg := opts.Message
	if copts.Author != nil && copts.Author.Email != "" {
		msg += fmt.Sprintf("\n\nSigned-off-by: %s <%s>\n", copts.Author.Name, copts.Author.Email)
	}

	if _, err = wtree.Commit(msg, copts); err != nil {
		return fmt.Errorf("committing changes: %w", err)
	}
	return nil
}

// AddFiles copies a list of files into the clone filesystem. All
func (c *Clone) AddFiles(clone *Clone, files []*PullRequestFileEntry) error {
	if clone.fs == nil {
		return fmt.Errorf("clone has no filesystem defined")
	}
	for i, fentry := range files {
		if fentry.Path == "" {
			return fmt.Errorf("file entry #%d has no path set", i)
		}
		file, err := clone.fs.Create(fentry.Path)
		if err != nil {
			return fmt.Errorf("creating file in cloned repo: %w", err)
		}

		if _, err := io.Copy(file, fentry.Reader); err != nil {
			return fmt.Errorf("copying data to %q in the cloned repo: %w", fentry.Path, err)
		}

		if err := clone.Add(fentry.Path); err != nil {
			return fmt.Errorf("adding %q to staging area: %w", fentry.Path, err)
		}
	}
	return nil
}
