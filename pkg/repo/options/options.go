// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package options

import "errors"

// PullRequestManagerOptions captures the pr manager options
type PullRequestManagerOptions struct {
	// UseGit controls if commits are done using the git binary. If false,
	// commits are done using a pure Go implementation. This methodd, however,
	// does not support signing. To sign commits, set this to true, and
	// commits will be done using `git commit -Ssm "Message"`, using the
	// local configuration.
	//
	// If the pointer is nil, the clone will look for the git binary and use
	// it if found or revert to pure go if not found.
	//
	// Note that the git binary can only be used when the repo is cloned to
	// disk and will error if attempting to commit a memory clone.
	UseGitToCommit *bool

	// Perform all ops on the repo clone in memory
	CloneToMemory bool

	// UseFork will force the pr manager to user a fork in the user's org
	UseFork bool

	// ForkName is an optional name to use when looking for the repo fork
	ForkName string

	// RemoteName is the name of the git remote that will be configured in
	// the repository clones
	RemoteName string
}

// Validate checks the consistency of the pr manager options
func (prmo *PullRequestManagerOptions) Validate() error {
	errs := []error{}
	if prmo.UseGitToCommit != nil && *prmo.UseGitToCommit && prmo.CloneToMemory {
		errs = append(errs, errors.New("the git cli can only be used when cloning to disk"))
	}
	return errors.Join(errs...)
}

// PullRequestOptions control how the manager opens a pull request on GitHub
type PullRequestOptions struct {
	Title string
	Body  string
	Head  string
	Base  string // main
}

// PullRequestFileList
type PullRequestFileListOptions struct {
	Title         string
	Body          string
	BaseBranch    string
	CommitOptions CommitOptions
}

type CommitOptions struct {
	Name    string
	Email   string
	Message string
	UseGit  *bool
	Sign    *bool
}

// Validate checks the consistency of the commit options
func (co *CommitOptions) Validate() error {
	errs := []error{}
	if co.Sign != nil && co.UseGit != nil && *co.Sign && !*co.UseGit {
		errs = append(errs, errors.New("signing commits is only possible when using the git binary"))
	}
	return errors.Join(errs...)
}
