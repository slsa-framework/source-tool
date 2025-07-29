// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPullRequestManagerOptionsValidate(t *testing.T) {
	t.Parallel()
	bTrue := true
	bFalse := false
	for _, tt := range []struct {
		name    string
		mustErr bool
		opts    *PullRequestManagerOptions
	}{
		{"git-and-mem", true, &PullRequestManagerOptions{
			UseGitToCommit: &bTrue,
			CloneToMemory:  true,
		}},
		{"nogit-and-mem", false, &PullRequestManagerOptions{
			UseGitToCommit: &bFalse,
			CloneToMemory:  true,
		}},
		{"nilgit-and-mem", false, &PullRequestManagerOptions{
			UseGitToCommit: nil,
			CloneToMemory:  true,
		}},
		{"nilgit-and-nomem", false, &PullRequestManagerOptions{
			UseGitToCommit: nil,
			CloneToMemory:  false,
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.opts.Validate()
			if tt.mustErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCommitOptionsValidate(t *testing.T) {
	t.Parallel()
	bTrue := true
	bFalse := false
	for _, tt := range []struct {
		name    string
		mustErr bool
		opts    *CommitOptions
	}{
		{"gittrue-signfalse", false, &CommitOptions{
			UseGit: &bTrue,
			Sign:   &bFalse,
		}},
		{"gittrue-signtrue", false, &CommitOptions{
			UseGit: &bTrue,
			Sign:   &bTrue,
		}},
		{"gitfalse-signtrue", true, &CommitOptions{
			UseGit: &bFalse,
			Sign:   &bTrue,
		}},
		{"gitfalse-signfalse", false, &CommitOptions{
			UseGit: &bFalse,
			Sign:   &bFalse,
		}},
		{"gitnil-signnil", false, &CommitOptions{
			UseGit: nil,
			Sign:   nil,
		}},
		{"gitnil-signtrue", false, &CommitOptions{
			UseGit: nil,
			Sign:   &bTrue,
		}},
		{"gitnil-signfalse", false, &CommitOptions{
			UseGit: nil,
			Sign:   &bFalse,
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// if co.Sign != nil && co.UseGit != nil && *co.Sign && !*co.UseGit {
			err := tt.opts.Validate()
			if tt.mustErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
