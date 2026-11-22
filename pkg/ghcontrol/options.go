// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package ghcontrol

var defaultOptions = Options{
	AllowMergeCommits: true,
	ApiRetries:        3,
}

type Options struct {
	// AllowMergeCommits causes the GitHub connector to reject merge
	// commits when set to false. When true, merge commits still have to
	// pass CheckMergeCommit.
	AllowMergeCommits bool

	// accessToken is the token we will use to connect to the GitHub API
	accessToken string

	// ApiRetries controls the number of time we retry calls to the GitHub API
	ApiRetries uint8
}
