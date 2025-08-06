// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package ghcontrol

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetNotesForCommit(t *testing.T) {
	t.Parallel()
	if tk := os.Getenv(tokenEnvVar); tk == "" {
		t.Log("Skipping API test as no token is set")
		t.Skip()
	}

	for _, tc := range []struct {
		name        string
		owner       string
		repo        string
		commit      string
		mustBeEmpty bool
		mustErr     bool
	}{
		{name: "success", owner: "slsa-framework", repo: "source-tool", commit: "e573149ab3e574abc2e5a151a04acfaf2a59b453", mustBeEmpty: false, mustErr: false},
		{name: "invalida-commit", owner: "kjsdhi373iuh", repo: "lksjdhfk3773", commit: "invalid", mustBeEmpty: true, mustErr: true},
		{name: "non-existent", owner: "kjsdhi373iuh", repo: "lksjdhfk3773", commit: "de9395302d14b24c0a42685cf27315d93c88ff79", mustBeEmpty: true, mustErr: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ghc := NewGhConnection(tc.owner, tc.repo, "main")
			notes, err := ghc.GetNotesForCommit(t.Context(), tc.commit)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err, tc.commit)
			if tc.mustBeEmpty {
				require.Empty(t, notes, "Commit: %s", tc.commit)
			} else {
				require.NotEmpty(t, notes, "Commit: %s", tc.commit)
			}
		})
	}
}
