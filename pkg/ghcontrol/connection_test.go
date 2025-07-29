// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package ghcontrol

import (
	"testing"

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
