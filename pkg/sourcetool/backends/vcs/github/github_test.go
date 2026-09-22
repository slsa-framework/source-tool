// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

func TestNewUsesDefaultVerifier(t *testing.T) {
	t.Parallel()

	backend := New(&models.BackendOptions{})
	verifier, ok := backend.verifier.(*attest.BndVerifier)

	require.True(t, ok)
	require.Equal(t, attest.DefaultVerifierOptions, verifier.Options)
}

func TestNewUsesConfiguredVerifier(t *testing.T) {
	t.Parallel()

	verifier := attest.NewBndVerifier(attest.VerificationOptions{
		ExpectedIssuer: "https://token.actions.githubusercontent.com",
		ExpectedSan:    "https://github.com/acme/project/.github/workflows/provenance.yml@refs/heads/main",
	})

	backend := New(&models.BackendOptions{}, WithVerifier(verifier))

	require.Same(t, verifier, backend.verifier)
}

func TestWithVerifierIgnoresNil(t *testing.T) {
	t.Parallel()

	backend := New(&models.BackendOptions{}, WithVerifier(nil))

	require.NotNil(t, backend.verifier)
}
