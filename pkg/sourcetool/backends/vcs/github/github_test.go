// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/ghcontrol"
	"github.com/slsa-framework/source-tool/pkg/slsa"
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

func TestCarryOverDynamicControls(t *testing.T) {
	t.Parallel()
	since := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	checkName := ghcontrol.CheckNameToControlName("ci / ci")

	activeControls := &slsa.ControlSet{}
	activeControls.AddControl(
		// A framework control, it already has an entry in the status
		&slsa.Control{Name: slsa.SLSA_SOURCE_SCS_CONTINUITY, Since: &since},
		// A required check, not part of the framework controls
		&slsa.Control{Name: checkName, Since: &since},
		nil,
	)

	status := slsa.NewControlSet()
	frameworkControls := len(status.Controls)
	require.Nil(t, status.GetControl(checkName))

	carryOverDynamicControls(status, activeControls)

	// Only the required check is added and it is added as active
	require.Len(t, status.Controls, frameworkControls+1)
	check := status.GetControl(checkName)
	require.NotNil(t, check)
	require.Equal(t, slsa.StateActive, check.State)
	require.Equal(t, &since, check.GetSince())
	require.NotNil(t, status.GetActiveControls().GetControl(checkName))

	// The framework control is left for the caller to enable
	require.Equal(t, slsa.StateNotEnabled, status.GetControl(slsa.SLSA_SOURCE_SCS_CONTINUITY).State)

	// The control in the status is a copy
	require.NotSame(t, activeControls.GetControl(checkName), check)

	// Carrying the controls over again does not duplicate them
	carryOverDynamicControls(status, activeControls)
	require.Len(t, status.Controls, frameworkControls+1)
}
