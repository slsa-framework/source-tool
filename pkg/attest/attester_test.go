// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/slsa-framework/source-tool/pkg/slsa"
)

// A commit has no attestations the first time it is attested, so the backend
// never reports the provenance and VSA controls. They have to be added when the
// attestations are about to be issued or the revision is stuck at level 1.
func TestAddAttestationControls(t *testing.T) {
	t.Parallel()

	// All the level 3 controls a backend can report on a fresh commit.
	backendControls := func() *provenance.SourceProvenancePred {
		pred := &provenance.SourceProvenancePred{}
		for _, name := range slsa.Level3 {
			if name == slsa.SLSA_SOURCE_SCS_PROVENANCE || name == slsa.SLSA_SOURCE_SCS_VSA {
				continue
			}
			provenance.AddControl(pred, &provenance.Control{Name: name.String()})
		}
		return pred
	}

	for _, tc := range []struct {
		name      string
		opts      *provenanceOptions
		expectVSA bool
	}{
		{name: "vsa-issued", opts: &provenanceOptions{vsaIssued: true}, expectVSA: true},
		{name: "vsa-not-issued", opts: &provenanceOptions{}, expectVSA: false},
		{name: "nil-options", opts: nil, expectVSA: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pred := backendControls()
			addAttestationControls(pred, tc.opts)

			require.NotNil(t, provenance.GetControl(pred, slsa.SLSA_SOURCE_SCS_PROVENANCE.String()))
			require.Equal(t, tc.expectVSA, provenance.GetControl(pred, slsa.SLSA_SOURCE_SCS_VSA.String()) != nil)

			controls := slsa.NewControlSetFromProvanenaceControls(pred.GetControls())
			require.Equal(t, tc.expectVSA, controls.AreControlsAvailable(slsa.Level3))
		})
	}

	t.Run("no-duplicates", func(t *testing.T) {
		t.Parallel()
		pred := backendControls()
		addAttestationControls(pred, &provenanceOptions{vsaIssued: true})
		count := len(pred.GetControls())
		addAttestationControls(pred, &provenanceOptions{vsaIssued: true})
		require.Len(t, pred.GetControls(), count)
	})
}
