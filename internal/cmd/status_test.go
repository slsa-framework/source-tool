// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/slsa-framework/source-tool/pkg/slsa"
)

// level3Controls returns the level 3 controls as a backend reports them for
// a commit, with the attestation controls in the given state.
func level3Controls(attestations slsa.ControlState) *slsa.ControlSet {
	cs := &slsa.ControlSet{}
	for _, name := range slsa.Level3 {
		state := slsa.StateActive
		if name == slsa.SLSA_SOURCE_SCS_PROVENANCE || name == slsa.SLSA_SOURCE_SCS_VSA {
			state = attestations
		}
		cs.AddControl(&slsa.Control{Name: name, State: state})
	}
	return cs
}

func TestVerifiedSourceLevel(t *testing.T) {
	t.Parallel()
	levels := slsa.SourceVerifiedLevels{
		slsa.ControlName(slsa.SlsaSourceLevel3), slsa.SLSA_SOURCE_SCS_PROTECTED_REFS,
	}
	for _, tt := range []struct {
		name      string
		levels    slsa.SourceVerifiedLevels
		tipHasVSA bool
		want      slsa.SlsaSourceLevel
	}{
		{name: "attested commit", levels: levels, tipHasVSA: true, want: slsa.SlsaSourceLevel3},
		{name: "no vsa means level 0", levels: levels, tipHasVSA: false, want: slsa.SlsaSourceLevel0},
		{name: "no levels", levels: nil, tipHasVSA: true, want: slsa.SlsaSourceLevel0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := verifiedSourceLevel(tt.levels, tt.tipHasVSA); got != string(tt.want) {
				t.Errorf("verifiedSourceLevel() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestEligibleLevel(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name       string
		controls   *slsa.ControlSet
		attestable bool
		want       slsa.SlsaSourceLevel
	}{
		{
			name:     "attested commit",
			controls: level3Controls(slsa.StateActive), attestable: true,
			want: slsa.SlsaSourceLevel3,
		},
		{
			name:     "commit waiting for its attestations",
			controls: level3Controls(slsa.StateNotEnabled), attestable: true,
			want: slsa.SlsaSourceLevel3,
		},
		{
			name:     "no provenance workflow",
			controls: level3Controls(slsa.StateNotEnabled), attestable: false,
			want: slsa.SlsaSourceLevel1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := eligibleLevel(tt.controls, tt.attestable); got != tt.want {
				t.Errorf("eligibleLevel() = %s, want %s", got, tt.want)
			}
			// The controls passed in are not modified
			if tt.controls.GetControl(slsa.SLSA_SOURCE_SCS_VSA).State == slsa.StateActive &&
				tt.name != "attested commit" {
				t.Errorf("eligibleLevel() activated the VSA control of its input")
			}
		})
	}
}
