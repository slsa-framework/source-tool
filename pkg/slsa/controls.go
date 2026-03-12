// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package slsa

import "slices"

type (
	ControlName  string
	ControlState string

	// ControlNameSet is a list of control names
	ControlNameSet []ControlName
)

func (c ControlName) String() string {
	return string(c)
}

const (
	// Control constants
	DEPRECATED_ContinuityEnforced  ControlName = "CONTINUITY_ENFORCED"
	DEPRECATED_ProvenanceAvailable ControlName = "PROVENANCE_AVAILABLE"
	DEPRECATED_ReviewEnforced      ControlName = "REVIEW_ENFORCED"
	DEPRECATED_TagHygiene          ControlName = "TAG_HYGIENE"

	// Virtual control to manage policy lifcycle
	PolicyAvailable ControlName = "POLICY_AVAILABLE"

	SLSA_SOURCE_ORG_SCS              ControlName = "SLSA_SOURCE_ORG_SCS"
	SLSA_SOURCE_ORG_ACCESS_CONTROL   ControlName = "SLSA_SOURCE_ORG_ACCESS_CONTROL"
	SLSA_SOURCE_ORG_SAFE_EXPUNGE     ControlName = "SLSA_SOURCE_ORG_SAFE_EXPUNGE"
	SLSA_SOURCE_ORG_CONTINUITY       ControlName = "SLSA_SOURCE_ORG_CONTINUITY"
	SLSA_SOURCE_SCS_REPO_ID          ControlName = "SLSA_SOURCE_SCS_REPO_ID"
	SLSA_SOURCE_SCS_REVISION_ID      ControlName = "SLSA_SOURCE_SCS_REVISION_ID"
	SLSA_SOURCE_SCS_DIFF_DISPLAY     ControlName = "SLSA_SOURCE_SCS_DIFF_DISPLAY"
	SLSA_SOURCE_SCS_VSA              ControlName = "SLSA_SOURCE_SCS_VSA"
	SLSA_SOURCE_SCS_HISTORY          ControlName = "SLSA_SOURCE_SCS_HISTORY"
	SLSA_SOURCE_SCS_CONTINUITY       ControlName = "SLSA_SOURCE_SCS_CONTINUITY"
	SLSA_SOURCE_SCS_IDENTITY         ControlName = "SLSA_SOURCE_SCS_IDENTITY"
	SLSA_SOURCE_SCS_PROVENANCE       ControlName = "SLSA_SOURCE_SCS_PROVENANCE"
	SLSA_SOURCE_SCS_PROTECTED_REFS   ControlName = "SLSA_SOURCE_SCS_PROTECTED_REFS"
	SLSA_SOURCE_SCS_TWO_PARTY_REVIEW ControlName = "SLSA_SOURCE_SCS_TWO_PARTY_REVIEW"

	// Control lifecycle states
	StateNotEnabled ControlState = "not_enabled"
	StateInProgress ControlState = "in_progress"
	StateActive     ControlState = "active"
)

// AllLevelControls is a set holding all controls of the SLSA Source spec
var AllLevelControls = ControlNameSet{
	SLSA_SOURCE_ORG_SCS,
	SLSA_SOURCE_ORG_ACCESS_CONTROL,
	SLSA_SOURCE_ORG_SAFE_EXPUNGE,
	SLSA_SOURCE_ORG_CONTINUITY,
	SLSA_SOURCE_SCS_REPO_ID,
	SLSA_SOURCE_SCS_REVISION_ID,
	SLSA_SOURCE_SCS_DIFF_DISPLAY,
	SLSA_SOURCE_SCS_VSA,
	SLSA_SOURCE_SCS_HISTORY,
	SLSA_SOURCE_SCS_CONTINUITY,
	SLSA_SOURCE_SCS_IDENTITY,
	SLSA_SOURCE_SCS_PROVENANCE,
	SLSA_SOURCE_SCS_PROTECTED_REFS,
	SLSA_SOURCE_SCS_TWO_PARTY_REVIEW,
}

func (cs ControlNameSet) GetControl(ctrl ControlName) ControlName {
	if slices.Contains(cs, ctrl) {
		return ctrl
	}
	return ""
}
