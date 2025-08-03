// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slsa-framework/slsa-source-poc/pkg/provenance"
)

type (
	ControlName     string
	ControlState    string
	SlsaSourceLevel ControlName
)

func (c ControlName) String() string {
	return string(c)
}

const (
	SlsaSourceLevel1         SlsaSourceLevel = "SLSA_SOURCE_LEVEL_1"
	SlsaSourceLevel2         SlsaSourceLevel = "SLSA_SOURCE_LEVEL_2"
	SlsaSourceLevel3         SlsaSourceLevel = "SLSA_SOURCE_LEVEL_3"
	SlsaSourceLevel4         SlsaSourceLevel = "SLSA_SOURCE_LEVEL_4"
	ContinuityEnforced       ControlName     = "CONTINUITY_ENFORCED"
	ProvenanceAvailable      ControlName     = "PROVENANCE_AVAILABLE"
	ReviewEnforced           ControlName     = "REVIEW_ENFORCED"
	TagHygiene               ControlName     = "TAG_HYGIENE"
	PolicyAvailable          ControlName     = "POLICY_AVAILABLE"
	SourceBranchesAnnotation                 = "source_branches"
	SourceRefsAnnotation                     = "source_refs"
	AllowedOrgPropPrefix                     = "ORG_SOURCE_"

	// Control lifecycle states
	StateNotEnabled ControlState = "not_enabled"
	StateInProgress ControlState = "in_progress"
	StateActive     ControlState = "active"
)

// AllLevelControls lists all the SLSA controls managed by sourcetool
var AllLevelControls = []ControlName{
	ContinuityEnforced, ProvenanceAvailable, ReviewEnforced, TagHygiene,
}

func IsSlsaSourceLevel(control ControlName) bool {
	return slices.Contains(
		[]ControlName{
			ControlName(SlsaSourceLevel1),
			ControlName(SlsaSourceLevel2),
			ControlName(SlsaSourceLevel3),
			ControlName(SlsaSourceLevel4),
		},
		control)
}

func IsLevelHigherOrEqualTo(level1, level2 SlsaSourceLevel) bool {
	// There's probably some fancy stuff we can get in to, but...
	// it just so happens that these level strings should sort the way we want.
	return level1 >= level2
}

type Controls []*provenance.Control

// Adds the control to the list. Ignores nil controls.
// Does not check for duplicate controls.
func (controls *Controls) AddControl(newControls ...*provenance.Control) {
	if controls == nil {
		controls = &Controls{}
	}
	for _, c := range newControls {
		if c == nil {
			continue
		}
		*controls = append(*controls, c)
	}
}

// Gets the control with the corresponding name, returns nil if not found.
func (controls *Controls) GetControl(name ControlName) *provenance.Control {
	for _, control := range *controls {
		if control.GetName() == name.String() {
			return control
		}
	}
	return nil
}

func (controls *Controls) AreControlsAvailable(names []ControlName) bool {
	for _, name := range names {
		if controls.GetControl(name) == nil {
			return false
		}
	}
	return true
}

// Returns the names of the controls.
func (controls *Controls) Names() []ControlName {
	names := make([]ControlName, len(*controls))
	for i := range *controls {
		names[i] = ControlName((*controls)[i].GetName())
	}
	return names
}

// These can be any string, not just SlsaLevels
type SourceVerifiedLevels []ControlName

// Returns the list of control names that must be set for the given slsa level.
func GetRequiredControlsForLevel(level SlsaSourceLevel) []ControlName {
	switch level {
	case SlsaSourceLevel1:
		return []ControlName{}
	case SlsaSourceLevel2:
		return []ControlName{ContinuityEnforced, TagHygiene}
	case SlsaSourceLevel3:
		return []ControlName{ContinuityEnforced, TagHygiene, ProvenanceAvailable}
	case SlsaSourceLevel4:
		return []ControlName{ContinuityEnforced, TagHygiene, ProvenanceAvailable, ReviewEnforced}
	default:
		return []ControlName{}
	}
}

func EarlierTime(time1, time2 time.Time) time.Time {
	if time1.Before(time2) {
		return time1
	}
	return time2
}

func ControlNamesToStrings(controlNames []ControlName) []string {
	strs := make([]string, len(controlNames))
	for i := range controlNames {
		strs[i] = string(controlNames[i])
	}
	return strs
}

// NewControlStatus returns a new control status object initialized with
// all existing controls in not_enabled state.
func NewControlSetStatus() *ControlSetStatus {
	status := &ControlSetStatus{
		Time:     time.Now(),
		Controls: []ControlStatus{},
	}

	for _, c := range AllLevelControls {
		status.Controls = append(status.Controls, ControlStatus{
			Name:  c,
			State: StateNotEnabled,
		})
	}

	return status
}

// ControlSetStatus is a snapshot of the status of SLSA controls in a branch at
// a point in time.
type ControlSetStatus struct {
	RepoUri  string
	Branch   string
	Time     time.Time
	Controls []ControlStatus
}

// ControlStatus captures the status of a control as seen from a VCS system
type ControlStatus struct {
	Name              ControlName
	State             ControlState `json:"control_state"`
	Since             *time.Time   `json:"since,omitempty"`
	Message           string
	RecommendedAction *ControlRecommendedAction
}

// ControlRecommendedAction captures the recommended action to complete
// a control's implementation.
type ControlRecommendedAction struct {
	Message string
	Command string
}

// GetActiveControls returns a Controls collection with all the controls
// which are active in the set.
func (cs *ControlSetStatus) GetActiveControls() *Controls {
	ret := Controls{}
	if cs == nil {
		return &ret
	}
	for _, c := range cs.Controls {
		if c.State == StateActive {
			ret.AddControl(&provenance.Control{
				Name: c.Name.String(), Since: timestamppb.New(*c.Since),
			})
		}
	}
	return &ret
}

// SetControlState sets the state of a control in the set by name.
func (cs *ControlSetStatus) SetControlState(ctrlName ControlName, state ControlState) {
	for i := range cs.Controls {
		if cs.Controls[i].Name == ctrlName {
			cs.Controls[i].State = state
			return
		}
	}
}
