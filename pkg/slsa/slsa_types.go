// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"slices"
	"time"

	"github.com/slsa-framework/source-tool/pkg/provenance"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	SourceBranchesAnnotation = "source_branches"
	SourceRefsAnnotation     = "source_refs"
	AllowedOrgPropPrefix     = "ORG_SOURCE_"
)

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

// These can be any string, not just SlsaLevels
type SourceVerifiedLevels []ControlName

// Returns the list of control names that must be set for the given slsa level.
func GetRequiredControlsForLevel(level SlsaSourceLevel) ControlNameSet {
	switch level {
	case SlsaSourceLevel1:
		return Level1
	case SlsaSourceLevel2:
		return Level2
	case SlsaSourceLevel3:
		return Level3
	case SlsaSourceLevel4:
		return Level4
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

func NewControlSetFromProvanenaceControls(provControls []*provenance.Control) *ControlSet {
	set := &ControlSet{
		Controls: []*Control{},
	}

	for _, ctl := range provControls {
		t := ctl.Since.AsTime()
		set.Controls = append(set.Controls, &Control{
			Name:  ControlName(ctl.Name),
			State: StateActive,
			Since: &t,
		})
	}
	return set
}

// NewControlStatus returns a new control status object initialized with
// all existing controls in not_enabled state.
func NewControlSet() *ControlSet {
	status := &ControlSet{
		Time:     time.Now(),
		Controls: []*Control{},
	}

	for _, c := range AllLevelControls {
		status.Controls = append(status.Controls, &Control{
			Name:  c,
			State: StateNotEnabled,
		})
	}

	return status
}

// ControlSet is a snapshot of the status of SLSA controls in a branch at
// a point in time.
type ControlSet struct {
	RepoUri  string
	Branch   string
	Time     time.Time
	Controls []*Control
}

// Control captures the status of a control as seen from a VCS system
type Control struct {
	Name              ControlName
	State             ControlState `json:"control_state"`
	Since             *time.Time   `json:"since,omitempty"`
	Message           string
	RecommendedAction *ControlRecommendedAction
}

func (cs *Control) GetName() ControlName {
	return cs.Name
}

func (cs *Control) GetSince() *time.Time {
	return cs.Since
}

// ControlRecommendedAction captures the recommended action to complete
// a control's implementation.
type ControlRecommendedAction struct {
	Message string
	Command string
}

// GetActiveControls returns a Controls collection with all the controls
// which are active in the set.
func (cs *ControlSet) GetActiveControls() *ControlSet {
	ret := ControlSet{}
	if cs == nil {
		return &ret
	}
	for _, c := range cs.Controls {
		if c.State == StateActive {
			ret.AddControl(c)
		}
	}
	return &ret
}

// SetControlState sets the state of a control in the set by name.
func (cs *ControlSet) SetControlState(ctrlName ControlName, state ControlState) {
	for i := range cs.Controls {
		if cs.Controls[i].Name == ctrlName {
			cs.Controls[i].State = state
			return
		}
	}
}

// Adds the control to the list. Ignores nil controls.
// Does not check for duplicate controls.
func (cs *ControlSet) AddControl(newControls ...*Control) {
	if cs == nil {
		cs = &ControlSet{}
	}
	for _, c := range newControls {
		if c == nil {
			continue
		}
		cs.Controls = append(cs.Controls, c)
	}
}

// Gets the control with the corresponding name, returns nil if not found.
func (cs *ControlSet) GetControl(name ControlName) *Control {
	for _, control := range cs.Controls {
		if control.GetName() == name {
			return control
		}
	}
	return nil
}

// This checks if the controls are present in the array. But As we merged the
// controls array with the struct we also check if they are all active
func (cs *ControlSet) AreControlsAvailable(names []ControlName) bool {
	for _, name := range names {
		ctl := cs.GetControl(name)
		if ctl == nil || ctl.State != StateActive {
			return false
		}
	}
	return true
}

// Returns the names of the controls.
func (cs *ControlSet) Names() []ControlName {
	names := make([]ControlName, len(cs.Controls))
	for i := range cs.Controls {
		names[i] = cs.Controls[i].GetName()
	}
	return names
}

func (cs *ControlSet) ToProvenanceControls() []*provenance.Control {
	var ret = []*provenance.Control{}
	for _, ctl := range cs.Controls {
		if ctl.State != StateActive {
			continue
		}
		c := &provenance.Control{
			Name:  ctl.Name.String(),
			Since: timestamppb.New(*ctl.Since),
		}
		ret = append(ret, c)
	}
	return ret
}
