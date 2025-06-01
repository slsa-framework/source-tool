package slsa_types

import "time"

type ControlName string
type SlsaSourceLevel ControlName

const (
	SlsaSourceLevel1         SlsaSourceLevel = "SLSA_SOURCE_LEVEL_1"
	SlsaSourceLevel2         SlsaSourceLevel = "SLSA_SOURCE_LEVEL_2"
	SlsaSourceLevel3         SlsaSourceLevel = "SLSA_SOURCE_LEVEL_3"
	SlsaSourceLevel4         SlsaSourceLevel = "SLSA_SOURCE_LEVEL_4"
	ContinuityEnforced       ControlName     = "CONTINUITY_ENFORCED"
	ProvenanceAvailable      ControlName     = "PROVENANCE_AVAILABLE"
	ReviewEnforced           ControlName     = "REVIEW_ENFORCED"
	TagHygiene               ControlName     = "TAG_HYGIENE"
	SourceBranchesAnnotation                 = "source_branches"
	SourceRefsAnnotation                     = "source_refs"
	AllowedOrgPropPrefix                     = "ORG_SOURCE_"
)

func IsLevelHigherOrEqualTo(level1, level2 SlsaSourceLevel) bool {
	// There's probably some fancy stuff we can get in to, but...
	// it just so happens that these level strings should sort the way we want.
	return level1 >= level2
}

type Control struct {
	// The name of the control
	Name ControlName `json:"name"`
	// The time from which this control has been continuously enforced/observed.
	Since time.Time `json:"since"`
}

type Controls []Control

// Adds the control to the list. Ignores nil controls.
// Does not check for duplicate controls.
func (controls *Controls) AddControl(newControls ...*Control) {
	for _, c := range newControls {
		if c == nil {
			continue
		}
		*controls = append(*controls, *c)
	}
}

// Gets the control with the corresponding name, returns nil if not found.
func (controls Controls) GetControl(name ControlName) *Control {
	for _, control := range controls {
		if control.Name == name {
			return &control
		}
	}
	return nil
}

// These can be any string, not just SlsaLevels
type SourceVerifiedLevels []ControlName

func EarlierTime(time1, time2 time.Time) time.Time {
	if time1.Before(time2) {
		return time1
	}
	return time2
}

func LaterTime(time1, time2 time.Time) time.Time {
	if time1.After(time2) {
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

func StringsToControlNames(strs []string) []ControlName {
	controlNames := make([]ControlName, len(strs))
	for i := range strs {
		controlNames[i] = ControlName(strs[i])
	}
	return controlNames
}
