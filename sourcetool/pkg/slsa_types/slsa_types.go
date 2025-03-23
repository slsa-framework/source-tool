package slsa_types

import "time"

type SlsaSourceLevel string

const (
	SlsaSourceLevel1        SlsaSourceLevel = "SLSA_SOURCE_LEVEL_1"
	SlsaSourceLevel2        SlsaSourceLevel = "SLSA_SOURCE_LEVEL_2"
	SlsaSourceLevel3        SlsaSourceLevel = "SLSA_SOURCE_LEVEL_3"
	ContinuityEnforced                      = "CONTINUITY_ENFORCED"
	ProvenanceAvailable                     = "PROVENANCE_AVAILABLE"
	ReviewEnforced                          = "REVIEW_ENFORCED"
	TagImmutabilityEnforced                 = "TAG_IMMUTABILITY_ENFORCED"
)

func IsLevelHigherOrEqualTo(level1, level2 SlsaSourceLevel) bool {
	// There's probably some fancy stuff we can get in to, but...
	// it just so happens that these level strings should sort the way we want.
	return level1 >= level2
}

type Control struct {
	// The name of the control
	Name string `json:"name"`
	// The time from which this control has been continuously enforced/observed.
	Since time.Time `json:"since"`
}

type Controls []Control

// Adds the control to the list. Ignores nil controls.
// Does not check for duplicate controls.
func (controls *Controls) AddControl(control *Control) {
	if control == nil {
		return
	}
	*controls = append(*controls, *control)
}

// Gets the control with the corresponding name, returns nil if not found.
func (controls Controls) GetControl(name string) *Control {
	for _, control := range controls {
		if control.Name == name {
			return &control
		}
	}
	return nil
}

// These can be any string, not just SlsaLevels
type SourceVerifiedLevels []string

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
