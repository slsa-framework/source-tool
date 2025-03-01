package slsa_types

import "time"

type SlsaSourceLevelData struct {
	LevelName string
	LevelNum  int
}

type SlsaSourceLevel *SlsaSourceLevelData

const (
	SlsaSourceLevel1    = "SLSA_SOURCE_LEVEL_1"
	SlsaSourceLevel2    = "SLSA_SOURCE_LEVEL_2"
	SlsaSourceLevel3    = "SLSA_SOURCE_LEVEL_3"
	ContinuityEnforced  = "CONTINUITY_ENFORCED"
	ProvenanceAvailable = "PROVENANCE_AVAILABLE"
	ReviewEnforced      = "REVIEW_ENFORCED"
)

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

type SourceVerifiedLevels []string
