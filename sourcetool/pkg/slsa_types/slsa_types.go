package slsa_types

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
