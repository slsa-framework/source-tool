package provenance

import (
	"time"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
)

const (
	SourceProvPredicateType = "https://github.com/slsa-framework/slsa-source-poc/source-provenance/v1-draft"
	TagProvPredicateType    = "https://github.com/slsa-framework/slsa-source-poc/tag-provenance/v1-draft"
)

// The predicate that encodes source provenance data.
// The git commit this corresponds to is encoded in the surrounding statement.
type SourceProvenancePred struct {
	// The commit preceding 'Commit' in the current context.
	PrevCommit   string    `json:"prev_commit"`
	RepoUri      string    `json:"repo_uri"`
	ActivityType string    `json:"activity_type"`
	Actor        string    `json:"actor"`
	Branch       string    `json:"branch"`
	CreatedOn    time.Time `json:"created_on"`
	// TODO: get the author of the PR (if this was from a PR).

	// The controls enabled at the time this commit was pushed.
	Controls slsa.Controls `json:"controls"`
}

type TagProvenancePred struct {
	RepoUri   string    `json:"repo_uri"`
	Actor     string    `json:"actor"`
	Tag       string    `json:"tag"`
	CreatedOn time.Time `json:"created_on"`
	// The tag related controls enabled at the time this tag was created/updated.
	Controls     slsa.Controls `json:"controls"`
	VsaSummaries []VsaSummary  `json:"vsa_summaries"`
}

// Summary of a summary
type VsaSummary struct {
	SourceRefs     []string           `json:"source_refs"`
	VerifiedLevels []slsa.ControlName `json:"verifiedLevels"`
}
