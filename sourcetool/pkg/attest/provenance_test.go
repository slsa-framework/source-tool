package attest

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-github/v69/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/gh_control"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa_types"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/testsupport"
)

var rulesetOldTime = time.Now().Add(-time.Hour)

func rulesForTagImmutability() *github.RepositoryRulesetRules {
	return &github.RepositoryRulesetRules{
		Update:         &github.UpdateRuleParameters{},
		Deletion:       &github.EmptyRuleParameters{},
		NonFastForward: &github.EmptyRuleParameters{},
	}
}

func conditionsForTagImmutability() *github.RepositoryRulesetConditions {
	return &github.RepositoryRulesetConditions{
		RefName: &github.RepositoryRulesetRefConditionParameters{
			Include: []string{"~ALL"},
		},
	}
}

func createTestVsa(t *testing.T, repoUri, ref, commit string, verifiedLevels slsa_types.SourceVerifiedLevels) string {
	vsa, err := CreateUnsignedSourceVsa(repoUri, ref, commit, verifiedLevels, "test-policy")
	if err != nil {
		t.Fatalf("failure creating test vsa: %v", err)
	}
	return vsa
}

func newNotesContent(content string) *github.RepositoryContent {
	return &github.RepositoryContent{
		Content: github.Ptr(content),
	}
}

func newImmutableTagsRulesetsResponse(id int64, target github.RulesetTarget, enforcement github.RulesetEnforcement,
	updatedAt time.Time) *github.RepositoryRuleset {
	return &github.RepositoryRuleset{
		ID:          github.Ptr(id),
		Target:      github.Ptr(target),
		Enforcement: enforcement,
		UpdatedAt:   github.Ptr(github.Timestamp{Time: updatedAt}),
		Rules:       rulesForTagImmutability(),
		Conditions:  conditionsForTagImmutability(),
	}
}

func newMockedGitHubClient(rulesetResponse *github.RepositoryRuleset, notesContent *github.RepositoryContent) *github.Client {
	return github.NewClient(mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetReposRulesetsByOwnerByRepo,
			[]*github.RepositoryRuleset{
				rulesetResponse,
			},
		),
		mock.WithRequestMatch(
			mock.GetReposRulesetsByOwnerByRepoByRulesetId,
			*rulesetResponse,
		),
		mock.WithRequestMatch(
			mock.GetReposContentsByOwnerByRepoByPath,
			*notesContent,
		),
	))
}

// Helper to create a test GH Branch connection with no client.
func newTestGhConnection(owner, repo, branch string, rulesetResponse *github.RepositoryRuleset, notesContent *github.RepositoryContent) *gh_control.GitHubConnection {
	return gh_control.NewGhConnectionWithClient(
		owner, repo, gh_control.BranchToFullRef(branch),
		newMockedGitHubClient(rulesetResponse, notesContent))
}

func timesEqualWithinMargin(t1, t2 time.Time, margin time.Duration) bool {
	diff := t1.Sub(t2).Abs()
	return diff <= margin
}

func assertTagProvPredsEqual(t *testing.T, actual, expected TagProvenancePred) {
	if actual.ActivityType != expected.ActivityType {
		t.Errorf("ActivityType %v does not match expected value %v", actual.ActivityType, expected.ActivityType)
	}

	if actual.Actor != expected.Actor {
		t.Errorf("Actor %v does not match expected value %v", actual.Actor, expected.Actor)
	}

	if actual.RepoUri != expected.RepoUri {
		t.Errorf("RepoUri %v does not match expected value %v", actual.RepoUri, expected.RepoUri)
	}

	if actual.Tag != expected.Tag {
		t.Errorf("Tag %v does not match expected value %v", actual.Tag, expected.Tag)
	}

	if timesEqualWithinMargin(actual.CreatedOn, expected.CreatedOn, 5*time.Second) {
		t.Errorf("CreatedOn %v does not match expected value %v", actual.CreatedOn, expected.CreatedOn)
	}

	if len(actual.Controls) != len(expected.Controls) {
		t.Errorf("Control %v does not match expected value %v", actual.Controls, expected.Controls)
	} else {
		for ci, _ := range actual.Controls {
			if !timesEqualWithinMargin(actual.Controls[ci].Since, expected.Controls[ci].Since, time.Second) {
				t.Errorf("control at [%d]'s time %v does not match expected time %v", ci,
					actual.Controls[ci].Since, expected.Controls[ci].Since)
			}
		}
	}
	if !reflect.DeepEqual(actual.VsaSummaries, expected.VsaSummaries) {
		t.Errorf("VsaSummaries %v does not match expected value %v", actual.VsaSummaries, expected.VsaSummaries)
	}
}

func TestCreateTagProvenance(t *testing.T) {
	testVsa := createTestVsa(t, "http://repo", "refs/some/ref", "abc123", slsa_types.SourceVerifiedLevels{"TEST_LEVEL"})

	ghc := newTestGhConnection("owner", "repo", "branch",
		newImmutableTagsRulesetsResponse(123, github.RulesetTargetTag,
			github.RulesetEnforcementActive, rulesetOldTime),
		newNotesContent(testVsa))
	verifier := testsupport.NewMockVerifier()

	pa := NewProvenanceAttestor(ghc, verifier)

	stmt, err := pa.CreateTagProvenance(context.Background(), "abc123", "refs/tags/v1")
	if err != nil {
		t.Fatalf("error creating tag prov %v", err)
	}

	if stmt == nil {
		t.Fatalf("returned statement is nil")
	}

	if stmt.PredicateType != TagProvPredicateType {
		t.Errorf("statement pred type %v does not match expected %v", stmt.PredicateType, TagProvPredicateType)
	}

	if !DoesSubjectIncludeCommit(stmt, "abc123") {
		t.Errorf("statement subject %v does not match expected %v", stmt.Subject, "abc123")
	}

	tagPred, err := GetTagProvPred(stmt)
	if err != nil {
		t.Fatalf("error getting tag prov %v", err)
	}

	expectedPred := TagProvenancePred{
		RepoUri:      "https://github.com/owner/repo",
		Actor:        "unknown actor",
		ActivityType: "unknown activity type",
		Tag:          "refs/tags/v1",
		CreatedOn:    rulesetOldTime,
		Controls: []slsa_types.Control{
			{
				Name:  "IMMUTABLE_TAGS",
				Since: rulesetOldTime,
			},
		},
		VsaSummaries: []VsaSummary{
			{
				SourceRefs:     []string{"refs/some/ref"},
				VerifiedLevels: []string{"TEST_LEVEL"},
			},
		},
	}

	assertTagProvPredsEqual(t, *tagPred, expectedPred)
}
