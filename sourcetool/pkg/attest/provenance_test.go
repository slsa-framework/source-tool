package attest

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-github/v69/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
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

func createTestProv(t *testing.T, repoUri, ref, commit string) string {

	provPred := SourceProvenancePred{RepoUri: repoUri, Branch: ref, ActivityType: "pr_merge", Actor: "test actor"}
	stmt, err := addPredToStatement(provPred, SourceProvPredicateType, commit)
	if err != nil {
		t.Fatalf("failure creating test prov: %v", err)
	}

	statementBytes, err := json.Marshal(&stmt)
	if err != nil {
		t.Fatalf("failure marshalling statement: %v", err)
	}
	return string(statementBytes)
}

func newNotesContent(content string) *github.RepositoryContent {
	return &github.RepositoryContent{
		Content: github.Ptr(content),
	}
}

func newTagHygieneRulesetsResponse(id int64, target github.RulesetTarget, enforcement github.RulesetEnforcement,
	updatedAt time.Time,
) *github.RepositoryRuleset {
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
func newTestGhConnection(owner, repo, branch string, rulesetResponse *github.RepositoryRuleset, notesContent *github.RepositoryContent) *ghcontrol.GitHubConnection {
	return ghcontrol.NewGhConnectionWithClient(
		owner, repo, ghcontrol.BranchToFullRef(branch),
		newMockedGitHubClient(rulesetResponse, notesContent))
}

func timesEqualWithinMargin(t1, t2 time.Time, margin time.Duration) bool {
	diff := t1.Sub(t2).Abs()
	return diff <= margin
}

func assertTagProvPredsEqual(t *testing.T, actual, expected *TagProvenancePred) {
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
		for ci := range actual.Controls {
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

func TestReadProvSuccess(t *testing.T) {
	testProv := createTestProv(t, "https://github.com/owner/repo", "main", "abc123")
	ghc := newTestGhConnection("owner", "repo", "branch",
		// We just need _some_ rulesets response, we don't care what.
		newTagHygieneRulesetsResponse(123, github.RulesetTargetTag,
			github.RulesetEnforcementActive, rulesetOldTime),
		newNotesContent(testProv))
	verifier := testsupport.NewMockVerifier()

	pa := NewProvenanceAttestor(ghc, verifier)
	readStmt, readPred, err := pa.GetProvenance(t.Context(), "abc123", "main")
	if err != nil {
		t.Fatalf("error finding prov: %v", err)
	}
	if readStmt == nil || readPred == nil {
		t.Errorf("could not find provenance")
	}
}

func TestReadProvFailure(t *testing.T) {
	testProv := createTestProv(t, "foo", "main", "abc123")
	ghc := newTestGhConnection("owner", "repo", "branch",
		// We just need _some_ rulesets response, we don't care what.
		newTagHygieneRulesetsResponse(123, github.RulesetTargetTag,
			github.RulesetEnforcementActive, rulesetOldTime),
		newNotesContent(testProv))
	verifier := testsupport.NewMockVerifier()

	pa := NewProvenanceAttestor(ghc, verifier)
	_, readPred, err := pa.GetProvenance(t.Context(), "abc123", "main")
	if err != nil {
		t.Fatalf("error finding prov: %v", err)
	}
	if readPred != nil {
		t.Errorf("should not have gotten provenance: %+v", readPred)
	}
}

func TestCreateTagProvenance(t *testing.T) {
	testVsa := createTestVsa(t, "http://repo", "refs/some/ref", "abc123", slsa.SourceVerifiedLevels{"TEST_LEVEL"})

	ghc := newTestGhConnection("owner", "repo", "branch",
		newTagHygieneRulesetsResponse(123, github.RulesetTargetTag,
			github.RulesetEnforcementActive, rulesetOldTime),
		newNotesContent(testVsa))
	verifier := testsupport.NewMockVerifier()

	pa := NewProvenanceAttestor(ghc, verifier)

	stmt, err := pa.CreateTagProvenance(t.Context(), "abc123", "refs/tags/v1", "the-tag-pusher")
	if err != nil {
		t.Fatalf("error creating tag prov %v", err)
	}

	if stmt == nil {
		t.Fatalf("returned statement is nil")
	}

	if stmt.GetPredicateType() != TagProvPredicateType {
		t.Errorf("statement pred type %v does not match expected %v", stmt.GetPredicateType(), TagProvPredicateType)
	}

	if !DoesSubjectIncludeCommit(stmt, "abc123") {
		t.Errorf("statement subject %v does not match expected %v", stmt.GetSubject(), "abc123")
	}

	tagPred, err := GetTagProvPred(stmt)
	if err != nil {
		t.Fatalf("error getting tag prov %v", err)
	}

	expectedPred := TagProvenancePred{
		RepoUri:   "https://github.com/owner/repo",
		Actor:     "the-tag-pusher",
		Tag:       "refs/tags/v1",
		CreatedOn: rulesetOldTime,
		Controls: []slsa.Control{
			{
				Name:  "TAG_HYGIENE",
				Since: rulesetOldTime,
			},
		},
		VsaSummaries: []VsaSummary{
			{
				SourceRefs:     []string{"refs/some/ref"},
				VerifiedLevels: []slsa.ControlName{"TEST_LEVEL"},
			},
		},
	}

	assertTagProvPredsEqual(t, tagPred, &expectedPred)
}
