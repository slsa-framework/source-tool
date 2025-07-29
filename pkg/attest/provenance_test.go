package attest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-github/v69/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slsa-framework/slsa-source-poc/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/pkg/provenance"
	"github.com/slsa-framework/slsa-source-poc/pkg/slsa"
	"github.com/slsa-framework/slsa-source-poc/pkg/testsupport"
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
	provPred := provenance.SourceProvenancePred{RepoUri: repoUri, Branch: ref, ActivityType: "pr_merge", Actor: "test actor"}
	stmt, err := addPredToStatement(&provPred, provenance.SourceProvPredicateType, commit)
	if err != nil {
		t.Fatalf("failure creating test prov: %v", err)
	}

	statementBytes, err := json.Marshal(&stmt)
	require.NoError(t, err, "failure marshalling statement: %v", err)

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

func assertTagProvPredsEqual(t *testing.T, actual, expected *provenance.TagProvenancePred) {
	if actual.GetActor() != expected.GetActor() {
		t.Errorf("Actor %v does not match expected value %v", actual.GetActor(), expected.GetActor())
	}

	if actual.GetRepoUri() != expected.GetRepoUri() {
		t.Errorf("RepoUri %v does not match expected value %v", actual.GetRepoUri(), expected.GetRepoUri())
	}

	if actual.GetTag() != expected.GetTag() {
		t.Errorf("Tag %v does not match expected value %v", actual.GetTag(), expected.GetTag())
	}

	if timesEqualWithinMargin(actual.GetCreatedOn().AsTime(), expected.GetCreatedOn().AsTime(), 5*time.Second) {
		t.Errorf("CreatedOn %v does not match expected value %v", actual.GetCreatedOn(), expected.GetCreatedOn())
	}

	if len(actual.GetControls()) != len(expected.GetControls()) {
		t.Errorf("Control %v does not match expected value %v", actual.GetControls(), expected.GetControls())
	} else {
		for ci := range actual.GetControls() {
			if !timesEqualWithinMargin(actual.GetControls()[ci].GetSince().AsTime(), expected.GetControls()[ci].GetSince().AsTime(), time.Second) {
				t.Errorf("control at [%d]'s time %v does not match expected time %v", ci,
					actual.GetControls()[ci].GetSince(), expected.GetControls()[ci].GetSince())
			}
		}
	}

	require.Len(t, actual.GetVsaSummaries(), len(expected.GetVsaSummaries()))
	for i := range actual.GetVsaSummaries() {
		if !proto.Equal(actual.GetVsaSummaries()[i], expected.GetVsaSummaries()[i]) {
			t.Errorf("VsaSummaries %v does not match expected value %v", actual.GetVsaSummaries(), expected.GetVsaSummaries())
		}
	}
}

func TestReadProvSuccess(t *testing.T) {
	testProv := createTestProv(t, "https://github.com/owner/repo", "main", "73f0a864c2c9af12e03dae433a6ff5f5e719d7aa")
	ghc := newTestGhConnection("owner", "repo", "branch",
		// We just need _some_ rulesets response, we don't care what.
		newTagHygieneRulesetsResponse(123, github.RulesetTargetTag,
			github.RulesetEnforcementActive, rulesetOldTime),
		newNotesContent(testProv))
	verifier := testsupport.NewMockVerifier()

	pa := NewProvenanceAttestor(ghc, verifier)
	readStmt, readPred, err := pa.GetProvenance(t.Context(), "73f0a864c2c9af12e03dae433a6ff5f5e719d7aa", "main")
	if err != nil {
		t.Fatalf("error finding prov: %v", err)
	}
	if readStmt == nil || readPred == nil {
		t.Errorf("could not find provenance")
	}
}

func TestReadProvFailure(t *testing.T) {
	testProv := createTestProv(t, "foo", "main", "73f0a864c2c9af12e03dae433a6ff5f5e719d7aa")
	ghc := newTestGhConnection("owner", "repo", "branch",
		// We just need _some_ rulesets response, we don't care what.
		newTagHygieneRulesetsResponse(456, github.RulesetTargetBranch,
			github.RulesetEnforcementEvaluate, rulesetOldTime),
		newNotesContent(testProv))
	verifier := testsupport.NewMockVerifier()

	pa := NewProvenanceAttestor(ghc, verifier)
	_, readPred, err := pa.GetProvenance(t.Context(), "73f0a864c2c9af12e03dae433a6ff5f5e719d7aa", "main")
	if err != nil {
		t.Fatalf("error finding prov: %v", err)
	}
	if readPred != nil {
		t.Errorf("should not have gotten provenance: %+v", readPred)
	}
}

func TestCreateTagProvenance(t *testing.T) {
	testVsa := createTestVsa(t, "https://github.com/owner/repo", "refs/some/ref", "73f0a864c2c9af12e03dae433a6ff5f5e719d7aa", slsa.SourceVerifiedLevels{"TEST_LEVEL"})

	ghc := newTestGhConnection("owner", "repo", "branch",
		newTagHygieneRulesetsResponse(123, github.RulesetTargetTag,
			github.RulesetEnforcementActive, rulesetOldTime),
		newNotesContent(testVsa))
	verifier := testsupport.NewMockVerifier()

	pa := NewProvenanceAttestor(ghc, verifier)

	stmt, err := pa.CreateTagProvenance(t.Context(), "73f0a864c2c9af12e03dae433a6ff5f5e719d7aa", "refs/tags/v1", "the-tag-pusher")
	if err != nil {
		t.Fatalf("error creating tag prov %v", err)
	}

	if stmt == nil {
		t.Fatalf("returned statement is nil")
	}

	if stmt.GetPredicateType() != provenance.TagProvPredicateType {
		t.Errorf("statement pred type %v does not match expected %v", stmt.GetPredicateType(), provenance.TagProvPredicateType)
	}

	if !DoesSubjectIncludeCommit(stmt, "73f0a864c2c9af12e03dae433a6ff5f5e719d7aa") {
		t.Errorf("statement subject %v does not match expected %v", stmt.GetSubject(), "73f0a864c2c9af12e03dae433a6ff5f5e719d7aa")
	}

	tagPred, err := GetTagProvPred(stmt)
	if err != nil {
		t.Fatalf("error getting tag prov %v", err)
	}

	expectedPred := provenance.TagProvenancePred{
		RepoUri:   "https://github.com/owner/repo",
		Actor:     "the-tag-pusher",
		Tag:       "refs/tags/v1",
		CreatedOn: timestamppb.New(rulesetOldTime),
		Controls: []*provenance.Control{
			{
				Name:  "TAG_HYGIENE",
				Since: timestamppb.New(rulesetOldTime),
			},
		},
		VsaSummaries: []*provenance.VsaSummary{
			{
				SourceRefs:     []string{"refs/some/ref"},
				VerifiedLevels: []string{"TEST_LEVEL"},
			},
		},
	}

	assertTagProvPredsEqual(t, tagPred, &expectedPred)
}
