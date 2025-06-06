package ghcontrol

import (
	"encoding/json"
	"log"
	"slices"
	"testing"
	"time"

	"github.com/google/go-github/v69/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
)

var (
	curTime   = time.Unix(1678886400, 0) // March 15, 2023 00:00:00 UTC
	priorTime = curTime.Add(-time.Hour)
)

// branchOrTagName could also be ~ALL or ~DEFAULT?
func conditionsForRuleset(branchOrTagName string) *github.RepositoryRulesetConditions {
	return &github.RepositoryRulesetConditions{
		RefName: &github.RepositoryRulesetRefConditionParameters{
			Include: []string{branchOrTagName},
		},
	}
}

func newRepoRulesets(id int64, target github.RulesetTarget, enforcement github.RulesetEnforcement,
	updatedAt time.Time, rules *github.RepositoryRulesetRules,
) *github.RepositoryRuleset {
	return &github.RepositoryRuleset{
		ID:          github.Ptr(id),
		Target:      github.Ptr(target),
		Enforcement: enforcement,
		UpdatedAt:   github.Ptr(github.Timestamp{Time: updatedAt}),
		Rules:       rules,
		// ~ALL is really a tag specific thing but we don't use it for branches so let's
		// include it all the time so that when we do check it for tags it works.
		// We'll want to change this behavior for more advanced tests.
		Conditions: conditionsForRuleset("~ALL"),
	}
}

func rulesForBranchContinuity() *github.RepositoryRulesetRules {
	return &github.RepositoryRulesetRules{
		Deletion:       &github.EmptyRuleParameters{},
		NonFastForward: &github.EmptyRuleParameters{},
	}
}

// These rules should result in a CONTINUITY_ENFORCED control.
func createContinuityBranchRules() []branchRuleRawResponse {
	return []branchRuleRawResponse{
		{
			Type: github.RulesetRuleTypeDeletion,
			BranchRuleMetadata: github.BranchRuleMetadata{
				RulesetSourceType: github.RulesetSourceTypeRepository,
				RulesetSource:     "foo",
				RulesetID:         2,
			},
		},
		{
			Type: github.RulesetRuleTypeNonFastForward,
			BranchRuleMetadata: github.BranchRuleMetadata{
				RulesetSourceType: github.RulesetSourceTypeRepository,
				RulesetSource:     "foo",
				RulesetID:         2,
			},
		},
	}
}

// These rules should result in a CONTINUITY_ENFORCED control.
func createReviewBranchRules() []branchRuleRawResponse {
	br := branchRuleRawResponse{
		Type: github.RulesetRuleTypePullRequest,
		BranchRuleMetadata: github.BranchRuleMetadata{
			RulesetSourceType: github.RulesetSourceTypeRepository,
			RulesetSource:     "foo",
			RulesetID:         2,
		},
	}
	params := github.PullRequestRuleParameters{
		DismissStaleReviewsOnPush:    true,
		RequireCodeOwnerReview:       true,
		RequireLastPushApproval:      true,
		RequiredApprovingReviewCount: 1,
	}
	var err error
	br.Parameters, err = json.Marshal(params)
	if err != nil {
		log.Fatalf("could not marshal params %+v", params)
	}

	return []branchRuleRawResponse{br}
}

func rulesForReviewEnforced() *github.RepositoryRulesetRules {
	return &github.RepositoryRulesetRules{
		PullRequest: &github.PullRequestRuleParameters{},
	}
}

// These rules should result in a CONTINUITY_ENFORCED control.
func createTagHygieneRules() []branchRuleRawResponse {
	return []branchRuleRawResponse{
		{
			Type: github.RulesetRuleTypeDeletion,
			BranchRuleMetadata: github.BranchRuleMetadata{
				RulesetSourceType: github.RulesetSourceTypeRepository,
				RulesetSource:     "foo",
				RulesetID:         2,
			},
		},
		{
			Type: github.RulesetRuleTypeNonFastForward,
			BranchRuleMetadata: github.BranchRuleMetadata{
				RulesetSourceType: github.RulesetSourceTypeRepository,
				RulesetSource:     "foo",
				RulesetID:         2,
			},
		},
		{
			Type: github.RulesetRuleTypeUpdate,
			BranchRuleMetadata: github.BranchRuleMetadata{
				RulesetSourceType: github.RulesetSourceTypeRepository,
				RulesetSource:     "foo",
				RulesetID:         2,
			},
		},
	}
}

func rulesForTagHygiene() *github.RepositoryRulesetRules {
	return &github.RepositoryRulesetRules{
		Deletion:       &github.EmptyRuleParameters{},
		NonFastForward: &github.EmptyRuleParameters{},
		Update:         &github.UpdateRuleParameters{},
	}
}

func createRequiredChecksRules(checks []*github.RuleStatusCheck) []branchRuleRawResponse {
	br := branchRuleRawResponse{
		Type: github.RulesetRuleTypeRequiredStatusChecks,
		BranchRuleMetadata: github.BranchRuleMetadata{
			RulesetSourceType: github.RulesetSourceTypeRepository,
			RulesetSource:     "foo",
			RulesetID:         2,
		},
	}

	params := github.RequiredStatusChecksRuleParameters{
		RequiredStatusChecks: checks,
	}

	var err error
	br.Parameters, err = json.Marshal(params)
	if err != nil {
		log.Fatalf("could not marshal params %+v", params)
	}

	return []branchRuleRawResponse{br}
}

func rulesForRequiredChecks() *github.RepositoryRulesetRules {
	return &github.RepositoryRulesetRules{
		RequiredStatusChecks: &github.RequiredStatusChecksRuleParameters{},
	}
}

func newMockedGitHubClient(rulesetResponse *github.RepositoryRuleset, activityResponse []activity, branchRulesResponse *[]branchRuleRawResponse) *github.Client {
	// The real GH API returns different results for the various ruleset responses
	// Either because the 'list' option returns a summary or because the different IDs return different
	// values.  We're not going to both with that and instead just return as many copies of the same response
	// as needed.  In the future we might want to support testing different rules being enabled in different
	// rulesets, but that's a problem for the future.
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
			*rulesetResponse,
			*rulesetResponse,
		),
		mock.WithRequestMatch(
			mock.GetReposActivityByOwnerByRepo,
			activityResponse,
		),
		mock.WithRequestMatch(
			mock.GetReposRulesBranchesByOwnerByRepoByBranch,
			*branchRulesResponse,
		),
	))
}

// Helper to create a test GH Branch connection with no client.
func newTestGhConnection(owner, repo, branch string, rulesetResponse *github.RepositoryRuleset, activityResponse []activity, branchRulesResponse *[]branchRuleRawResponse) *GitHubConnection {
	return NewGhConnectionWithClient(
		owner, repo, BranchToFullRef(branch),
		newMockedGitHubClient(rulesetResponse, activityResponse, branchRulesResponse))
}

// The API doesn't just return BranchRuleMetadata, there's more to it.
type branchRuleRawResponse struct {
	Type github.RepositoryRuleType `json:"type"`
	github.BranchRuleMetadata
	Parameters json.RawMessage `json:"parameters"`
}

func activityForBranch(commit, ref string) []activity {
	return []activity{
		{
			Id:           1,
			Before:       "unused",
			After:        commit,
			Ref:          ref,
			Timestamp:    curTime,
			ActivityType: "pr_merge",
			Actor:        actor{Login: "the-actor"},
		},
	}
}

func TestBuiltinBranchControls(t *testing.T) {
	tests := []struct {
		branchRules     []branchRuleRawResponse
		rulesetRules    *github.RepositoryRulesetRules
		expectedControl slsa.ControlName
	}{
		{
			branchRules:     createContinuityBranchRules(),
			rulesetRules:    rulesForBranchContinuity(),
			expectedControl: slsa.ContinuityEnforced,
		},
		{
			branchRules:     createReviewBranchRules(),
			rulesetRules:    rulesForReviewEnforced(),
			expectedControl: slsa.ReviewEnforced,
		},
		{
			branchRules:     createTagHygieneRules(),
			rulesetRules:    rulesForTagHygiene(),
			expectedControl: slsa.TagHygiene,
		},
	}
	for _, tt := range tests {
		t.Run(string(tt.expectedControl), func(t *testing.T) {
			ghc := newTestGhConnection("owner", "repo", "branch_name",
				newRepoRulesets(123, github.RulesetTargetTag,
					github.RulesetEnforcementActive, priorTime, tt.rulesetRules),
				activityForBranch("abc123", "refs/heads/branch_name"), &tt.branchRules)

			controlStatus, err := ghc.GetBranchControls(t.Context(), "abc123", "refs/heads/branch_name")
			if err != nil {
				t.Fatalf("Error getting branch controls: %v", err)
			}

			control := controlStatus.Controls.GetControl(tt.expectedControl)
			if control == nil {
				t.Fatalf("expected controls to contain %v, got %+v", tt.expectedControl, controlStatus.Controls)
			}
			if !control.Since.Equal(priorTime) {
				t.Fatalf("expected control.Since %v, got %v", priorTime, control.Since)
			}
		})
	}
}

func TestGetBranchControlsRequiredChecks(t *testing.T) {
	tests := []struct {
		name                 string
		checks               []branchRuleRawResponse
		expectedControlNames []slsa.ControlName
	}{
		{
			name: "check with invalid id",
			checks: createRequiredChecksRules([]*github.RuleStatusCheck{
				{Context: "check-bad", IntegrationID: github.Ptr(int64(1))},
			}),
			expectedControlNames: []slsa.ControlName{},
		},
		{
			name: "check using Github Actions",
			checks: createRequiredChecksRules([]*github.RuleStatusCheck{
				{Context: "check-good", IntegrationID: github.Ptr(int64(15368))},
			}),
			expectedControlNames: []slsa.ControlName{"GH_REQUIRED_CHECK_check-good"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ghc := newTestGhConnection("owner", "repo", "branch_name",
				newRepoRulesets(123, github.RulesetTargetTag,
					github.RulesetEnforcementActive, priorTime, rulesForRequiredChecks()),
				activityForBranch("abc123", "refs/heads/branch_name"), &tt.checks)

			controlStatus, err := ghc.GetBranchControls(t.Context(), "abc123", "refs/heads/branch_name")
			if err != nil {
				t.Fatalf("Error getting branch controls: %v", err)
			}

			controlNames := []slsa.ControlName{}
			for _, control := range controlStatus.Controls {
				controlNames = append(controlNames, control.Name)
				if !control.Since.Equal(priorTime) {
					t.Errorf("Expected control.Since %v, got %v", priorTime, control.Since)
				}
			}

			if !slices.Equal(controlNames, tt.expectedControlNames) {
				t.Errorf("expected control names %v, got %v", tt.expectedControlNames, controlNames)
			}
		})
	}
}
