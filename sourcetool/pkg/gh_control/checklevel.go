package gh_control

import (
	"context"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/google/go-github/v69/github"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa_types"
)

type actor struct {
	Login string `json:"login"`
}

type activity struct {
	Id           int
	Before       string
	After        string
	Ref          string
	Timestamp    time.Time
	ActivityType string `json:"activity_type"`
	Actor        actor  `json:"actor"`
}

func (ghc *GitHubConnection) commitActivity(ctx context.Context, commit string) (*activity, error) {
	// Unfortunately the gh_client doesn't have native support for this...'
	reqUrl := fmt.Sprintf("repos/%s/%s/activity", ghc.Owner, ghc.Repo)
	req, err := ghc.Client.NewRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}

	var result []*activity
	_, err = ghc.Client.Do(ctx, req, &result)
	if err != nil {
		return nil, err
	}

	targetRef := ghc.GetFullBranch()
	monitoredTypes := []string{"push", "force_push", "pr_merge"}
	for _, activity := range result {
		if !slices.Contains(monitoredTypes, activity.ActivityType) {
			continue
		}
		if activity.After == commit && activity.Ref == targetRef {
			// Found it
			return activity, nil
		}
	}

	return nil, fmt.Errorf("could not find repo activity for commit %s", commit)
}

type GhControlStatus struct {
	// The time the commit we're evaluating was pushed.
	CommitPushTime time.Time
	// The actor that pushed the commit.
	ActorLogin string
	// The type of activity that created the commit.
	ActivityType string
	// The controls that are enabled according to the GitHub API.
	// May not include other controls like if we have provenance.
	Controls slsa_types.Controls
}

func (ghc *GitHubConnection) ruleMeetsRequiresReview(rule *github.PullRequestBranchRule) bool {
	return rule.Parameters.RequiredApprovingReviewCount > 0 &&
		rule.Parameters.DismissStaleReviewsOnPush &&
		rule.Parameters.RequireCodeOwnerReview &&
		rule.Parameters.RequireLastPushApproval
}

// Computes the continuity control returning nil if it's not enabled.
func (ghc *GitHubConnection) computeContinuityControl(ctx context.Context, commit string, rules *github.BranchRules, activity *activity) (*slsa_types.Control, error) {
	oldestDeletion, err := ghc.getOldestActiveRule(ctx, rules.Deletion)
	if err != nil {
		return nil, err
	}

	oldestNoFf, err := ghc.getOldestActiveRule(ctx, rules.NonFastForward)
	if err != nil {
		return nil, err
	}

	if oldestDeletion == nil || oldestNoFf == nil {
		log.Printf("oldestDeletion (%v) or oldestNoFf (%v) is nil, cannot be L2+", oldestDeletion, oldestNoFf)
		return nil, nil
	}

	newestRule := oldestDeletion
	if newestRule.UpdatedAt.Time.Before(oldestNoFf.UpdatedAt.Time) {
		newestRule = oldestNoFf
	}

	// Check that the commit was created after the newest rule was enabled...
	// to be sure folks aren't somehow sneaking something through...
	if activity.Timestamp.Before(newestRule.UpdatedAt.Time) {
		return nil, fmt.Errorf("commit %s created before (%v) the rule was enabled (%v), that shouldn't happen", commit, activity.Timestamp, newestRule.UpdatedAt.Time)
	}

	return &slsa_types.Control{Name: slsa_types.ContinuityEnforced, Since: newestRule.UpdatedAt.Time}, nil
}

func enforcesImmutableTags(ruleset *github.RepositoryRuleset) bool {
	if ruleset.Rules != nil &&
		ruleset.Rules.Update != nil &&
		ruleset.Rules.Deletion != nil &&
		ruleset.Rules.NonFastForward != nil &&
		len(ruleset.Conditions.RefName.Exclude) == 0 &&
		slices.Contains(ruleset.Conditions.RefName.Include, "~ALL") {
		return true
	}
	return false
}

func (ghc *GitHubConnection) computeImmutableTagsControl(ctx context.Context, commit string, allRulesets []*github.RepositoryRuleset, activity *activity) (*slsa_types.Control, error) {
	var validRuleset *github.RepositoryRuleset
	for _, ruleset := range allRulesets {
		if *ruleset.Target != github.RulesetTargetTag {
			continue
		}

		if ruleset.Enforcement != github.RulesetEnforcementActive {
			continue
		}

		// The GitHub API only seems to return a partial ruleset when asking for 'all' the rules
		// So we'll ask for this specific rule here so we can get all the data.
		fullRuleset, _, err := ghc.Client.Repositories.GetRuleset(ctx, ghc.Owner, ghc.Repo, ruleset.GetID(), false)
		if err != nil {
			return nil, fmt.Errorf("could not get full ruleset for ruleset id %d", ruleset.GetID())
		}

		if !enforcesImmutableTags(fullRuleset) {
			continue
		}
		if validRuleset == nil || validRuleset.UpdatedAt.After(ruleset.UpdatedAt.Time) {
			validRuleset = ruleset
		}
	}

	if validRuleset == nil {
		return nil, nil
	}

	// Check that the commit was created after this rule was enabled.
	if activity.Timestamp.Before(validRuleset.UpdatedAt.Time) {
		return nil, nil
	}

	return &slsa_types.Control{Name: slsa_types.ImmutableTags, Since: validRuleset.UpdatedAt.Time}, nil
}

// Computes the review control returning nil if it's not enabled.
func (ghc *GitHubConnection) computeReviewControl(ctx context.Context, rules []*github.PullRequestBranchRule) (*slsa_types.Control, error) {
	var oldestActive *github.RepositoryRuleset
	for _, rule := range rules {
		if ghc.ruleMeetsRequiresReview(rule) {
			ruleset, _, err := ghc.Client.Repositories.GetRuleset(ctx, ghc.Owner, ghc.Repo, rule.RulesetID, false)
			if err != nil {
				return nil, err
			}
			if ruleset.Enforcement == "active" {
				if oldestActive == nil || oldestActive.UpdatedAt.Time.After(ruleset.UpdatedAt.Time) {
					oldestActive = ruleset
				}
			}
		}
	}

	if oldestActive != nil {
		return &slsa_types.Control{Name: slsa_types.ReviewEnforced, Since: oldestActive.UpdatedAt.Time}, nil
	}

	return nil, nil
}

func (ghc *GitHubConnection) getOldestActiveRule(ctx context.Context, rules []*github.BranchRuleMetadata) (*github.RepositoryRuleset, error) {
	var oldestActive *github.RepositoryRuleset
	for _, rule := range rules {
		ruleset, _, err := ghc.Client.Repositories.GetRuleset(ctx, ghc.Owner, ghc.Repo, rule.RulesetID, false)
		if err != nil {
			return nil, err
		}
		if ruleset.Enforcement == "active" {
			if oldestActive == nil || oldestActive.UpdatedAt.Time.After(ruleset.UpdatedAt.Time) {
				oldestActive = ruleset
			}
		}
	}
	return oldestActive, nil
}

// Determines the controls that are in place using GitHub's APIs.
// This is necessarily only as good as GitHub's controls and existing APIs.
func (ghc *GitHubConnection) GetControls(ctx context.Context, commit string) (*GhControlStatus, error) {
	// We want to know when this commit was pushed to ensure the rules were active _then_.
	activity, err := ghc.commitActivity(ctx, commit)
	if err != nil {
		return nil, err
	}

	controlStatus := GhControlStatus{
		CommitPushTime: activity.Timestamp,
		ActivityType:   activity.ActivityType,
		ActorLogin:     activity.Actor.Login,
		Controls:       slsa_types.Controls{}}

	branchRules, _, err := ghc.Client.Repositories.GetRulesForBranch(ctx, ghc.Owner, ghc.Repo, ghc.Branch)
	if err != nil {
		return nil, err
	}

	allRulesets, _, err := ghc.Client.Repositories.GetAllRulesets(ctx, ghc.Owner, ghc.Repo, true)
	if err != nil {
		return nil, err
	}

	// Compute the controls enforced.
	continuityControl, err := ghc.computeContinuityControl(ctx, commit, branchRules, activity)
	if err != nil {
		return nil, fmt.Errorf("could not populate ContinuityControl: %w", err)
	}
	controlStatus.Controls.AddControl(continuityControl)

	ImmutableTagsControl, err := ghc.computeImmutableTagsControl(ctx, commit, allRulesets, activity)
	if err != nil {
		return nil, fmt.Errorf("could not populate ImmutableTagsControl: %w", err)
	}
	controlStatus.Controls.AddControl(ImmutableTagsControl)

	reviewControl, err := ghc.computeReviewControl(ctx, branchRules.PullRequest)
	if err != nil {
		return nil, fmt.Errorf("could not populate ReviewControl: %w", err)
	}
	controlStatus.Controls.AddControl(reviewControl)

	return &controlStatus, nil
}
