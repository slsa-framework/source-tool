package gh_control

import (
	"context"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/google/go-github/v69/github"
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

type ContinuityControl struct {
	RequiresContinuity bool
	EnabledSince       time.Time
}

type ReviewControl struct {
	RequiresReview bool
	EnabledSince   time.Time
}

type GhControlStatus struct {
	ContinuityControl ContinuityControl
	ReviewControl     ReviewControl
	// The time the commit we're evaluating was pushed.
	CommitPushTime time.Time
	// The actor that pushed the commit.
	ActorLogin string
	// The type of activity that created the commit.
	ActivityType string
}

func (ghc *GitHubConnection) ruleMeetsRequiresReview(rule *github.PullRequestBranchRule) bool {
	return rule.Parameters.RequiredApprovingReviewCount > 0 &&
		rule.Parameters.DismissStaleReviewsOnPush &&
		rule.Parameters.RequireCodeOwnerReview &&
		rule.Parameters.RequireLastPushApproval
}

func (ghc *GitHubConnection) computeContinuityControl(ctx context.Context, commit string, rules *github.BranchRules, activity *activity) (ContinuityControl, error) {
	oldestDeletion, err := ghc.getOldestActiveRule(ctx, rules.Deletion)
	if err != nil {
		return ContinuityControl{}, err
	}

	oldestNoFf, err := ghc.getOldestActiveRule(ctx, rules.NonFastForward)
	if err != nil {
		return ContinuityControl{}, err
	}

	if oldestDeletion == nil || oldestNoFf == nil {
		log.Printf("oldestDeletion (%v) or oldestNoFastForward (%v) is nil, cannot be L2+", oldestDeletion, oldestNoFf)
		return ContinuityControl{RequiresContinuity: false, EnabledSince: time.Time{}}, nil
	}

	newestRule := oldestDeletion
	if newestRule.UpdatedAt.Time.Before(oldestNoFf.UpdatedAt.Time) {
		newestRule = oldestNoFf
	}

	// Check that the commit was created after the newest rule was enabled...
	// to be sure folks aren't somehow sneaking something through...
	if activity.Timestamp.Before(newestRule.UpdatedAt.Time) {
		return ContinuityControl{}, fmt.Errorf("commit %s created before (%v) the rule was enabled (%v), that shouldn't happen", commit, activity.Timestamp, newestRule.UpdatedAt.Time)
	}

	// All the rules required for L2 are enabled.
	return ContinuityControl{RequiresContinuity: true, EnabledSince: newestRule.UpdatedAt.Time}, nil
}

func (ghc *GitHubConnection) computeReviewControl(ctx context.Context, rules []*github.PullRequestBranchRule) (ReviewControl, error) {
	var oldestActive *github.RepositoryRuleset
	for _, rule := range rules {
		if ghc.ruleMeetsRequiresReview(rule) {
			ruleset, _, err := ghc.Client.Repositories.GetRuleset(ctx, ghc.Owner, ghc.Repo, rule.RulesetID, false)
			if err != nil {
				return ReviewControl{}, err
			}
			if ruleset.Enforcement == "active" {
				if oldestActive == nil || oldestActive.UpdatedAt.Time.After(ruleset.UpdatedAt.Time) {
					oldestActive = ruleset
				}
			}
		}
	}

	if oldestActive != nil {
		return ReviewControl{RequiresReview: true, EnabledSince: oldestActive.UpdatedAt.Time}, nil
	}

	return ReviewControl{}, nil
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

// Determines the source level using GitHub's built in controls only.
// This is necessarily only as good as GitHub's controls and existing APIs.
// This is a useful demonstration on how SLSA Level 2 can be achieved with ~minimal effort.
//
// Returns the determined source level (level 2 max) or error.
func (ghc *GitHubConnection) DetermineSourceLevelControlOnly(ctx context.Context, commit string) (*GhControlStatus, error) {
	// We want to know when this commit was pushed to ensure the rules were active _then_.
	activity, err := ghc.commitActivity(ctx, commit)
	if err != nil {
		return nil, err
	}

	controlStatus := GhControlStatus{
		// Assume continuity isn't required until we find otherwise.
		ContinuityControl: ContinuityControl{
			RequiresContinuity: false,
			EnabledSince:       time.Time{}},
		CommitPushTime: activity.Timestamp,
		ActivityType:   activity.ActivityType,
		ActorLogin:     activity.Actor.Login}

	rules, _, err := ghc.Client.Repositories.GetRulesForBranch(ctx, ghc.Owner, ghc.Repo, ghc.Branch)

	if err != nil {
		return nil, err
	}

	// Compute the controls enforced.
	controlStatus.ContinuityControl, err = ghc.computeContinuityControl(ctx, commit, rules, activity)
	if err != nil {
		return nil, fmt.Errorf("could not populate ContinuityControl: %w", err)
	}

	controlStatus.ReviewControl, err = ghc.computeReviewControl(ctx, rules.PullRequest)
	if err != nil {
		return nil, fmt.Errorf("could not populate ReviewControl: %w", err)
	}

	return &controlStatus, nil
}
