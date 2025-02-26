package gh_control

import (
	"context"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa_types"

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

type SlsaLevelControl struct {
	Level        string
	EnabledSince time.Time
}

type GhControlStatus struct {
	// The SLSA Source Level the _controls_ in this repo meet.
	SlsaLevelControl SlsaLevelControl
	// The time the commit we're evaluating was pushed.
	CommitPushTime time.Time
	// The actor that pushed the commit.
	ActorLogin string
	// The type of activity that created the commit.
	ActivityType string
	// True if the branch requires review
	RequiresReview      bool
	RequiresReviewSince time.Time
}

func (ghc *GitHubConnection) ruleMeetsRequiresReview(rule *github.PullRequestBranchRule) bool {
	return rule.Parameters.RequiredApprovingReviewCount > 0 &&
		rule.Parameters.DismissStaleReviewsOnPush &&
		rule.Parameters.RequireCodeOwnerReview &&
		rule.Parameters.RequireLastPushApproval
}

func (ghc *GitHubConnection) populateRequiresReview(ctx context.Context, rules []*github.PullRequestBranchRule, controlStatus *GhControlStatus) error {
	var oldestActive *github.RepositoryRuleset
	for _, rule := range rules {
		if ghc.ruleMeetsRequiresReview(rule) {
			ruleset, _, err := ghc.Client.Repositories.GetRuleset(ctx, ghc.Owner, ghc.Repo, rule.RulesetID, false)
			if err != nil {
				return err
			}
			if ruleset.Enforcement == "active" {
				if oldestActive == nil || oldestActive.UpdatedAt.Time.After(ruleset.UpdatedAt.Time) {
					oldestActive = ruleset
				}
			}
		}
	}

	if oldestActive != nil {
		controlStatus.RequiresReview = true
		controlStatus.RequiresReviewSince = oldestActive.UpdatedAt.Time
	}

	return nil
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
		// Default to L1, but upgrade later if possible.
		SlsaLevelControl: SlsaLevelControl{
			Level:        slsa_types.SlsaSourceLevel1,
			EnabledSince: time.Time{}},
		CommitPushTime: activity.Timestamp,
		ActivityType:   activity.ActivityType,
		ActorLogin:     activity.Actor.Login}

	rules, _, err := ghc.Client.Repositories.GetRulesForBranch(ctx, ghc.Owner, ghc.Repo, ghc.Branch)

	if err != nil {
		return nil, err
	}

	oldestDeletion, err := ghc.getOldestActiveRule(ctx, rules.Deletion)
	if err != nil {
		return nil, err
	}

	oldestNoFastForward, err := ghc.getOldestActiveRule(ctx, rules.Deletion)
	if err != nil {
		return nil, err
	}

	if oldestDeletion == nil || oldestNoFastForward == nil {
		log.Printf("oldestDeletion (%v) or oldestNoFastForward (%v) is nil, cannot be L2+", oldestDeletion, oldestNoFastForward)
		return &controlStatus, nil
	}

	newestRule := oldestDeletion
	if newestRule.UpdatedAt.Time.Before(oldestNoFastForward.UpdatedAt.Time) {
		newestRule = oldestNoFastForward
	}

	// Check that the commit was created after the newest rule was enabled...
	// to be sure folks aren't somehow sneaking something through...
	if activity.Timestamp.Before(newestRule.UpdatedAt.Time) {
		return nil, fmt.Errorf("commit %s created before (%v) the rule was enabled (%v), that shouldn't happen", commit, activity.Timestamp, newestRule.UpdatedAt.Time)
	}

	// All the rules required for L2 are enabled.
	controlStatus.SlsaLevelControl.Level = slsa_types.SlsaSourceLevel2
	controlStatus.SlsaLevelControl.EnabledSince = newestRule.UpdatedAt.Time

	// Let's get some extra information, like do they require reviews?
	err = ghc.populateRequiresReview(ctx, rules.PullRequest, &controlStatus)
	if err != nil {
		log.Printf("failed to populate requires review information: %s", err)
	}

	return &controlStatus, nil
}
