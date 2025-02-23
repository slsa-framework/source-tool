package gh_control

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa_types"

	"github.com/google/go-github/v68/github"
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

// Checks to see if the rule was enabled and since what time.
func (ghc GitHubConnection) checkRule(ctx context.Context, rule *github.RepositoryRule) (bool, time.Time, error) {
	ruleset, _, err := ghc.Client.Repositories.GetRuleset(ctx, ghc.Owner, ghc.Repo, rule.RulesetID, false)
	if err != nil {
		return false, time.Time{}, err
	}

	// We need rules to be 'active' and to have been updated no later than minTime.
	if ruleset.Enforcement != "active" {
		return false, time.Time{}, nil
	}

	return true, ruleset.UpdatedAt.Time, nil
}

func (ghc GitHubConnection) commitActivity(ctx context.Context, commit string) (*activity, error) {
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

	targetRef := fmt.Sprintf("refs/heads/%s", ghc.Branch)
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
	// The SLSA Source Level the _controls_ in this repo meet.
	ControlLevel string
	// The time the control has been enabled since.
	ControlLevelSince time.Time
	// The time the commit we're evaluating was pushed.
	CommitPushTime time.Time
	// The actor that pushed the commit.
	ActorLogin string
	// The type of activity that created the commit.
	ActivityType string
}

// Returns the time the rule has been enabled since or nil if we can't find one that's enabled and the rule itself.
func (ghc GitHubConnection) getRuleTime(ctx context.Context, rules []*github.RepositoryRule, ruleType string) (*time.Time, *github.RepositoryRule, error) {
	var oldestRule *github.RepositoryRule
	var oldestTime *time.Time
	for _, rule := range rules {
		if rule.Type == ruleType {
			ruleGood, enabledSince, err := ghc.checkRule(ctx, rule)
			if err != nil {
				return nil, nil, err
			}
			if ruleGood && (oldestTime == nil || enabledSince.Before(*oldestTime)) {
				oldestRule = rule
				oldestTime = &enabledSince
			}
		}
	}

	return oldestTime, oldestRule, nil
}

// Determines the source level using GitHub's built in controls only.
// This is necessarily only as good as GitHub's controls and existing APIs.
// This is a useful demonstration on how SLSA Level 2 can be achieved with ~minimal effort.
//
// Returns the determined source level (level 2 max) or error.
func (ghc GitHubConnection) DetermineSourceLevelControlOnly(ctx context.Context, commit string) (*GhControlStatus, error) {
	// We want to know when this commit was pushed to ensure the rules were active _then_.
	activity, err := ghc.commitActivity(ctx, commit)
	if err != nil {
		return nil, err
	}

	controlStatus := GhControlStatus{
		// Default to L1, but upgrade later if possible.
		ControlLevel:      slsa_types.SlsaSourceLevel1,
		ControlLevelSince: time.Time{},
		CommitPushTime:    activity.Timestamp,
		ActivityType:      activity.ActivityType,
		ActorLogin:        activity.Actor.Login}

	rules, _, err := ghc.Client.Repositories.GetRulesForBranch(ctx, ghc.Owner, ghc.Repo, ghc.Branch)

	if err != nil {
		return nil, err
	}

	var newestRuleEnabled *time.Time
	for _, ruleType := range []string{"deletion", "non_fast_forward"} {
		ruleTime, _, err := ghc.getRuleTime(ctx, rules, ruleType)
		if err != nil {
			return nil, err
		}
		if ruleTime == nil {
			// This rule isn't enabled, so we'll fallback to our default.
			return &controlStatus, nil
		}
		if newestRuleEnabled == nil || newestRuleEnabled.Before(*ruleTime) {
			newestRuleEnabled = ruleTime
		}
	}

	// Check that the commit was created after the newest rule was enabled...
	// to be sure folks aren't somehow sneaking something through...
	if activity.Timestamp.Before(*newestRuleEnabled) {
		return nil, fmt.Errorf("commit %s created before (%v) the rule was enabled (%v), that shouldn't happen", commit, activity.Timestamp, newestRuleEnabled)
	}

	// All the rules required for L2 are enabled.
	controlStatus.ControlLevel = slsa_types.SlsaSourceLevel2
	controlStatus.ControlLevelSince = *newestRuleEnabled

	return &controlStatus, nil
}
