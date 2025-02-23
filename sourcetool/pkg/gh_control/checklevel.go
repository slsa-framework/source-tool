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

	return nil, fmt.Errorf("Could not find repo activity for commit %s", commit)
}

func maxTime(times []time.Time) time.Time {
	if len(times) == 0 {
		return time.Time{} // Return zero value if the slice is empty
	}

	max := times[0]
	for _, t := range times[1:] {
		if t.After(max) {
			max = t
		}
	}
	return max
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

// Determines the source level using GitHub's built in controls only.
// This is necessarily only as good as GitHub's controls and existing APIs.
// This is a useful demonstration on how SLSA Level 2 can be achieved with ~minimal effort.
//
// Returns the determined source level (level 2 max) or error.
func (ghc GitHubConnection) DetermineSourceLevelControlOnly(ctx context.Context, commit string) (*GhControlStatus, error) {
	rules, _, err := ghc.Client.Repositories.GetRulesForBranch(ctx, ghc.Owner, ghc.Repo, ghc.Branch)

	if err != nil {
		return nil, err
	}

	var deletionRule *github.RepositoryRule
	var nonFastFowardRule *github.RepositoryRule
	for _, rule := range rules {
		switch rule.Type {
		case "deletion":
			deletionRule = rule
		case "non_fast_forward":
			nonFastFowardRule = rule
		default:
			// ignore
		}
	}

	// We want to know when this commit was pushed to ensure the rules were active _then_.
	activity, err := ghc.commitActivity(ctx, commit)
	if err != nil {
		return nil, err
	}

	controlStatus := GhControlStatus{
		ControlLevel:      slsa_types.SlsaSourceLevel1,
		ControlLevelSince: time.Time{},
		CommitPushTime:    activity.Timestamp,
		ActivityType:      activity.ActivityType,
		ActorLogin:        activity.Actor.Login}

	if deletionRule == nil && nonFastFowardRule == nil {
		// For L2 we need deletion and non-fast-forward rules.
		return &controlStatus, nil
	}

	deletionGood, deletionSince, err := ghc.checkRule(ctx, deletionRule)
	if err != nil {
		return nil, err
	}
	nonFFGood, nonFFSince, err := ghc.checkRule(ctx, nonFastFowardRule)
	if err != nil {
		return nil, err
	}

	if deletionGood && nonFFGood {
		controlStatus.ControlLevel = slsa_types.SlsaSourceLevel2
		controlStatus.ControlLevelSince = maxTime([]time.Time{deletionSince, nonFFSince})
	}

	return &controlStatus, nil
}
