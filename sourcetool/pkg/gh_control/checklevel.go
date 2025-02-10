package gh_control

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa_types"

	"github.com/google/go-github/v68/github"
)

type activity struct {
	Id           int
	Before       string
	After        string
	Ref          string
	Timestamp    time.Time
	ActivityType string `json:"activity_type"`
}

// Checks to see if the rule was enabled and since what time.
func checkRule(ctx context.Context, gh_client *github.Client, owner string, repo string, rule *github.RepositoryRule) (bool, time.Time, error) {
	ruleset, _, err := gh_client.Repositories.GetRuleset(ctx, owner, repo, rule.RulesetID, false)
	if err != nil {
		return false, time.Time{}, err
	}

	// We need rules to be 'active' and to have been updated no later than minTime.
	if ruleset.Enforcement != "active" {
		return false, time.Time{}, nil
	}

	return true, ruleset.UpdatedAt.Time, nil
}

func commitPushTime(ctx context.Context, gh_client *github.Client, commit string, owner string, repo string, branch string) (time.Time, error) {
	// Unfortunately the gh_client doesn't have native support for this...'
	reqUrl := fmt.Sprintf("repos/%s/%s/activity", owner, repo)
	req, err := gh_client.NewRequest("GET", reqUrl, nil)
	if err != nil {
		return time.Time{}, err
	}

	var result []*activity
	_, err = gh_client.Do(ctx, req, &result)
	if err != nil {
		return time.Time{}, err
	}

	targetRef := fmt.Sprintf("refs/heads/%s", branch)
	monitoredTypes := []string{"push", "force_push", "pr_merge"}
	for _, activity := range result {
		if !slices.Contains(monitoredTypes, activity.ActivityType) {
			continue
		}
		if activity.After == commit && activity.Ref == targetRef {
			// Found it
			return activity.Timestamp, nil
		}
	}

	return time.Time{}, errors.New(fmt.Sprintf("Could not find repo activity for commit %s", commit))
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
	// The time the commit we're evaluting was pushed.
	CommitPushTime time.Time
}

// Determines the source level using GitHub's built in controls only.
// This is necessarily only as good as GitHub's controls and existing APIs.
// This is a useful demonstration on how SLSA Level 2 can be acheived with ~minimal effort.
//
// Returns the determined source level (level 2 max) or error.
func DetermineSourceLevelControlOnly(ctx context.Context, gh_client *github.Client, commit string, owner string, repo string, branch string) (*GhControlStatus, error) {
	rules, _, err := gh_client.Repositories.GetRulesForBranch(ctx, owner, repo, branch)

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
	pushTime, err := commitPushTime(ctx, gh_client, commit, owner, repo, branch)
	if err != nil {
		return nil, err
	}

	controlStatus := GhControlStatus{ControlLevel: slsa_types.SlsaSourceLevel1, ControlLevelSince: time.Time{}, CommitPushTime: pushTime}

	if deletionRule == nil && nonFastFowardRule == nil {
		// For L2 we need deletion and non-fast-forward rules.
		return &controlStatus, nil
	}

	deletionGood, deletionSince, err := checkRule(ctx, gh_client, owner, repo, deletionRule)
	if err != nil {
		return nil, err
	}
	nonFFGood, nonFFSince, err := checkRule(ctx, gh_client, owner, repo, nonFastFowardRule)
	if err != nil {
		return nil, err
	}

	if deletionGood && nonFFGood {
		controlStatus.ControlLevel = slsa_types.SlsaSourceLevel2
		controlStatus.ControlLevelSince = maxTime([]time.Time{deletionSince, nonFFSince})
	}

	return &controlStatus, nil
}
