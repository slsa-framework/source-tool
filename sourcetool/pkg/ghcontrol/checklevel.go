package ghcontrol

import (
	"context"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/google/go-github/v69/github"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
)

const (
	EnforcementActive = "active"
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

func (ghc *GitHubConnection) commitActivity(ctx context.Context, commit, targetRef string) (*activity, error) {
	// Unfortunately the gh_client doesn't have native support for this...'
	reqUrl := fmt.Sprintf("repos/%s/%s/activity", ghc.Owner(), ghc.Repo())
	req, err := ghc.Client().NewRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}

	var result []*activity
	_, err = ghc.Client().Do(ctx, req, &result)
	if err != nil {
		return nil, err
	}

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

	return nil, fmt.Errorf("could not find repo activity for %s on %s", commit, targetRef)
}

type RequiredCheck struct {
	// The name of the required status check as reported in the GitHub UI/API.
	Name string
	// How long that check has been required.
	Since time.Time
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
	Controls slsa.Controls
}

// Adds the control, but only if it existed when the commit was pushed.
func (cs *GhControlStatus) AddControl(newControls ...*slsa.Control) {
	for _, newControl := range newControls {
		if newControl != nil && cs.CommitPushTime.After(newControl.Since) {
			cs.Controls.AddControl(newControl)
		}
	}
}

func (ghc *GitHubConnection) ruleMeetsRequiresReview(rule *github.PullRequestBranchRule) bool {
	return rule.Parameters.RequiredApprovingReviewCount > 0 &&
		rule.Parameters.DismissStaleReviewsOnPush &&
		rule.Parameters.RequireCodeOwnerReview &&
		rule.Parameters.RequireLastPushApproval
}

// Computes the continuity control returning nil if it's not enabled.
func (ghc *GitHubConnection) computeContinuityControl(ctx context.Context, rules *github.BranchRules) (*slsa.Control, error) {
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
	if newestRule.UpdatedAt.Before(oldestNoFf.UpdatedAt.Time) {
		newestRule = oldestNoFf
	}

	return &slsa.Control{Name: slsa.ContinuityEnforced, Since: newestRule.UpdatedAt.Time}, nil
}

func enforcesTagHygiene(ruleset *github.RepositoryRuleset) bool {
	if ruleset.Rules != nil &&
		ruleset.Rules.Update != nil &&
		ruleset.Rules.Deletion != nil &&
		ruleset.Rules.NonFastForward != nil &&
		ruleset.Conditions != nil &&
		len(ruleset.Conditions.RefName.Exclude) == 0 &&
		slices.Contains(ruleset.Conditions.RefName.Include, "~ALL") {
		return true
	}
	return false
}

func (ghc *GitHubConnection) computeTagHygieneControl(ctx context.Context, allRulesets []*github.RepositoryRuleset) (*slsa.Control, error) {
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
		fullRuleset, _, err := ghc.Client().Repositories.GetRuleset(ctx, ghc.Owner(), ghc.Repo(), ruleset.GetID(), false)
		if err != nil {
			return nil, fmt.Errorf("could not get full ruleset for ruleset id %d: err: %w", ruleset.GetID(), err)
		}

		if !enforcesTagHygiene(fullRuleset) {
			continue
		}
		if validRuleset == nil || validRuleset.UpdatedAt.After(ruleset.UpdatedAt.Time) {
			validRuleset = ruleset
		}
	}

	if validRuleset == nil {
		return nil, nil
	}

	return &slsa.Control{Name: slsa.TagHygiene, Since: validRuleset.UpdatedAt.Time}, nil
}

// Computes the review control returning nil if it's not enabled.
func (ghc *GitHubConnection) computeReviewControl(ctx context.Context, rules []*github.PullRequestBranchRule) (*slsa.Control, error) {
	var oldestActive *github.RepositoryRuleset
	for _, rule := range rules {
		if ghc.ruleMeetsRequiresReview(rule) {
			ruleset, _, err := ghc.Client().Repositories.GetRuleset(ctx, ghc.Owner(), ghc.Repo(), rule.RulesetID, false)
			if err != nil {
				return nil, err
			}
			if ruleset.Enforcement == EnforcementActive {
				if oldestActive == nil || oldestActive.UpdatedAt.After(ruleset.UpdatedAt.Time) {
					oldestActive = ruleset
				}
			}
		}
	}

	if oldestActive != nil {
		return &slsa.Control{Name: slsa.ReviewEnforced, Since: oldestActive.UpdatedAt.Time}, nil
	}

	return nil, nil
}

func (ghc *GitHubConnection) computeRequiredChecks(ctx context.Context, ghCheckRules []*github.RequiredStatusChecksBranchRule) ([]*slsa.Control, error) {
	// Only return the checks we're happy about.
	// For now that's only stuff from the GitHub Actions app.
	requiredChecks := []*slsa.Control{}
	for _, ghCheckRule := range ghCheckRules {
		ruleset, _, err := ghc.Client().Repositories.GetRuleset(ctx, ghc.Owner(), ghc.Repo(), ghCheckRule.RulesetID, false)
		if err != nil {
			return nil, err
		}
		if ruleset.Enforcement != EnforcementActive {
			// Only look at rules being enforced.
			continue
		}

		for _, check := range ghCheckRule.Parameters.RequiredStatusChecks {
			if check.IntegrationID == nil || *check.IntegrationID != GitHubActionsIntegrationId {
				// Ignore untrusted integration id.
				continue
			}
			requiredChecks = append(requiredChecks, &slsa.Control{
				Name:  CheckNameToControlName(check.Context),
				Since: ruleset.UpdatedAt.Time,
			})
		}
	}
	return requiredChecks, nil
}

func (ghc *GitHubConnection) getOldestActiveRule(ctx context.Context, rules []*github.BranchRuleMetadata) (*github.RepositoryRuleset, error) {
	var oldestActive *github.RepositoryRuleset
	for _, rule := range rules {
		ruleset, _, err := ghc.Client().Repositories.GetRuleset(ctx, ghc.Owner(), ghc.Repo(), rule.RulesetID, false)
		if err != nil {
			return nil, err
		}
		if ruleset.Enforcement == EnforcementActive {
			if oldestActive == nil || oldestActive.UpdatedAt.After(ruleset.UpdatedAt.Time) {
				oldestActive = ruleset
			}
		}
	}
	return oldestActive, nil
}

// GetBranchControls returns a list of the controls enabled at present for a branch.
// This function does not take into account a commit date, it just returns those controls
// that are active when called.
func (ghc *GitHubConnection) GetBranchControls(ctx context.Context, ref string) (*slsa.Controls, error) {
	branch := GetBranchFromRef(ref)
	if branch == "" {
		return nil, fmt.Errorf("ref %s is not a branch", ref)
	}

	controls := &slsa.Controls{}

	// Do the branch specific stuff.
	branchRules, _, err := ghc.Client().Repositories.GetRulesForBranch(ctx, ghc.Owner(), ghc.Repo(), branch)
	if err != nil {
		return nil, err
	}

	// Compute the controls enforced.
	continuityControl, err := ghc.computeContinuityControl(ctx, branchRules)
	if err != nil {
		return nil, fmt.Errorf("could not populate ContinuityControl: %w", err)
	}
	controls.AddControl(continuityControl)

	reviewControl, err := ghc.computeReviewControl(ctx, branchRules.PullRequest)
	if err != nil {
		return nil, fmt.Errorf("could not populate ReviewControl: %w", err)
	}
	controls.AddControl(reviewControl)

	requiredCheckControls, err := ghc.computeRequiredChecks(ctx, branchRules.RequiredStatusChecks)
	if err != nil {
		return nil, fmt.Errorf("could not populate RequiredChecks: %w", err)
	}
	controls.AddControl(requiredCheckControls...)

	// Check the tag rules.
	allRulesets, _, err := ghc.Client().Repositories.GetAllRulesets(ctx, ghc.Owner(), ghc.Repo(), true)
	if err != nil {
		return nil, err
	}
	TagHygieneControl, err := ghc.computeTagHygieneControl(ctx, allRulesets)
	if err != nil {
		return nil, fmt.Errorf("could not populate TagHygieneControl: %w", err)
	}
	controls.AddControl(TagHygieneControl)

	return controls, nil
}

// GetBranchControlsAtCommit determines the controls that are in place for a branch
// at a specific commit using GitHub's APIs. This is necessarily only as good as
// GitHub's controls and existing APIs.
func (ghc *GitHubConnection) GetBranchControlsAtCommit(ctx context.Context, commit, ref string) (*GhControlStatus, error) {
	// We want to know when this commit was pushed to ensure the rules were active _then_.
	activity, err := ghc.commitActivity(ctx, commit, ref)
	if err != nil {
		return nil, err
	}

	controlStatus := GhControlStatus{
		CommitPushTime: activity.Timestamp,
		ActivityType:   activity.ActivityType,
		ActorLogin:     activity.Actor.Login,
		Controls:       slsa.Controls{},
	}

	activeControls, err := ghc.GetBranchControls(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("reading active controls: %w", err)
	}

	// Add the controls to the control status object. This will
	// discard any that were not active when the commit merged.
	for _, c := range *activeControls {
		controlStatus.AddControl(&c)
	}

	return &controlStatus, nil
}

func (ghc *GitHubConnection) GetTagControls(ctx context.Context, commit, ref string) (*GhControlStatus, error) {
	controlStatus := GhControlStatus{
		CommitPushTime: time.Now(),
		Controls:       slsa.Controls{},
	}

	allRulesets, _, err := ghc.Client().Repositories.GetAllRulesets(ctx, ghc.Owner(), ghc.Repo(), true)
	if err != nil {
		return nil, fmt.Errorf("getting repository rules from API: %w", err)
	}

	TagHygieneControl, err := ghc.computeTagHygieneControl(ctx, allRulesets)
	if err != nil {
		return nil, fmt.Errorf("could not populate TagHygieneControl: %w", err)
	}
	controlStatus.AddControl(TagHygieneControl)

	return &controlStatus, nil
}
