package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	spb "github.com/in-toto/attestation/go/v1"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/gh_control"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa_types"

	"github.com/go-git/go-git/v5"
)

const (
	SourcePolicyUri       = "github.com/slsa-framework/slsa-source-poc"
	SourcePolicyRepoOwner = "slsa-framework"
	SourcePolicyRepo      = "slsa-source-poc"
)

// Used by orgs to require that specific 'checks' are run on protected
// branches and to associate those checks with a control name to include
// in provenance and VSAs.
// https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-status-checks-to-pass-before-merging
type OrgStatusCheckControl struct {
	// The property to record in the VSA if the conditions are met.
	// MUST start with `ORG_SOURCE_`.
	PropertyName slsa_types.ControlName `json:"property_name"`
	// These controls have their own start time to enable orgs to enable
	// new ones without violating continuity on other controls.
	Since time.Time
	// The name of the 'Status Check' as reported in the GitHub UI & API.
	CheckName string `json:"check_name"`
}

// When a branch requires multiple controls, they must all be enabled
// at or before 'Since'.
type ProtectedBranch struct {
	Name                  string
	Since                 time.Time
	TargetSlsaSourceLevel slsa_types.SlsaSourceLevel `json:"target_slsa_source_level"`
	RequireReview         bool                       `json:"require_review"`
	RequiredStatusChecks  []OrgStatusCheckControl    `json:"org_status_check_controls"`
}

// The controls required for protected tags.
type ProtectedTag struct {
	Since      time.Time
	TagHygiene bool `json:"tag_hygiene"`
}

type RepoPolicy struct {
	// TODO: I'm actually not sure we need this.  Consider removing?
	CanonicalRepo     string            `json:"canonical_repo"`
	ProtectedBranches []ProtectedBranch `json:"protected_branches"`
	ProtectedTag      *ProtectedTag     `json:"protected_tag"`
}

// Returns the policy for the branch or nil if the branch doesn't have one.
func (rp *RepoPolicy) getBranchPolicy(branch string) *ProtectedBranch {
	for _, pb := range rp.ProtectedBranches {
		if pb.Name == branch {
			return &pb
		}
	}
	return nil
}

func createDefaultBranchPolicy(branch string) *ProtectedBranch {
	return &ProtectedBranch{
		Name:                  branch,
		Since:                 time.Now(),
		TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel1,
		RequireReview:         false}
}

func getPolicyPath(gh_connection *gh_control.GitHubConnection) string {
	return fmt.Sprintf("policy/github.com/%s/%s/source-policy.json", gh_connection.Owner(), gh_connection.Repo())
}

func getPolicyRepoPath(pathToClone string, gh_connection *gh_control.GitHubConnection) string {
	return fmt.Sprintf("%s/%s", pathToClone, getPolicyPath(gh_connection))
}

// If we can't find a policy we return a nil policy.
func getRemotePolicy(ctx context.Context, gh_connection *gh_control.GitHubConnection) (*RepoPolicy, string, error) {
	path := getPolicyPath(gh_connection)

	policyContents, _, resp, err := gh_connection.Client().Repositories.GetContents(ctx, SourcePolicyRepoOwner, SourcePolicyRepo, path, nil)
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		return nil, "", nil
	}

	if err != nil {
		return nil, "", err
	}

	content, err := policyContents.GetContent()
	if err != nil {
		return nil, "", err
	}
	var p RepoPolicy
	err = json.Unmarshal([]byte(content), &p)
	if err != nil {
		return nil, "", err
	}
	return &p, *policyContents.HTMLURL, nil
}

func getLocalPolicy(path string) (*RepoPolicy, string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	var p RepoPolicy
	err = json.Unmarshal([]byte(contents), &p)
	if err != nil {
		return nil, "", err
	}
	return &p, path, nil
}

func (pe PolicyEvaluator) getPolicy(ctx context.Context, gh_connection *gh_control.GitHubConnection) (policy *RepoPolicy, path string, err error) {
	if pe.UseLocalPolicy == "" {
		policy, path, err = getRemotePolicy(ctx, gh_connection)
	} else {
		policy, path, err = getLocalPolicy(pe.UseLocalPolicy)
	}

	return policy, path, err
}

// Check to see if the local directory is a clean clone or not
// TODO: Check if the policy exists remotely.
func checkLocalDir(ctx context.Context, gh_connection *gh_control.GitHubConnection, pathToClone string) error {
	repo, err := git.PlainOpen(pathToClone)
	if err != nil {
		return err
	}
	worktree, err := repo.Worktree()
	if err != nil {
		return err
	}
	status, err := worktree.Status()
	if err != nil {
		return err
	}
	if !status.IsClean() {
		return fmt.Errorf("you must run this command in a clean clone of %s", SourcePolicyUri)
	}

	path := getPolicyRepoPath(pathToClone, gh_connection)
	// Is there already a local policy?
	_, err = os.Stat(path)
	if err != nil {
		// We _want_ ErrNotExist.
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else {
		return fmt.Errorf("policy already exists at %s", path)
	}

	// Is there a remote policy?
	rp, _, _ := getRemotePolicy(ctx, gh_connection)
	if rp != nil {
		return fmt.Errorf("policy already exists remotely for %s", getPolicyPath(gh_connection))
	}
	return nil
}

func CreateLocalPolicy(ctx context.Context, gh_connection *gh_control.GitHubConnection, pathToClone string) (string, error) {
	// First make sure they're in the right state...
	err := checkLocalDir(ctx, gh_connection, pathToClone)
	if err != nil {
		return "", err
	}

	path := getPolicyRepoPath(pathToClone, gh_connection)

	// What's their latest commit (needed for checking control status)
	branch := gh_control.GetBranchFromRef(gh_connection.GetFullRef())
	if branch == "" {
		return "", fmt.Errorf("cannot create local policy, ref %s isn't a branch", gh_connection.GetFullRef())
	}
	latestCommit, err := gh_connection.GetLatestCommit(ctx, branch)
	if err != nil {
		return "", fmt.Errorf("could not get latest commit: %w", err)
	}

	pa := attest.NewProvenanceAttestor(gh_connection, attest.GetDefaultVerifier())
	_, provPred, err := pa.GetProvenance(ctx, latestCommit, gh_connection.GetFullRef())
	if err != nil {
		return "", fmt.Errorf("could not get provenance for latest commit: %w", err)
	}

	// Default to SLSA1 since unset date
	var eligibleSince = &time.Time{}
	var eligibleLevel = slsa_types.SlsaSourceLevel1

	// Unless there is previous provenance metadata, then we can compute
	// a higher level
	if provPred != nil {
		eligibleLevel = computeEligibleSlsaLevel(provPred.Controls)
		eligibleSince, err = computeEligibleSince(provPred.Controls, eligibleLevel)
		if err != nil {
			return "", fmt.Errorf("could not compute eligible since: %w", err)
		}
	}

	p := RepoPolicy{
		CanonicalRepo: "TODO fill this in",
		ProtectedBranches: []ProtectedBranch{
			{
				Name:                  branch,
				Since:                 *eligibleSince,
				TargetSlsaSourceLevel: eligibleLevel,
				// TODO support filling in other controls too.
			},
		},
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}

	// Create the entire path if it doesn't already exist
	if err := os.MkdirAll(filepath.Dir(path), 0770); err != nil {
		return "", err
	}

	err = os.WriteFile(path, data, 0644)
	if err != nil {
		return "", err
	}
	return path, nil
}

func computeEligibleForLevel(controls slsa_types.Controls, level slsa_types.SlsaSourceLevel) bool {
	requiredControls := slsa_types.GetRequiredControlsForLevel(level)
	if controls.AreControlsAvailable(requiredControls) {
		return true
	}
	return false
}

// Computes the eligible SLSA level, and when they started being eligible for it,
// if only they had a policy.  Also returns a rationale for why it's eligible for this level.
func computeEligibleSlsaLevel(controls slsa_types.Controls) slsa_types.SlsaSourceLevel {
	// Go from highest to lowest.
	for _, level := range []slsa_types.SlsaSourceLevel{
		slsa_types.SlsaSourceLevel4, slsa_types.SlsaSourceLevel3, slsa_types.SlsaSourceLevel2} {
		eligible := computeEligibleForLevel(controls, level)
		if eligible {
			return level
		}
	}

	// If nothing else, level 1.
	// The time here is tricky, it's really probably since whenever they created the repo
	// But also, they don't qualify for much so maybe it doesn't matter.
	// Just return now for now.
	return slsa_types.SlsaSourceLevel1
}

// Computes the time since these controls have been eligible for the level, nil if not eligible.
func computeEligibleSince(controls slsa_types.Controls, level slsa_types.SlsaSourceLevel) (*time.Time, error) {

	requiredControls := slsa_types.GetRequiredControlsForLevel(level)
	var newestTime time.Time
	for _, rc := range requiredControls {
		ac := controls.GetControl(rc)
		if ac == nil {
			return nil, nil
		}
		if newestTime.Equal(time.Time{}) {
			newestTime = ac.Since
		} else {
			newestTime = slsa_types.LaterTime(newestTime, ac.Since)
		}
	}
	return &newestTime, nil
}

// Every function that determines properties to include in the result & VSA implements this interface.
type computePolicyResult func(*ProtectedBranch, *ProtectedTag, slsa_types.Controls) ([]slsa_types.ControlName, error)

func computeSlsaLevel(branchPolicy *ProtectedBranch, _ *ProtectedTag, controls slsa_types.Controls) ([]slsa_types.ControlName, error) {
	eligibleLevel := computeEligibleSlsaLevel(controls)

	if !slsa_types.IsLevelHigherOrEqualTo(eligibleLevel, branchPolicy.TargetSlsaSourceLevel) {
		return []slsa_types.ControlName{}, fmt.Errorf(
			"policy sets target level %s which requires %v, but branch is only eligible for %s because it only has %v",
			branchPolicy.TargetSlsaSourceLevel,
			slsa_types.GetRequiredControlsForLevel(branchPolicy.TargetSlsaSourceLevel),
			eligibleLevel, controls.Names())
	}

	// Check to see when this branch became eligible for the current target level.
	eligibleSince, err := computeEligibleSince(controls, branchPolicy.TargetSlsaSourceLevel)
	if err != nil {
		return []slsa_types.ControlName{}, fmt.Errorf("could not compute eligible since: %w", err)
	}
	if eligibleSince == nil {
		return []slsa_types.ControlName{}, fmt.Errorf("policy sets target level %s, but cannot compute when controls made it eligible for that level", branchPolicy.TargetSlsaSourceLevel)
	}

	if branchPolicy.Since.Before(*eligibleSince) {
		return []slsa_types.ControlName{}, fmt.Errorf("policy sets target level %s since %v, but it has only been eligible for that level since %v", branchPolicy.TargetSlsaSourceLevel, branchPolicy.Since, eligibleSince)
	}

	return []slsa_types.ControlName{slsa_types.ControlName(branchPolicy.TargetSlsaSourceLevel)}, nil
}

func computeReviewEnforced(branchPolicy *ProtectedBranch, _ *ProtectedTag, controls slsa_types.Controls) ([]slsa_types.ControlName, error) {
	if !branchPolicy.RequireReview {
		return []slsa_types.ControlName{}, nil
	}

	reviewControl := controls.GetControl(slsa_types.ReviewEnforced)
	if reviewControl == nil {
		return []slsa_types.ControlName{}, fmt.Errorf("policy requires review, but that control is not enabled")
	}

	if branchPolicy.Since.Before(reviewControl.Since) {
		return []slsa_types.ControlName{}, fmt.Errorf("policy requires review since %v, but that control has only been enabled since %v", branchPolicy.Since, reviewControl.Since)
	}

	return []slsa_types.ControlName{slsa_types.ReviewEnforced}, nil
}

func computeTagHygiene(_ *ProtectedBranch, tagPolicy *ProtectedTag, controls slsa_types.Controls) ([]slsa_types.ControlName, error) {
	if tagPolicy == nil {
		// There is no tag policy, so the control isn't met, but it's not an error.
		return []slsa_types.ControlName{}, nil
	}

	if !tagPolicy.TagHygiene {
		return []slsa_types.ControlName{}, nil
	}

	tagHygiene := controls.GetControl(slsa_types.TagHygiene)
	if tagHygiene == nil {
		return []slsa_types.ControlName{}, fmt.Errorf("policy requires tag hygiene, but that control is not enabled")
	}

	if tagPolicy.Since.Before(tagHygiene.Since) {
		return []slsa_types.ControlName{}, fmt.Errorf("policy requires tag hygiene since %v, but that control has only been enabled since %v", tagPolicy.Since, tagHygiene.Since)
	}

	return []slsa_types.ControlName{slsa_types.TagHygiene}, nil
}

func computeOrgControls(branchPolicy *ProtectedBranch, _ *ProtectedTag, controls slsa_types.Controls) ([]slsa_types.ControlName, error) {
	controlNames := []slsa_types.ControlName{}
	for _, rc := range branchPolicy.RequiredStatusChecks {
		if !strings.HasPrefix(string(rc.PropertyName), slsa_types.AllowedOrgPropPrefix) {
			return []slsa_types.ControlName{}, fmt.Errorf("policy specifies an invalid property name %v, custom property names MUST start with %v", rc.PropertyName, slsa_types.AllowedOrgPropPrefix)
		}

		control := controls.GetControl(gh_control.CheckNameToControlName(rc.CheckName))
		if control != nil {
			if rc.Since.Before(control.Since) {
				return []slsa_types.ControlName{}, fmt.Errorf("policy requires check '%v' since %v, but that control has only been enabled since %v", rc.CheckName, rc.Since, control.Since)
			}
			controlNames = append(controlNames, rc.PropertyName)
		} else {
			return []slsa_types.ControlName{}, fmt.Errorf("policy requires check '%v', but that control is not enabled", rc.CheckName)
		}
	}
	return controlNames, nil
}

// Returns a list of controls to include in the vsa's 'verifiedLevels' field when creating a VSA for a branch.
func evaluateBranchControls(branchPolicy *ProtectedBranch, tagPolicy *ProtectedTag, controls slsa_types.Controls) (slsa_types.SourceVerifiedLevels, error) {

	policyComputers := []computePolicyResult{computeSlsaLevel, computeReviewEnforced, computeTagHygiene, computeOrgControls}

	verifiedLevels := slsa_types.SourceVerifiedLevels{}

	for _, pc := range policyComputers {
		computedControls, err := pc(branchPolicy, tagPolicy, controls)
		if err != nil {
			return slsa_types.SourceVerifiedLevels{}, fmt.Errorf("error computing branch controls: %w", err)
		}
		verifiedLevels = append(verifiedLevels, computedControls...)
	}

	return verifiedLevels, nil
}

// Returns a list of controls to include in the vsa's 'verifiedLevels' field when creating a VSA for a tag.
// Users provide a list of verifiedLevels that came from VSAs issued previously for the commit pointed to by this
// tag.
func evaluateTagProv(tagPolicy *ProtectedTag, tagProvPred *attest.TagProvenancePred) (slsa_types.SourceVerifiedLevels, error) {
	// As long as all the controls for tag protection are currently in force then we'll
	// include the verifiedLevels.

	computedControls, err := computeTagHygiene(nil, tagPolicy, tagProvPred.Controls)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, fmt.Errorf("error computing tag immutability enforced: %w", err)
	}
	if len(computedControls) == 0 || tagPolicy == nil {
		// If tag hygiene isn't enabled then we just return level 1.
		return slsa_types.SourceVerifiedLevels{slsa_types.ControlName(slsa_types.SlsaSourceLevel1)}, nil
	}

	// We have multiple summaries with their own verifiedLevels.
	// There are probably duplicates. We need to return a single list.
	// We also need to remove duplicate SLSA Source Levels since we can
	// only include one. We'll include the highest.
	// There's probably a faster way to do this, or a library that could
	// be used, I don't think it would be very readable.
	verifiedLevels := slsa_types.SourceVerifiedLevels{}
	highestSlsaLevel := slsa_types.SlsaSourceLevel1
	for _, summary := range tagProvPred.VsaSummaries {
		for _, level := range summary.VerifiedLevels {
			verifiedLevels = append(verifiedLevels, level)
			if slsa_types.IsSlsaSourceLevel(level) &&
				slsa_types.IsLevelHigherOrEqualTo(slsa_types.SlsaSourceLevel(level), highestSlsaLevel) {
				highestSlsaLevel = slsa_types.SlsaSourceLevel(level)
			}
		}
	}
	// Sort (to keep order deterministic) and compact to remove dup
	slices.Sort(verifiedLevels)
	verifiedLevels = slices.Compact(verifiedLevels)

	// Now delete anything that is a SLSA source level but isn't the highest one.
	verifiedLevels = slices.DeleteFunc(verifiedLevels, func(level slsa_types.ControlName) bool {
		return slsa_types.IsSlsaSourceLevel(level) && level != slsa_types.ControlName(highestSlsaLevel)
	})

	return verifiedLevels, nil
}

type PolicyEvaluator struct {
	// UNSAFE!
	// Instead of grabbing the policy from the canonical repo, use the policy at this path instead.
	UseLocalPolicy string
}

func NewPolicyEvaluator() *PolicyEvaluator {
	return &PolicyEvaluator{}
}

// Evaluates the control against the policy and returns the resulting source level and policy path.
func (pe PolicyEvaluator) EvaluateControl(ctx context.Context, gh_connection *gh_control.GitHubConnection, controlStatus *gh_control.GhControlStatus) (slsa_types.SourceVerifiedLevels, string, error) {
	// We want to check to ensure the repo hasn't enabled/disabled the rules since
	// setting the 'since' field in their policy.
	rp, policyPath, err := pe.getPolicy(ctx, gh_connection)
	if err != nil || rp == nil {
		return slsa_types.SourceVerifiedLevels{}, "", err
	}

	branch := gh_control.GetBranchFromRef(gh_connection.GetFullRef())
	branchPolicy := rp.getBranchPolicy(branch)
	if branchPolicy == nil {
		branchPolicy = createDefaultBranchPolicy(branch)
		policyPath = "DEFAULT"
	}

	if controlStatus.CommitPushTime.Before(branchPolicy.Since) {
		// This commit was pushed before they had an explicit policy.
		return slsa_types.SourceVerifiedLevels{slsa_types.ControlName(slsa_types.SlsaSourceLevel1)}, policyPath, nil
	}

	verifiedLevels, err := evaluateBranchControls(branchPolicy, rp.ProtectedTag, controlStatus.Controls)
	if err != nil {
		return verifiedLevels, policyPath, fmt.Errorf("error evaluating policy %s: %w", policyPath, err)
	}
	return verifiedLevels, policyPath, nil
}

// Evaluates the provenance against the policy and returns the resulting source level and policy path
func (pe PolicyEvaluator) EvaluateSourceProv(ctx context.Context, gh_connection *gh_control.GitHubConnection, prov *spb.Statement) (slsa_types.SourceVerifiedLevels, string, error) {
	rp, policyPath, err := pe.getPolicy(ctx, gh_connection)
	if err != nil || rp == nil {
		return slsa_types.SourceVerifiedLevels{}, "", err
	}

	provPred, err := attest.GetSourceProvPred(prov)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, "", err
	}

	branch := gh_control.GetBranchFromRef(gh_connection.GetFullRef())
	branchPolicy := rp.getBranchPolicy(branch)
	if branchPolicy == nil {
		branchPolicy = createDefaultBranchPolicy(branch)
		policyPath = "DEFAULT"
	}

	verifiedLevels, err := evaluateBranchControls(branchPolicy, rp.ProtectedTag, provPred.Controls)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, policyPath, fmt.Errorf("error evaluating policy %s: %w", policyPath, err)
	}

	// Looks good!
	return verifiedLevels, policyPath, nil
}

// Evaluates the provenance against the policy and returns the resulting source level and policy path
func (pe PolicyEvaluator) EvaluateTagProv(ctx context.Context, gh_connection *gh_control.GitHubConnection, prov *spb.Statement) (slsa_types.SourceVerifiedLevels, string, error) {
	rp, policyPath, err := pe.getPolicy(ctx, gh_connection)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, "", err
	}

	provPred, err := attest.GetTagProvPred(prov)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, "", err
	}

	outputVerifiedLevels, err := evaluateTagProv(rp.ProtectedTag, provPred)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, policyPath, fmt.Errorf("error evaluating policy %s: %w", policyPath, err)
	}

	// Looks good!
	return outputVerifiedLevels, policyPath, nil
}
