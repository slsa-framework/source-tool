// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

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

	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/google/go-github/v69/github" // Use v69
	spb "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slsa-framework/slsa-source-poc/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/pkg/auth"
	"github.com/slsa-framework/slsa-source-poc/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/pkg/provenance"
	"github.com/slsa-framework/slsa-source-poc/pkg/slsa"
	"github.com/slsa-framework/slsa-source-poc/pkg/sourcetool/backends/attestation/notes"
	"github.com/slsa-framework/slsa-source-poc/pkg/sourcetool/models"
)

const (
	SourcePolicyUri       = "github.com/slsa-framework/source-policies"
	SourcePolicyRepoOwner = "slsa-framework"
	SourcePolicyRepo      = "source-policies"
)

// Returns the policy for the branch or nil if the branch doesn't have one.
func (rp *RepoPolicy) getBranchPolicy(branch string) *ProtectedBranch {
	for _, pb := range rp.GetProtectedBranches() {
		if pb.GetName() == branch {
			return pb
		}
	}
	return nil
}

func createDefaultBranchPolicy(branch *models.Branch) *ProtectedBranch {
	return &ProtectedBranch{
		Name:                  branch.Name,
		Since:                 timestamppb.Now(),
		TargetSlsaSourceLevel: string(slsa.SlsaSourceLevel1),
		RequireReview:         false,
	}
}

func getPolicyPath(repo *models.Repository) string {
	ownerName, repoName, err := repo.PathAsGitHubOwnerName()
	if err != nil {
		return ""
	}
	return fmt.Sprintf("policy/github.com/%s/%s/source-policy.json", ownerName, repoName)
}

func getPolicyRepoPath(pathToClone string, repo *models.Repository) string {
	return fmt.Sprintf("%s/%s", pathToClone, getPolicyPath(repo))
}

func (pe *PolicyEvaluator) getGitHubClient() (*github.Client, error) {
	if pe.client != nil {
		return pe.client, nil
	}
	if pe.authenticator == nil {
		return nil, errors.New("unable to get github client, no authenticator set")
	}
	return pe.authenticator.GetGitHubClient()
}

// getRemotePolicy fetches a policy using the GitHub API
// If we can't find a policy we return a nil policy.
func (pe *PolicyEvaluator) getRemotePolicy(ctx context.Context, repo *models.Repository) (*RepoPolicy, string, error) {
	path := getPolicyPath(repo)
	client, err := pe.getGitHubClient()
	if err != nil {
		return nil, "", err
	}

	policyContents, _, resp, err := client.Repositories.GetContents(ctx, SourcePolicyRepoOwner, SourcePolicyRepo, path, nil)
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		return nil, "", nil
	}

	if err != nil {
		return nil, "", fmt.Errorf("fetching policy code: %w", err)
	}

	content, err := policyContents.GetContent()
	if err != nil {
		return nil, "", err
	}

	p := &RepoPolicy{}
	err = protojson.UnmarshalOptions{
		DiscardUnknown: false,
	}.Unmarshal([]byte(content), p)
	if err != nil {
		return nil, "", fmt.Errorf("unmarshaling policy code: %w", err)
	}
	return p, *policyContents.HTMLURL, nil
}

func getLocalPolicy(path string) (*RepoPolicy, string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	var p RepoPolicy
	err = protojson.Unmarshal(contents, &p)
	if err != nil {
		return nil, "", fmt.Errorf("unmarshaling json: %w", err)
	}
	return &p, path, nil
}

// GetPolicy fetches the policy for a repository from the SLSA source repo.
// For debugging purposes, if UseLocalPolicy is defined, then the policy will
// be read from a local file.
func (pe *PolicyEvaluator) GetPolicy(ctx context.Context, repo *models.Repository) (policy *RepoPolicy, path string, err error) {
	if pe.UseLocalPolicy == "" {
		policy, path, err = pe.getRemotePolicy(ctx, repo)
	} else {
		policy, path, err = getLocalPolicy(pe.UseLocalPolicy)
	}

	return policy, path, err
}

// Check to see if the local directory is a clean clone or not
func (pe *PolicyEvaluator) checkLocalDir(ctx context.Context, repo *models.Repository, pathToClone string) error {
	gitRepo, err := git.PlainOpen(pathToClone)
	if err != nil {
		return err
	}
	worktree, err := gitRepo.Worktree()
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

	path := getPolicyRepoPath(pathToClone, repo)
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
	rp, _, err := pe.getRemotePolicy(ctx, repo)
	if err != nil {
		return fmt.Errorf("checking remote policy: %w", err)
	}
	if rp != nil {
		return fmt.Errorf("policy already exists remotely for %s", getPolicyPath(repo))
	}
	return nil
}

func readLastCommit(branch *models.Branch, repoPath string) (*models.Commit, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("opening local clone: %w", err)
	}

	if branch != nil {
		worktree, err := repo.Worktree()
		if err != nil {
			return nil, fmt.Errorf("failed to get worktree: %w", err)
		}

		// Checkout the specified branch
		if err := worktree.Checkout(&git.CheckoutOptions{
			Branch: plumbing.NewBranchReferenceName(branch.Name),
		}); err != nil {
			return nil, fmt.Errorf("checking branch %s: %w", branch.Name, err)
		}
	}

	ref, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("reading HEAD: %w", err)
	}

	// Get the commit object from the reference
	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return nil, fmt.Errorf("failed to get commit object: %w", err)
	}

	return &models.Commit{
		SHA:     ref.Hash().String(),
		Author:  commit.Author.Email,
		Time:    &time.Time{},
		Message: commit.Message,
	}, nil
}

func (pe *PolicyEvaluator) CreateLocalPolicy(ctx context.Context, repo *models.Repository, branch *models.Branch, pathToClone string) (string, error) {
	if pe.reader == nil {
		return "", fmt.Errorf("no attestation reader defined")
	}

	// First make sure they're in the right state...
	if err := pe.checkLocalDir(ctx, repo, pathToClone); err != nil {
		return "", err
	}

	repoOrg, repoName, err := repo.PathAsGitHubOwnerName()
	if err != nil {
		return "", err
	}

	path := getPolicyRepoPath(pathToClone, repo)

	// What's their latest commit (needed for checking control status)
	if branch == nil {
		return "", fmt.Errorf("cannot create local policy, branch no defined")
	}

	latestCommit, err := readLastCommit(branch, pathToClone)
	if err != nil {
		return "", fmt.Errorf("could not get latest commit: %w", err)
	}

	_, provPred, err := pe.reader.GetCommitProvenance(ctx, branch, latestCommit)
	if err != nil {
		return "", fmt.Errorf("could not get provenance for latest commit: %w", err)
	}

	// Default to SLSA1 since unset date
	eligibleSince := &time.Time{}
	eligibleLevel := slsa.SlsaSourceLevel1

	// Unless there is previous provenance metadata, then we can compute
	// a higher level
	if provPred != nil {
		eligibleLevel = ComputeEligibleSlsaLevel(provPred.GetControls())
		eligibleSince, err = ComputeEligibleSince(provPred.GetControls(), eligibleLevel)
		if err != nil {
			return "", fmt.Errorf("could not compute eligible since: %w", err)
		}
	}

	p := RepoPolicy{
		CanonicalRepo: fmt.Sprintf("https://github.com/%s/%s", repoOrg, repoName),
		ProtectedBranches: []*ProtectedBranch{
			{
				Name:                  branch.Name,
				Since:                 timestamppb.New(*eligibleSince),
				TargetSlsaSourceLevel: string(eligibleLevel),
				// TODO support filling in other controls too.
			},
		},
	}
	data, err := json.MarshalIndent(&p, "", "  ")
	if err != nil {
		return "", err
	}

	// Create the entire path if it doesn't already exist
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", err
	}

	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec
		return "", fmt.Errorf("writing policy file: %w", err)
	}
	return path, nil
}

func computeEligibleForLevel(controls slsa.Controls, level slsa.SlsaSourceLevel) bool {
	requiredControls := slsa.GetRequiredControlsForLevel(level)
	return controls.AreControlsAvailable(requiredControls)
}

// Computes the eligible SLSA level, and when they started being eligible for it,
// if only they had a policy.  Also returns a rationale for why it's eligible for this level.
func ComputeEligibleSlsaLevel(controls slsa.Controls) slsa.SlsaSourceLevel {
	// Go from highest to lowest.
	for _, level := range []slsa.SlsaSourceLevel{
		slsa.SlsaSourceLevel4, slsa.SlsaSourceLevel3, slsa.SlsaSourceLevel2,
	} {
		eligible := computeEligibleForLevel(controls, level)
		if eligible {
			return level
		}
	}

	// If nothing else, level 1.
	// The time here is tricky, it's really probably since whenever they created the repo
	// But also, they don't qualify for much so maybe it doesn't matter.
	// Just return now for now.
	return slsa.SlsaSourceLevel1
}

func laterTime(time1, time2 time.Time) time.Time {
	if time1.After(time2) {
		return time1
	}
	return time2
}

// Computes the time since these controls have been eligible for the level, nil if not eligible.
func ComputeEligibleSince(controls slsa.Controls, level slsa.SlsaSourceLevel) (*time.Time, error) {
	requiredControls := slsa.GetRequiredControlsForLevel(level)
	var newestTime time.Time
	for _, rc := range requiredControls {
		ac := controls.GetControl(rc)
		if ac == nil {
			return nil, nil
		}
		if newestTime.Equal(time.Time{}) {
			newestTime = ac.GetSince().AsTime()
		} else {
			newestTime = laterTime(newestTime, ac.GetSince().AsTime())
		}
	}
	return &newestTime, nil
}

// Every function that determines properties to include in the result & VSA implements this interface.
type computePolicyResult func(*ProtectedBranch, *ProtectedTag, slsa.Controls) ([]slsa.ControlName, error)

func computeSlsaLevel(branchPolicy *ProtectedBranch, _ *ProtectedTag, controls slsa.Controls) ([]slsa.ControlName, error) {
	eligibleLevel := ComputeEligibleSlsaLevel(controls)

	if !slsa.IsLevelHigherOrEqualTo(eligibleLevel, slsa.SlsaSourceLevel(branchPolicy.GetTargetSlsaSourceLevel())) {
		return []slsa.ControlName{}, fmt.Errorf(
			"policy sets target level %s which requires %v, but branch is only eligible for %s because it only has %v",
			branchPolicy.GetTargetSlsaSourceLevel(),
			slsa.GetRequiredControlsForLevel(slsa.SlsaSourceLevel(branchPolicy.GetTargetSlsaSourceLevel())),
			eligibleLevel, controls.Names())
	}

	// Check to see when this branch became eligible for the current target level.
	eligibleSince, err := ComputeEligibleSince(controls, slsa.SlsaSourceLevel(branchPolicy.GetTargetSlsaSourceLevel()))
	if err != nil {
		return []slsa.ControlName{}, fmt.Errorf("could not compute eligible since: %w", err)
	}
	if eligibleSince == nil {
		return []slsa.ControlName{}, fmt.Errorf("policy sets target level %s, but cannot compute when controls made it eligible for that level", branchPolicy.GetTargetSlsaSourceLevel())
	}

	if branchPolicy.GetSince().AsTime().Before(*eligibleSince) {
		return []slsa.ControlName{}, fmt.Errorf("policy sets target level %s since %v, but it has only been eligible for that level since %v", branchPolicy.GetTargetSlsaSourceLevel(), branchPolicy.GetSince().AsTime(), eligibleSince)
	}

	return []slsa.ControlName{slsa.ControlName(branchPolicy.GetTargetSlsaSourceLevel())}, nil
}

func computeReviewEnforced(branchPolicy *ProtectedBranch, _ *ProtectedTag, controls slsa.Controls) ([]slsa.ControlName, error) {
	if !branchPolicy.GetRequireReview() {
		return []slsa.ControlName{}, nil
	}

	reviewControl := controls.GetControl(slsa.ReviewEnforced)
	if reviewControl == nil {
		return []slsa.ControlName{}, fmt.Errorf("policy requires review, but that control is not enabled")
	}

	if branchPolicy.GetSince().AsTime().Before(reviewControl.GetSince().AsTime()) {
		return []slsa.ControlName{}, fmt.Errorf("policy requires review since %v, but that control has only been enabled since %v", branchPolicy.GetSince(), reviewControl.GetSince())
	}

	return []slsa.ControlName{slsa.ReviewEnforced}, nil
}

func computeTagHygiene(_ *ProtectedBranch, tagPolicy *ProtectedTag, controls slsa.Controls) ([]slsa.ControlName, error) {
	if tagPolicy == nil {
		// There is no tag policy, so the control isn't met, but it's not an error.
		return []slsa.ControlName{}, nil
	}

	if !tagPolicy.GetTagHygiene() {
		return []slsa.ControlName{}, nil
	}

	tagHygiene := controls.GetControl(slsa.TagHygiene)
	if tagHygiene == nil {
		return []slsa.ControlName{}, fmt.Errorf("policy requires tag hygiene, but that control is not enabled")
	}

	if tagPolicy.GetSince().AsTime().Before(tagHygiene.GetSince().AsTime()) {
		return []slsa.ControlName{}, fmt.Errorf("policy requires tag hygiene since %v, but that control has only been enabled since %v", tagPolicy.GetSince(), tagHygiene.GetSince())
	}

	return []slsa.ControlName{slsa.TagHygiene}, nil
}

func computeOrgControls(branchPolicy *ProtectedBranch, _ *ProtectedTag, controls slsa.Controls) ([]slsa.ControlName, error) {
	controlNames := []slsa.ControlName{}
	for _, rc := range branchPolicy.GetOrgStatusCheckControls() {
		if !strings.HasPrefix(rc.GetPropertyName(), slsa.AllowedOrgPropPrefix) {
			return []slsa.ControlName{}, fmt.Errorf("policy specifies an invalid property name %v, custom property names MUST start with %v", rc.GetPropertyName(), slsa.AllowedOrgPropPrefix)
		}

		control := controls.GetControl(ghcontrol.CheckNameToControlName(rc.GetCheckName()))
		if control != nil {
			if rc.GetSince().AsTime().Before(control.GetSince().AsTime()) {
				return []slsa.ControlName{}, fmt.Errorf("policy requires check '%v' since %v, but that control has only been enabled since %v", rc.GetCheckName(), rc.GetSince(), control.GetSince())
			}
			controlNames = append(controlNames, slsa.ControlName(rc.GetPropertyName()))
		} else {
			return []slsa.ControlName{}, fmt.Errorf("policy requires check '%v', but that control is not enabled", rc.GetCheckName())
		}
	}
	return controlNames, nil
}

// Returns a list of controls to include in the vsa's 'verifiedLevels' field when creating a VSA for a branch.
func evaluateBranchControls(branchPolicy *ProtectedBranch, tagPolicy *ProtectedTag, controls slsa.Controls) (slsa.SourceVerifiedLevels, error) {
	policyComputers := []computePolicyResult{computeSlsaLevel, computeReviewEnforced, computeTagHygiene, computeOrgControls}

	verifiedLevels := slsa.SourceVerifiedLevels{}

	for _, pc := range policyComputers {
		computedControls, err := pc(branchPolicy, tagPolicy, controls)
		if err != nil {
			return slsa.SourceVerifiedLevels{}, fmt.Errorf("error computing branch controls: %w", err)
		}
		verifiedLevels = append(verifiedLevels, computedControls...)
	}

	return verifiedLevels, nil
}

// Returns a list of controls to include in the vsa's 'verifiedLevels' field when creating a VSA for a tag.
// Users provide a list of verifiedLevels that came from VSAs issued previously for the commit pointed to by this
// tag.
func evaluateTagProv(tagPolicy *ProtectedTag, tagProvPred *provenance.TagProvenancePred) (slsa.SourceVerifiedLevels, error) {
	// As long as all the controls for tag protection are currently in force then we'll
	// include the verifiedLevels.

	computedControls, err := computeTagHygiene(nil, tagPolicy, tagProvPred.GetControls())
	if err != nil {
		return slsa.SourceVerifiedLevels{}, fmt.Errorf("error computing tag immutability enforced: %w", err)
	}
	if len(computedControls) == 0 || tagPolicy == nil {
		// If tag hygiene isn't enabled then we just return level 1.
		return slsa.SourceVerifiedLevels{slsa.ControlName(slsa.SlsaSourceLevel1)}, nil
	}

	// We have multiple summaries with their own verifiedLevels.
	// There are probably duplicates. We need to return a single list.
	// We also need to remove duplicate SLSA Source Levels since we can
	// only include one. We'll include the highest.
	// There's probably a faster way to do this, or a library that could
	// be used, I don't think it would be very readable.
	verifiedLevels := slsa.SourceVerifiedLevels{}
	highestSlsaLevel := slsa.SlsaSourceLevel1
	for _, summary := range tagProvPred.GetVsaSummaries() {
		for _, level := range summary.GetVerifiedLevels() {
			verifiedLevels = append(verifiedLevels, slsa.ControlName(level))
			if slsa.IsSlsaSourceLevel(slsa.ControlName(level)) &&
				slsa.IsLevelHigherOrEqualTo(slsa.SlsaSourceLevel(level), highestSlsaLevel) {
				highestSlsaLevel = slsa.SlsaSourceLevel(level)
			}
		}
	}
	// Sort (to keep order deterministic) and compact to remove dup
	slices.Sort(verifiedLevels)
	verifiedLevels = slices.Compact(verifiedLevels)

	// Now delete anything that is a SLSA source level but isn't the highest one.
	verifiedLevels = slices.DeleteFunc(verifiedLevels, func(level slsa.ControlName) bool {
		return slsa.IsSlsaSourceLevel(level) && level != slsa.ControlName(highestSlsaLevel)
	})

	return verifiedLevels, nil
}

// PolicyEvaluator creates a new policy evaluator
type PolicyEvaluator struct {
	// UNSAFE!
	// Instead of grabbing the policy from the canonical repo, use the policy at this path instead.
	UseLocalPolicy string

	authenticator *auth.Authenticator
	reader        models.AttestationStorageReader
	client        *github.Client
}

func NewPolicyEvaluator() *PolicyEvaluator {
	eval := &PolicyEvaluator{}
	// TODO(puerco): Implement functional opts to reuse clients
	if eval.reader == nil {
		eval.reader = notes.New()
	}

	if eval.authenticator == nil {
		eval.authenticator = auth.New()
	}
	return eval
}

// EvaluateControl checks the control against the policy and returns the resulting source level and policy path.
func (pe *PolicyEvaluator) EvaluateControl(ctx context.Context, repo *models.Repository, branch *models.Branch, controlStatus *ghcontrol.GhControlStatus) (slsa.SourceVerifiedLevels, string, error) {
	// We want to check to ensure the repo hasn't enabled/disabled the rules since
	// setting the 'since' field in their policy.
	rp, policyPath, err := pe.GetPolicy(ctx, repo)
	if err != nil {
		return slsa.SourceVerifiedLevels{}, "", err
	}

	branchPolicy := rp.getBranchPolicy(branch.Name)
	if branchPolicy == nil {
		branchPolicy = createDefaultBranchPolicy(branch)
		policyPath = "DEFAULT"
	}

	if controlStatus.CommitPushTime.Before(branchPolicy.GetSince().AsTime()) {
		// This commit was pushed before they had an explicit policy.
		return slsa.SourceVerifiedLevels{slsa.ControlName(slsa.SlsaSourceLevel1)}, policyPath, nil
	}

	verifiedLevels, err := evaluateBranchControls(branchPolicy, rp.GetProtectedTag(), controlStatus.Controls)
	if err != nil {
		return verifiedLevels, policyPath, fmt.Errorf("error evaluating policy %s: %w", policyPath, err)
	}
	return verifiedLevels, policyPath, nil
}

// Evaluates the provenance against the policy and returns the resulting source level and policy path
func (pe *PolicyEvaluator) EvaluateSourceProv(ctx context.Context, repo *models.Repository, branch *models.Branch, prov *spb.Statement) (slsa.SourceVerifiedLevels, string, error) {
	rp, policyPath, err := pe.GetPolicy(ctx, repo)
	if err != nil {
		return slsa.SourceVerifiedLevels{}, "", fmt.Errorf("getting policy: %w", err)
	}

	provPred, err := attest.GetSourceProvPred(prov)
	if err != nil {
		return slsa.SourceVerifiedLevels{}, "", err
	}

	branchPolicy := rp.getBranchPolicy(branch.Name)
	if branchPolicy == nil {
		branchPolicy = createDefaultBranchPolicy(branch)
		policyPath = "DEFAULT"
	}

	verifiedLevels, err := evaluateBranchControls(branchPolicy, rp.GetProtectedTag(), provPred.GetControls())
	if err != nil {
		return slsa.SourceVerifiedLevels{}, policyPath, fmt.Errorf("error evaluating policy %s: %w", policyPath, err)
	}

	// Looks good!
	return verifiedLevels, policyPath, nil
}

// Evaluates the provenance against the policy and returns the resulting source level and policy path
func (pe *PolicyEvaluator) EvaluateTagProv(ctx context.Context, repo *models.Repository, prov *spb.Statement) (slsa.SourceVerifiedLevels, string, error) {
	rp, policyPath, err := pe.GetPolicy(ctx, repo)
	if err != nil {
		return slsa.SourceVerifiedLevels{}, "", err
	}

	provPred, err := attest.GetTagProvPred(prov)
	if err != nil {
		return slsa.SourceVerifiedLevels{}, "", err
	}

	outputVerifiedLevels, err := evaluateTagProv(rp.GetProtectedTag(), provPred)
	if err != nil {
		return slsa.SourceVerifiedLevels{}, policyPath, fmt.Errorf("error evaluating policy %s: %w", policyPath, err)
	}

	// Looks good!
	return outputVerifiedLevels, policyPath, nil
}
