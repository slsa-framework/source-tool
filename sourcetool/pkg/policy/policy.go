package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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

// When a branch requires multiple controls, they must all be enabled
// at or before 'Since'.
type ProtectedBranch struct {
	Name                  string
	Since                 time.Time
	TargetSlsaSourceLevel slsa_types.SlsaSourceLevel `json:"target_slsa_source_level"`
	RequireReview         bool                       `json:"require_review"`
	ImmutableTags         bool                       `json:"immutable_tags"`
}

type RepoPolicy struct {
	// I'm actually not sure we need this.  Consider removing?
	CanonicalRepo     string            `json:"canonical_repo"`
	ProtectedBranches []ProtectedBranch `json:"protected_branches"`
}

func getPolicyPath(gh_connection *gh_control.GitHubConnection) string {
	return fmt.Sprintf("policy/github.com/%s/%s/source-policy.json", gh_connection.Owner, gh_connection.Repo)
}

func getPolicyRepoPath(pathToClone string, gh_connection *gh_control.GitHubConnection) string {
	return fmt.Sprintf("%s/%s", pathToClone, getPolicyPath(gh_connection))
}

// If we can't find a policy we return a nil policy.
func getRemotePolicy(ctx context.Context, gh_connection *gh_control.GitHubConnection) (*RepoPolicy, string, error) {
	path := getPolicyPath(gh_connection)

	policyContents, _, resp, err := gh_connection.Client.Repositories.GetContents(ctx, SourcePolicyRepoOwner, SourcePolicyRepo, path, nil)
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

func (policy Policy) getPolicy(ctx context.Context, gh_connection *gh_control.GitHubConnection) (*RepoPolicy, string, error) {
	if policy.UseLocalPolicy == "" {
		return getRemotePolicy(ctx, gh_connection)
	}
	return getLocalPolicy(policy.UseLocalPolicy)
}

// Gets the policy for the indicated branch direct from the GitHub repo.
func (policy Policy) getBranchPolicy(ctx context.Context, gh_connection *gh_control.GitHubConnection) (*ProtectedBranch, string, error) {
	p, path, err := policy.getPolicy(ctx, gh_connection)

	if err != nil {
		return nil, "", err
	}

	if p != nil {
		for _, pb := range p.ProtectedBranches {
			if pb.Name == gh_connection.Branch {
				return &pb, path, nil
			}
		}
	}

	// No policy so return the default branch policy.
	return &ProtectedBranch{
		Name:                  gh_connection.Branch,
		Since:                 time.Now(),
		TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel1,
		RequireReview:         false}, "DEFAULT", nil
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
	// TODO: Look for errors that _aren't_ 404.
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
	latestCommit, err := gh_connection.GetLatestCommit(ctx)
	if err != nil {
		return "", fmt.Errorf("could not get latest commit: %w", err)
	}

	ver_options := attest.DefaultVerifierOptions
	pa := attest.NewProvenanceAttestor(gh_connection, ver_options)
	_, provPred, err := pa.GetProvenance(ctx, latestCommit)
	if err != nil {
		return "", fmt.Errorf("could not get provenance for latest commit: %w", err)
	}

	// Default to SLSA1 since unset date
	var eligibleSince = &time.Time{}
	var eligibleLevel = slsa_types.SlsaSourceLevel1

	// Unless there is previous provenance metadata, then we can compute
	// a higher level
	if provPred != nil {
		eligibleLevel, _ = computeEligibleSlsaLevel(provPred.Controls)
		eligibleSince, err = computeEligibleSince(provPred.Controls, eligibleLevel)
		if err != nil {
			return "", fmt.Errorf("could not compute eligible since: %w", err)
		}
	}

	p := RepoPolicy{
		CanonicalRepo: "TODO fill this in",
		ProtectedBranches: []ProtectedBranch{
			{
				Name:                  gh_connection.Branch,
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

// Computes the eligible SLSA level, and when they started being eligible for it,
// if only they had a policy.  Also returns a rationale for why it's eligible for this level.
func computeEligibleSlsaLevel(controls slsa_types.Controls) (slsa_types.SlsaSourceLevel, string) {
	continuityControl := controls.GetControl(slsa_types.ContinuityEnforced)
	provControl := controls.GetControl(slsa_types.ProvenanceAvailable)

	if continuityControl != nil && provControl != nil {
		// Both continuity and prov means it can get level 3
		return slsa_types.SlsaSourceLevel3, "continuity is enable and provenance is available"
	}

	if continuityControl != nil {
		// Just continuity control means it can get level 2
		return slsa_types.SlsaSourceLevel2, "continuity is enabled but provenance is not available"
	}

	// If nothing else, level 1.
	// The time here is tricky, it's really probably since whenever they created the repo
	// But also, they don't qualify for much so maybe it doesn't matter.
	// Just return now for now.
	return slsa_types.SlsaSourceLevel1, "continuity is not enabled"
}

// Computes the time since these controls have been eligible for the level, nil if not eligible.
func computeEligibleSince(controls slsa_types.Controls, level slsa_types.SlsaSourceLevel) (*time.Time, error) {
	continuityControl := controls.GetControl(slsa_types.ContinuityEnforced)
	provControl := controls.GetControl(slsa_types.ProvenanceAvailable)

	if level == slsa_types.SlsaSourceLevel3 {
		if continuityControl != nil && provControl != nil {
			t := slsa_types.LaterTime(continuityControl.Since, provControl.Since)
			return &t, nil
		}
		return nil, nil
	}

	if level == slsa_types.SlsaSourceLevel2 {
		if continuityControl != nil {
			return &continuityControl.Since, nil
		}
		return nil, nil
	}

	if level == slsa_types.SlsaSourceLevel1 {
		// Use an uninitialized time to indicate it's always been eligible.
		return &time.Time{}, nil
	}

	// Unknown level
	return nil, fmt.Errorf("unknown level %s", level)
}

func computeSlsaLevel(branchPolicy *ProtectedBranch, controls slsa_types.Controls) (slsa_types.SlsaSourceLevel, error) {
	eligibleLevel, eligibleWhy := computeEligibleSlsaLevel(controls)

	if !slsa_types.IsLevelHigherOrEqualTo(eligibleLevel, branchPolicy.TargetSlsaSourceLevel) {
		return "", fmt.Errorf("policy sets target level %s, but branch is only eligible for %s because %s", branchPolicy.TargetSlsaSourceLevel, eligibleLevel, eligibleWhy)
	}

	// Check to see when this branch became eligible for the current target level.
	eligibleSince, err := computeEligibleSince(controls, branchPolicy.TargetSlsaSourceLevel)
	if err != nil {
		return "", fmt.Errorf("could not compute eligible since: %w", err)
	}
	if eligibleSince == nil {
		return "", fmt.Errorf("policy sets target level %s, but cannot compute when controls made it eligible for that level", branchPolicy.TargetSlsaSourceLevel)
	}

	if branchPolicy.Since.Before(*eligibleSince) {
		return "", fmt.Errorf("policy sets target level %s since %v, but it has only been eligible for that level since %v", branchPolicy.TargetSlsaSourceLevel, branchPolicy.Since, eligibleSince)
	}

	return branchPolicy.TargetSlsaSourceLevel, nil
}

func computeReviewEnforced(branchPolicy *ProtectedBranch, controls slsa_types.Controls) (bool, error) {
	if !branchPolicy.RequireReview {
		return false, nil
	}

	reviewControl := controls.GetControl(slsa_types.ReviewEnforced)
	if reviewControl == nil {
		return false, fmt.Errorf("policy requires review, but that control is not enabled")
	}

	if branchPolicy.Since.Before(reviewControl.Since) {
		return false, fmt.Errorf("policy requires review since %v, but that control has only been enabled since %v", branchPolicy.Since, reviewControl.Since)
	}

	return true, nil
}

func computeImmutableTags(branchPolicy *ProtectedBranch, controls slsa_types.Controls) (bool, error) {
	if !branchPolicy.ImmutableTags {
		return false, nil
	}

	immutableTags := controls.GetControl(slsa_types.ImmutableTags)
	if immutableTags == nil {
		return false, fmt.Errorf("policy requires immutable tags, but that control is not enabled")
	}

	if branchPolicy.Since.Before(immutableTags.Since) {
		return false, fmt.Errorf("policy requires immutable tags since %v, but that control has only been enabled since %v", branchPolicy.Since, immutableTags.Since)
	}

	return true, nil
}

// Returns a list of controls to include in the vsa's 'verifiedLevels' field.
func evaluateControls(branchPolicy *ProtectedBranch, controls slsa_types.Controls) (slsa_types.SourceVerifiedLevels, error) {
	slsaSourceLevel, err := computeSlsaLevel(branchPolicy, controls)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, fmt.Errorf("error computing slsa level: %w", err)
	}

	verifiedLevels := slsa_types.SourceVerifiedLevels{string(slsaSourceLevel)}

	reviewEnforced, err := computeReviewEnforced(branchPolicy, controls)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, fmt.Errorf("error computing review enforced: %w", err)
	}
	if reviewEnforced {
		verifiedLevels = append(verifiedLevels, slsa_types.ReviewEnforced)
	}

	immutableTags, err := computeImmutableTags(branchPolicy, controls)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, fmt.Errorf("error computing tag immutability enforced: %w", err)
	}
	if immutableTags {
		verifiedLevels = append(verifiedLevels, slsa_types.ImmutableTags)
	}

	return verifiedLevels, nil
}

type Policy struct {
	// UNSAFE!
	// Instead of grabbing the policy from the canonical repo, use the policy at this path instead.
	UseLocalPolicy string
}

func NewPolicy() *Policy {
	return &Policy{}
}

// Evaluates the control against the policy and returns the resulting source level and policy path.
func (policy Policy) EvaluateControl(ctx context.Context, gh_connection *gh_control.GitHubConnection, controlStatus *gh_control.GhControlStatus) (slsa_types.SourceVerifiedLevels, string, error) {
	// We want to check to ensure the repo hasn't enabled/disabled the rules since
	// setting the 'since' field in their policy.
	branchPolicy, policyPath, err := policy.getBranchPolicy(ctx, gh_connection)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, "", err
	}

	if controlStatus.CommitPushTime.Before(branchPolicy.Since) {
		// This commit was pushed before they had an explicit policy.
		return slsa_types.SourceVerifiedLevels{string(slsa_types.SlsaSourceLevel1)}, policyPath, nil
	}

	verifiedLevels, err := evaluateControls(branchPolicy, controlStatus.Controls)
	if err != nil {
		return verifiedLevels, policyPath, fmt.Errorf("error evaluating policy %s: %w", policyPath, err)
	}
	return verifiedLevels, policyPath, nil
}

// Evaluates the provenance against the policy and returns the resulting source level and policy path
func (policy Policy) EvaluateProv(ctx context.Context, gh_connection *gh_control.GitHubConnection, prov *spb.Statement) (slsa_types.SourceVerifiedLevels, string, error) {
	branchPolicy, policyPath, err := policy.getBranchPolicy(ctx, gh_connection)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, "", err
	}

	provPred, err := attest.GetProvPred(prov)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, "", err
	}

	verifiedLevels, err := evaluateControls(branchPolicy, provPred.Controls)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, policyPath, fmt.Errorf("error evaluating policy %s: %w", policyPath, err)
	}

	// Looks good!
	return verifiedLevels, policyPath, nil
}
