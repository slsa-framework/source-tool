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
	TargetSlsaSourceLevel string `json:"target_slsa_source_level"`
	RequireReview         bool   `json:"require_review"`
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

// Gets the policy for the indicated branch direct from the GitHub repo.
func GetBranchPolicy(ctx context.Context, gh_connection *gh_control.GitHubConnection) (*ProtectedBranch, string, error) {
	p, path, err := getRemotePolicy(ctx, gh_connection)

	if err != nil {
		return nil, "", err
	}

	if p == nil {
		// No policy so return the default branch policy.
		return &ProtectedBranch{
			Name:                  gh_connection.Branch,
			Since:                 time.Now(),
			TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel1,
			RequireReview:         false}, "DEFAULT", nil
	}

	for _, pb := range p.ProtectedBranches {
		if pb.Name == gh_connection.Branch {
			return &pb, path, nil
		}
	}

	return nil, "", fmt.Errorf("could not find rule for branch %s", gh_connection.Branch)
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

	// TODO check to make sure we're in a clean copy of the repo.
	p := RepoPolicy{
		CanonicalRepo: "TODO fill this in",
		ProtectedBranches: []ProtectedBranch{
			ProtectedBranch{
				Name:                  gh_connection.Branch,
				Since:                 time.Now(),
				TargetSlsaSourceLevel: slsa_types.SlsaSourceLevel2,
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

func computeSlsaLevel(branchPolicy *ProtectedBranch, controls slsa_types.Controls) (string, error) {
	// Level 1 is easy...
	if branchPolicy.TargetSlsaSourceLevel == slsa_types.SlsaSourceLevel1 {
		// No point in checking anything else.
		return slsa_types.SlsaSourceLevel1, nil
	}

	// Level 2 requires continuity and nothing else.
	continuityControl := controls.GetControl(slsa_types.ContinuityEnforced)
	if continuityControl == nil {
		return "", fmt.Errorf("policy sets target level %s, but continuity is not enabled so control only qualifies for %s", branchPolicy.TargetSlsaSourceLevel, slsa_types.SlsaSourceLevel1)
	}

	if branchPolicy.Since.Before(continuityControl.Since) {
		return "", fmt.Errorf("policy sets target level %s since %v, but continuity has only been enabled since %v", branchPolicy.TargetSlsaSourceLevel, branchPolicy.Since, continuityControl.Since)
	}

	if branchPolicy.TargetSlsaSourceLevel == slsa_types.SlsaSourceLevel2 {
		// Meets all the L2 control requirements.
		return slsa_types.SlsaSourceLevel2, nil
	}

	// In addition to continuity level 3 also requires provenance.
	provControl := controls.GetControl(slsa_types.ProvenanceAvailable)
	if provControl == nil {
		return "", fmt.Errorf("policy sets target level %s, but no provenance is available so control only qualifies for %s", branchPolicy.TargetSlsaSourceLevel, slsa_types.SlsaSourceLevel2)
	}

	if branchPolicy.Since.Before(provControl.Since) {
		return "", fmt.Errorf("policy sets target level %s since %v, but provenance has only been available since %v", branchPolicy.TargetSlsaSourceLevel, branchPolicy.Since, provControl.Since)
	}

	if branchPolicy.TargetSlsaSourceLevel == slsa_types.SlsaSourceLevel3 {
		// Meets all the L3 control requirements.
		return slsa_types.SlsaSourceLevel3, nil
	}

	return "", fmt.Errorf("policy sets an unknown target level: %s", branchPolicy.TargetSlsaSourceLevel)
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

// Returns a list of controls to include in the vsa's 'verifiedLevels' field.
func evaluateControls(branchPolicy *ProtectedBranch, controls slsa_types.Controls) (slsa_types.SourceVerifiedLevels, error) {
	slsaSourceLevel, err := computeSlsaLevel(branchPolicy, controls)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, fmt.Errorf("error computing slsa level: %w", err)
	}

	verifiedLevels := slsa_types.SourceVerifiedLevels{slsaSourceLevel}

	reviewEnforced, err := computeReviewEnforced(branchPolicy, controls)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, fmt.Errorf("error computing review enforced: %w", err)
	}
	if reviewEnforced {
		verifiedLevels = append(verifiedLevels, slsa_types.ReviewEnforced)
	}

	return verifiedLevels, nil
}

// Evaluates the control against the policy and returns the resulting source level and policy path.
func EvaluateControl(ctx context.Context, gh_connection *gh_control.GitHubConnection, controlStatus *gh_control.GhControlStatus) (slsa_types.SourceVerifiedLevels, string, error) {
	// We want to check to ensure the repo hasn't enabled/disabled the rules since
	// setting the 'since' field in their policy.
	branchPolicy, policyPath, err := GetBranchPolicy(ctx, gh_connection)
	if err != nil {
		return slsa_types.SourceVerifiedLevels{}, "", err
	}

	if controlStatus.CommitPushTime.Before(branchPolicy.Since) {
		// This commit was pushed before they had an explicit policy.
		return slsa_types.SourceVerifiedLevels{slsa_types.SlsaSourceLevel1}, policyPath, nil
	}

	verifiedLevels, err := evaluateControls(branchPolicy, controlStatus.Controls)
	if err != nil {
		return verifiedLevels, policyPath, fmt.Errorf("error evaluating policy %s: %w", policyPath, err)
	}
	return verifiedLevels, policyPath, nil
}

// Evaluates the provenance against the policy and returns the resulting source level and policy path
func EvaluateProv(ctx context.Context, gh_connection *gh_control.GitHubConnection, prov *spb.Statement) (slsa_types.SourceVerifiedLevels, string, error) {
	branchPolicy, policyPath, err := GetBranchPolicy(ctx, gh_connection)
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
