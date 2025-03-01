package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

type ProtectedBranch struct {
	Name                  string
	Since                 time.Time
	TargetSlsaSourceLevel string `json:"target_slsa_source_level"`
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

func getRemotePolicy(ctx context.Context, gh_connection *gh_control.GitHubConnection) (*RepoPolicy, string, error) {
	path := getPolicyPath(gh_connection)

	policyContents, _, _, err := gh_connection.Client.Repositories.GetContents(ctx, SourcePolicyRepoOwner, SourcePolicyRepo, path, nil)
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
		return fmt.Errorf("You must run this command in a clean clone of %s", SourcePolicyUri)
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
		return fmt.Errorf("Policy already exists at %s", path)
	}

	// Is there a remote policy?
	// TODO: Look for errors that _aren't_ 404.
	rp, _, _ := getRemotePolicy(ctx, gh_connection)
	if rp != nil {
		return fmt.Errorf("Policy already exists remotely for %s", getPolicyPath(gh_connection))
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

func evaluateControls(branchPolicy *ProtectedBranch, continuityEnabled bool, continuitySince *time.Time, provAvailable bool, provAvailableSince *time.Time) (string, error) {
	// Level 1 is easy...
	if branchPolicy.TargetSlsaSourceLevel == slsa_types.SlsaSourceLevel1 {
		// No point in checking anything else.
		return slsa_types.SlsaSourceLevel1, nil
	}

	// Level 2 requires continuity and nothing else.
	if !continuityEnabled {
		return "", fmt.Errorf("policy sets target level %s, but continuity is not enabled so control only qualifies for %s", branchPolicy.TargetSlsaSourceLevel, slsa_types.SlsaSourceLevel1)
	}

	if continuitySince == nil {
		return "", fmt.Errorf("continuity control required but continuitySince is nil")
	}

	if branchPolicy.Since.Before(*continuitySince) {
		return "", fmt.Errorf("policy sets target level %s since %v, but continuity has only been enabled since %v", branchPolicy.TargetSlsaSourceLevel, branchPolicy.Since, *continuitySince)
	}

	if branchPolicy.TargetSlsaSourceLevel == slsa_types.SlsaSourceLevel2 {
		// Meets all the L2 control requirements.
		return slsa_types.SlsaSourceLevel2, nil
	}

	// In addition to continuity level 3 also requires provenance.
	if !provAvailable {
		return "", fmt.Errorf("policy sets target level %s, but no provenance is available so control only qualifies for %s", branchPolicy.TargetSlsaSourceLevel, slsa_types.SlsaSourceLevel2)
	}

	if provAvailableSince == nil {
		return "", fmt.Errorf("provenance is available but provAvailableSince is nil")
	}

	if branchPolicy.Since.Before(*provAvailableSince) {
		return "", fmt.Errorf("policy sets target level %s since %v, but provenance has only been available since %v", branchPolicy.TargetSlsaSourceLevel, branchPolicy.Since, *provAvailableSince)
	}

	if branchPolicy.TargetSlsaSourceLevel == slsa_types.SlsaSourceLevel3 {
		// Meets all the L3 control requirements.
		return slsa_types.SlsaSourceLevel3, nil
	}

	return "", fmt.Errorf("policy sets an unknown target level: %s", branchPolicy.TargetSlsaSourceLevel)
}

// Evaluates the control against the policy and returns the resulting source level and policy path.
func EvaluateControl(ctx context.Context, gh_connection *gh_control.GitHubConnection, controlStatus *gh_control.GhControlStatus) (string, string, error) {
	// We want to check to ensure the repo hasn't enabled/disabled the rules since
	// setting the 'since' field in their policy.
	branchPolicy, policyPath, err := GetBranchPolicy(ctx, gh_connection)
	if err != nil {
		return "", "", err
	}

	if controlStatus.CommitPushTime.Before(branchPolicy.Since) {
		// This commit was pushed before they had an explicit policy.
		return slsa_types.SlsaSourceLevel1, policyPath, nil
	}

	level, err := evaluateControls(branchPolicy, controlStatus.ContinuityControl.RequiresContinuity, &controlStatus.ContinuityControl.EnabledSince, false, nil)
	if err != nil {
		return "", policyPath, fmt.Errorf("error evaluating policy %s: %w", policyPath, err)
	}
	return level, policyPath, nil
}

// Evaluates the provenance against the policy and returns the resulting source level and policy path
func EvaluateProv(ctx context.Context, gh_connection *gh_control.GitHubConnection, prov *spb.Statement) (string, string, error) {
	branchPolicy, policyPath, err := GetBranchPolicy(ctx, gh_connection)
	if err != nil {
		return "", "", err
	}

	provPred, err := attest.GetProvPred(prov)
	if err != nil {
		return "", "", err
	}

	continuityProp, continuityEnabled := provPred.Properties[slsa_types.ContinuityEnforced]
	provAvailableProp, provAvailable := provPred.Properties[slsa_types.ProvenanceAvailable]

	level, err := evaluateControls(branchPolicy, continuityEnabled, &continuityProp.Since, provAvailable, &provAvailableProp.Since)
	if err != nil {
		return "", policyPath, fmt.Errorf("error evaluating policy %s: %w", policyPath, err)
	}

	// Looks good!
	return level, policyPath, nil
}
