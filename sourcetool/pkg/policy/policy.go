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

	// The control needs to have been enabled for at least as long as the policy says.
	if branchPolicy.Since.Before(controlStatus.SlsaLevelControl.EnabledSince) {
		if branchPolicy.TargetSlsaSourceLevel != slsa_types.SlsaSourceLevel1 {
			return "", "", fmt.Errorf("Policy sets target level %s, but control only qualifies for %s", branchPolicy.TargetSlsaSourceLevel, slsa_types.SlsaSourceLevel1)
		}

		// Level 1 doesn't really require any controls.
		return slsa_types.SlsaSourceLevel1, policyPath, nil
	}

	// Seems fine, so they get whatever the control status is.
	// TODO: should we cap them at whatever the policies target is?
	return controlStatus.SlsaLevelControl.Level, policyPath, nil
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

	levelProp, ok := provPred.Properties[branchPolicy.TargetSlsaSourceLevel]
	if !ok {
		// Error, or do we take the min?
		return "", "", fmt.Errorf("target level %s not found in provenance %v", branchPolicy.TargetSlsaSourceLevel, provPred)
	}

	// Unlike the control only approach, the provenance approach doesn't care how long GitHub claims the control
	// was in place. The only thing that matters is how long the provenance claims it was in place.
	if branchPolicy.Since.Before(levelProp.Since) {
		return "", "", fmt.Errorf("level %s only in effect since %v, policy requires it since at least %v", branchPolicy.TargetSlsaSourceLevel, levelProp.Since, branchPolicy.Since)
	}

	// Looks good!
	return branchPolicy.TargetSlsaSourceLevel, policyPath, nil
}
