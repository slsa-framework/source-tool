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
	"github.com/google/go-github/v68/github"
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

func getPolicyPath(owner, repo string) string {
	return fmt.Sprintf("policy/github.com/%s/%s/source-policy.json", owner, repo)
}

func getPolicyRepoPath(pathToClone, owner, repo string) string {
	return fmt.Sprintf("%s/%s", pathToClone, getPolicyPath(owner, repo))
}

func getRemotePolicy(ctx context.Context, gh_client *github.Client, owner, repo string) (*RepoPolicy, error) {
	path := getPolicyPath(owner, repo)

	policyContents, _, _, err := gh_client.Repositories.GetContents(ctx, SourcePolicyRepoOwner, SourcePolicyRepo, path, nil)
	if err != nil {
		return nil, err
	}

	content, err := policyContents.GetContent()
	if err != nil {
		return nil, err
	}
	var p RepoPolicy
	err = json.Unmarshal([]byte(content), &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Gets the policy for the indicated branch direct from the GitHub repo.
func GetBranchPolicy(ctx context.Context, gh_client *github.Client, owner, repo, branch string) (*ProtectedBranch, error) {
	p, err := getRemotePolicy(ctx, gh_client, owner, repo)
	if err != nil {
		return nil, err
	}

	for _, pb := range p.ProtectedBranches {
		if pb.Name == branch {
			return &pb, nil
		}
	}

	return nil, errors.New(fmt.Sprintf("Could not find rule for branch %s", branch))
}

// Check to see if the local directory is a clean clone or not
// TODO: Check if the policy exists remotely.
func checkLocalDir(ctx context.Context, gh_client *github.Client, pathToClone, owner, repoName string) error {
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
		return errors.New(fmt.Sprintf("You must run this command in a clean clone of %s", SourcePolicyUri))
	}

	path := getPolicyRepoPath(pathToClone, owner, repoName)
	// Is there already a local policy?
	_, err = os.Stat(path)
	if err != nil {
		// We _want_ ErrNotExist.
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else {
		return errors.New(fmt.Sprintf("Policy already exists at %s", path))
	}

	// Is there a remote policy?
	// TODO: Look for errors that _aren't_ 404.
	rp, _ := getRemotePolicy(ctx, gh_client, owner, repoName)
	if rp != nil {
		return errors.New(fmt.Sprintf("Policy already exists remotely for %s", getPolicyPath(owner, repoName)))
	}
	return nil
}

func CreateLocalPolicy(ctx context.Context, gh_client *github.Client, pathToClone, owner, repo, branch string) (string, error) {
	// First make sure they're in the right state...
	err := checkLocalDir(ctx, gh_client, pathToClone, owner, repo)
	if err != nil {
		return "", err
	}

	path := getPolicyRepoPath(pathToClone, owner, repo)

	// TODO check to make sure we're in a clean copy of the repo.
	p := RepoPolicy{
		CanonicalRepo: "TODO fill this in",
		ProtectedBranches: []ProtectedBranch{
			ProtectedBranch{
				Name:                  branch,
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

// Evaluates the control against the policy and returns the resulting source level.
func EvaluateControl(ctx context.Context, gh_client *github.Client, owner, repo, branch string, pushTime time.Time, controlStatus *gh_control.GhControlStatus) (string, error) {
	// We want to check to ensure the repo hasn't enabled/disabled the rules since
	// setting the 'since' field in their policy.
	branchPolicy, err := GetBranchPolicy(ctx, gh_client, owner, repo, branch)
	if err != nil {
		return "", err
	}

	if pushTime.Before(branchPolicy.Since) {
		// This commit was pushed before they had an explicit policy.
		return slsa_types.SlsaSourceLevel1, nil
	}

	// The control needs to have been enabled for at least as long as the policy says.
	if branchPolicy.Since.Before(controlStatus.ControlLevelSince) {
		if branchPolicy.TargetSlsaSourceLevel != slsa_types.SlsaSourceLevel1 {
			return "", errors.New(fmt.Sprintf("Policy sets target level %s, but control only qualifies for %s", branchPolicy.TargetSlsaSourceLevel, slsa_types.SlsaSourceLevel1))
		}

		// Level 1 doesn't really require any controls.
		return slsa_types.SlsaSourceLevel1, nil
	}

	// Seems fine, so they get whatever the control status is.
	// TODO: should we cap them at whatever the policies target is?
	return controlStatus.ControlLevel, nil
}

// Evaluates the provenance against the policy and returns the resulting source level
func EvaluateProv(ctx context.Context, gh_client *github.Client, owner, repo, branch string, prov *spb.Statement) (string, error) {
	branchPolicy, err := GetBranchPolicy(ctx, gh_client, owner, repo, branch)
	if err != nil {
		return "", err
	}

	provPred, err := attest.GetProvPred(prov)
	if err != nil {
		return "", err
	}

	levelProp, ok := provPred.Properties[branchPolicy.TargetSlsaSourceLevel]
	if !ok {
		// Error, or do we take the min?
		return "", errors.New(fmt.Sprintf("target level %s not found in provenance %v", branchPolicy.TargetSlsaSourceLevel, provPred))
	}

	// Unlike the control only approach, the provenance approach doesn't care how long GitHub claims the control
	// was in place. The only thing that matters is how long the provenance claims it was in place.
	if branchPolicy.Since.Before(levelProp.Since) {
		return "", errors.New(fmt.Sprintf("level %s only in effect since %v, policy requires it since at least %v", branchPolicy.TargetSlsaSourceLevel, levelProp.Since, branchPolicy.Since))
	}

	// Looks good!
	return branchPolicy.TargetSlsaSourceLevel, nil
}
