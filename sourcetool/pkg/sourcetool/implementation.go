package sourcetool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/carabiner-dev/github"
	gogit "github.com/go-git/go-git/v5"
	gogithub "github.com/google/go-github/v69/github"
	"github.com/sirupsen/logrus"
	kgithub "sigs.k8s.io/release-sdk/github"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/policy"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/options"
)

const (
	tokenVar = "GITHUB_TOKEN" //nolint:gosec // This are not creds, just the name

	workflowPath   = ".github/workflows/compute_slsa_source.yaml"
	workflowSource = "git+https://github.com/slsa-"

	// workflowCommitMessage will be used as the commit message and the PR title
	workflowCommitMessage = "Add SLSA Source Provenance Workflow"

	// workflowPRBody is the body of the pull request that adds the provenance workflow
	workflowPRBody = `This pull request adds a new workflow to the repository to generate ` +
		`[SLSA](https://slsa.dev/) Source provenance data on every push.` + "\n\n" +
		`Every time a new commit merges to the specified branch, attestations will ` +
		`be automatically signed and stored in git notes in this repository.` + "\n\n" +
		`Note: This is an automated PR created using the ` +
		`[SLSA sourcetool](https://github.com/slsa-framework/slsa-source-poc) utility.` + "\n"
)

// TODO(puerco): Read this from latest version on the repository
var workflowData = `---
name: SLSA Source
on:
  push:
    branches: [ %q ]
permissions: {}

jobs:
  # Whenever new source is pushed recompute the slsa source information.
  generate-provenance:
    permissions:
      contents: write # needed for storing the vsa in the repo.
      id-token: write # meeded to mint yokens for signing
    uses: slsa-framework/slsa-source-poc/.github/workflows/compute_slsa_source.yml@main
`

// toolImplementation defines the mockable implementation of source tool
//
//counterfeiter:generate . toolImplementation
type toolImplementation interface {
	GetActiveControls(*options.Options) (slsa.Controls, error)
	EnsureDefaults(opts *options.Options) error
	VerifyOptionsForFullOnboard(*options.Options) error
	CreateRepoRuleset(*options.Options) error
	CheckWorkflowFork(*options.Options) error
	CreateWorkflowPR(*options.Options) error
	CheckPolicyFork(*options.Options) error
	CreatePolicyPR(*options.Options) error
	CheckForks(*options.Options) error
	SearchPullRequest(*options.Options, string) (int, error)
}

type defaultToolImplementation struct{}

// GetActiveControls returns a slsa.Controls with the active controls on a repo
func (impl *defaultToolImplementation) GetActiveControls(opts *options.Options) (slsa.Controls, error) {
	ctx := context.Background()

	if err := opts.EnsureBranch(); err != nil {
		return nil, err
	}

	if err := opts.EnsureCommit(); err != nil {
		return nil, err
	}

	ghc, err := opts.GetGitHubConnection()
	if err != nil {
		return nil, fmt.Errorf("getting GitHub connection: %w", err)
	}

	// Get the active controls
	activeControls, err := ghc.GetBranchControls(ctx, ghcontrol.BranchToFullRef(opts.Branch))
	if err != nil {
		return nil, fmt.Errorf("checking status: %w", err)
	}

	// We need to manually check for PROVENANCE_AVAILABLE which is not
	// handled by ghcontrol
	attestor := attest.NewProvenanceAttestor(
		ghc, attest.GetDefaultVerifier(),
	)

	// Fetch the attestation. If found, then add the control:
	attestation, _, err := attestor.GetProvenance(ctx, opts.Commit, ghcontrol.BranchToFullRef(opts.Branch))
	if err != nil {
		return nil, fmt.Errorf("attempting to read provenance from commit %q: %w", opts.Commit, err)
	}
	if attestation != nil {
		activeControls.AddControl(&slsa.Control{
			Name: slsa.ProvenanceAvailable,
		})
	} else {
		log.Printf("No provenance attestation found on %s", opts.Commit)
	}

	return *activeControls, nil
}

// EnsureBranch makes sure the manager has a defined branch, looking up the
// default if it needs to
func (impl *defaultToolImplementation) EnsureDefaults(opts *options.Options) error {
	if t := os.Getenv(tokenVar); t == "" {
		return fmt.Errorf("$%s environment variable not set", tokenVar)
	}

	if err := opts.EnsureBranch(); err != nil {
		return err
	}

	// Load the token user to use as source org
	if err := getUserData(opts); err != nil {
		return err
	}

	// Output the computed defaults
	logrus.Infof("We will create branches based on forks from %q", opts.UserForkOrg)
	logrus.Infof("Using default branch %q", opts.Branch)
	return nil
}

func getUserData(opts *options.Options) error {
	if opts.UserForkOrg != "" {
		return nil
	}
	// Fetch the default branch
	client, err := github.NewClient()
	if err != nil {
		return fmt.Errorf("creating GitHub client: %w", err)
	}

	// Call the api to get the user's data
	res, err := client.Call(
		context.Background(), http.MethodGet,
		"https://api.github.com/user", nil,
	)
	if err != nil {
		return fmt.Errorf("fetching user data: %w", err)
	}
	defer res.Body.Close() //nolint:errcheck

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("reading user data: %w", err)
	}

	userdata := struct {
		Login string `json:"login"`
	}{}

	if err := json.Unmarshal(data, &userdata); err != nil {
		return fmt.Errorf("unmarshaling repo data: %w", err)
	}

	if userdata.Login == "" {
		return fmt.Errorf("unable to read user login for the token")
	}

	opts.UserForkOrg = userdata.Login
	return nil
}

// VerifyOptions checks options are in good shape to run
func (impl *defaultToolImplementation) VerifyOptionsForFullOnboard(opts *options.Options) error {
	errs := []error{}
	if opts.Repo == "" {
		errs = append(errs, errors.New("no repository name defined"))
	}

	if opts.Owner == "" {
		errs = append(errs, errors.New("no repository owner defined"))
	}

	if t := os.Getenv(tokenVar); t == "" {
		errs = append(errs, fmt.Errorf("$%s environment variable not set", tokenVar))
	}

	if opts.Enforce {
		client, err := github.NewClient()
		if err != nil {
			errs = append(errs, fmt.Errorf("creating GitHub client: %w", err))
		} else {
			scopes, err := client.TokenScopes()
			if err == nil {
				if !slices.Contains(scopes, "admin:write") {
					errs = append(errs, fmt.Errorf(`unable to create enforcing branch rules, token needs "Administration" repository permissions (write)`))
				}
			} else {
				errs = append(errs, fmt.Errorf("checking token scopes: %w", err))
			}
		}
	}

	return errors.Join(errs...)
}

func (impl *defaultToolImplementation) CreateRepoRuleset(opts *options.Options) error {
	// Ensure we have branch and defaults
	if err := opts.EnsureBranch(); err != nil {
		return err
	}
	if err := opts.EnsureCommit(); err != nil {
		return err
	}

	ghc, err := opts.GetGitHubConnection()
	if err != nil {
		return err
	}

	if err := ghc.EnableBranchRules(context.Background()); err != nil {
		return fmt.Errorf("enabling branch protection rules: %w", err)
	}

	return nil
}

// CheckWorkflowFork verifies that the user has a fork of the repository
// we are configuring.
func (impl *defaultToolImplementation) CheckWorkflowFork(opts *options.Options) error {
	userForkOrg := opts.UserForkOrg
	userForkRepo := opts.Repo // For now we only support forks with the same name

	if err := kgithub.VerifyFork(
		fmt.Sprintf("slsa-source-workflow-%d", time.Now().Unix()), userForkOrg, userForkRepo, opts.Owner, opts.Repo,
	); err != nil {
		return fmt.Errorf(
			"while checking fork of %s/%s in %s: %w ",
			opts.Owner, opts.Repo, opts.UserForkOrg, err,
		)
	}
	return nil
}

// CreateWorkflowPR creates the pull request to add the provenance workflow
// to the repository
func (impl *defaultToolImplementation) CreateWorkflowPR(opts *options.Options) error {
	// Branchname to be created on the user's fork
	branchname := fmt.Sprintf("slsa-source-workflow-%d", time.Now().Unix())

	// Check Environment
	gh := kgithub.New()

	userForkOrg := opts.UserForkOrg
	userForkRepo := opts.Repo // For now we only support forks with the same name

	// Clone the repository being onboarded
	gitCloneOpts := &gogit.CloneOptions{Depth: 1}
	repo, err := kgithub.PrepareFork(
		branchname, opts.Owner, opts.Repo,
		userForkOrg, userForkRepo,
		opts.UseSSH, opts.UpdateRepo, gitCloneOpts,
	)
	if err != nil {
		return fmt.Errorf("while preparing the repository fork: %w", err)
	}

	defer func() {
		repo.Cleanup() //nolint:errcheck,gosec
	}()

	// Create the workflow file here
	fullPath := filepath.Join(repo.Dir(), workflowPath)
	if err := os.MkdirAll(filepath.Dir(fullPath), os.FileMode(0o755)); err != nil {
		return fmt.Errorf("creating workflow directory: %w", err)
	}

	// Write the workflow file to disk
	if err := os.WriteFile(fullPath, []byte(fmt.Sprintf(workflowData, opts.Branch)), os.FileMode(0o644)); err != nil {
		return fmt.Errorf("writing workflow data to disk: %w", err)
	}

	// add the modified manifest to staging
	logrus.Debugf("Adding %s to staging area", workflowPath)
	if err := repo.Add(workflowPath); err != nil {
		return fmt.Errorf("adding workflow file to staging area: %w", err)
	}

	// Create the commit
	if err := repo.UserCommit(workflowCommitMessage); err != nil {
		return fmt.Errorf("committing changes to workflow: %w", err)
	}

	// Push commit to branch in the user's fork
	logrus.Infof("Pushing workflow commit to %s/%s", userForkOrg, userForkRepo)
	if err := repo.PushToRemote(kgithub.UserForkName, branchname); err != nil {
		return fmt.Errorf("pushing %s to %s/%s: %w", kgithub.UserForkName, userForkOrg, userForkRepo, err)
	}

	// Create the Pull Request
	pr, err := gh.CreatePullRequest(
		opts.Owner, opts.Repo, opts.Branch,
		fmt.Sprintf("%s:%s", userForkOrg, branchname),
		workflowCommitMessage, workflowPRBody, false,
	)
	if err != nil {
		return fmt.Errorf("creating the pull request in %s: %w", opts.Owner, err)
	}
	logrus.Infof(
		"Successfully created PR: %s%s/%s/pull/%d",
		kgithub.GitHubURL, opts.Owner, opts.Repo, pr.GetNumber(),
	)

	// Success!
	return nil
}

func (impl *defaultToolImplementation) CheckPolicyFork(opts *options.Options) error {
	policyOrg, policyRepo, ok := strings.Cut(opts.PolicyRepo, "/")
	if !ok || policyRepo == "" {
		return fmt.Errorf("unable to parse policy repository slug")
	}
	userForkOrg := opts.UserForkOrg
	userForkRepo := policyRepo // For now we only support forks with the same name

	// Check the user has a fork of the slsa repo
	if err := kgithub.VerifyFork(
		fmt.Sprintf("slsa-source-policy-%d", time.Now().Unix()), userForkOrg, userForkRepo, policyOrg, policyRepo,
	); err != nil {
		return fmt.Errorf(
			"while checking fork of %s/%s in %s: %w ",
			policyOrg, policyRepo, userForkOrg, err,
		)
	}
	return nil
}

// CreatePolicyPR creates a pull request to push the policy
func (impl *defaultToolImplementation) CreatePolicyPR(opts *options.Options) error {
	// Branchname to be created on the user's fork
	branchname := fmt.Sprintf("slsa-source-policy-%d", time.Now().Unix())

	gh := kgithub.New()
	policyOrg, policyRepo, ok := strings.Cut(opts.PolicyRepo, "/")
	if !ok || policyRepo == "" {
		return fmt.Errorf("unable to parse policy repository slug")
	}

	userForkOrg := opts.UserForkOrg
	userForkRepo := policyRepo // For now we only support forks with the same name

	// Clone the slsa repo
	gitCloneOpts := &gogit.CloneOptions{Depth: 1}
	repo, err := kgithub.PrepareFork(
		branchname, policyOrg, policyRepo,
		userForkOrg, userForkRepo,
		opts.UseSSH, opts.UpdateRepo, gitCloneOpts,
	)
	if err != nil {
		return fmt.Errorf("while preparing Slsa Source fork: %w", err)
	}

	defer func() {
		repo.Cleanup() //nolint:errcheck,gosec
	}()

	// Create the policy in the local clone
	ghc := ghcontrol.NewGhConnection(opts.Owner, opts.Repo, opts.Branch).WithAuthToken(os.Getenv(tokenVar))
	outpath, err := policy.CreateLocalPolicy(context.Background(), ghc, repo.Dir())
	if err != nil {
		return fmt.Errorf("creating local policy: %w", err)
	}

	// add the modified manifest to staging
	logrus.Debugf("Adding %s to staging area", outpath)
	if err := repo.Add(strings.TrimPrefix(strings.TrimPrefix(outpath, repo.Dir()), "/")); err != nil {
		return fmt.Errorf("adding new policy file to staging area: %w", err)
	}

	commitMessage := fmt.Sprintf("Add %s/%s SLSA Source policy file", opts.Owner, opts.Repo)

	// Commit files
	if err := repo.UserCommit(commitMessage); err != nil {
		return fmt.Errorf("creating commit in %s/%s: %w", policyOrg, policyRepo, err)
	}

	// Push to fork
	logrus.Infof("Pushing policy commit to %s/%s", userForkOrg, userForkRepo)
	if err := repo.PushToRemote(kgithub.UserForkName, branchname); err != nil {
		return fmt.Errorf("pushing %s to %s/%s: %w", kgithub.UserForkName, userForkOrg, userForkRepo, err)
	}

	prBody := fmt.Sprintf(`This pull request adds the SLSA source policy for github.com/%s/%s`, opts.Owner, opts.Repo)

	// Create the Pull Request
	pr, err := gh.CreatePullRequest(
		policyOrg, policyRepo, "main",
		fmt.Sprintf("%s:%s", userForkOrg, branchname),
		commitMessage, prBody, false,
	)
	if err != nil {
		logrus.Infof("%+v", err)
		return fmt.Errorf("creating the policy PR in %s/%s: %w", policyOrg, policyRepo, err)
	}
	logrus.Infof(
		"Successfully created PR: %s%s/%s/pull/%d",
		kgithub.GitHubURL, policyOrg, policyRepo, pr.GetNumber(),
	)

	// Success!
	return nil
}

// CheckForks checks that the user has forks of the required repositories
func (impl *defaultToolImplementation) CheckForks(opts *options.Options) error {
	errs := []error{}
	if err := impl.CheckPolicyFork(opts); err != nil {
		errs = append(errs, err)
	}

	if err := impl.CheckWorkflowFork(opts); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// SearchPullRequest searches the last pull requests on a repo for one whose
// title matches the query string
func (impl *defaultToolImplementation) SearchPullRequest(opts *options.Options, query string) (int, error) {
	gcx, err := opts.GetGitHubConnection()
	if err != nil {
		return 0, err
	}

	prs, _, err := gcx.Client().PullRequests.List(
		context.Background(), opts.Owner, opts.Repo, &gogithub.PullRequestListOptions{
			State: "open",
		},
	)

	if err != nil {
		return 0, fmt.Errorf("listing pull requests: %w", err)
	}

	for _, pr := range prs {
		if strings.Contains(pr.GetTitle(), query) {
			return pr.GetNumber(), nil
		}
	}
	return 0, nil
}
