//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package sourcetool

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/auth"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/policy"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/models"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/options"
)

var ControlConfigurations = []models.ControlConfiguration{
	models.CONFIG_POLICY, models.CONFIG_GEN_PROVENANCE, models.CONFIG_BRANCH_RULES,
}

// New initializes a new source tool instance.
func New(funcs ...ConfigFn) (*Tool, error) {
	t := &Tool{
		Options: options.Default,
		impl:    &defaultToolImplementation{},
	}

	for _, f := range funcs {
		if err := f(t); err != nil {
			return nil, err
		}
	}

	return t, nil
}

// Tool is the main object intended to expose sourcetool's functionality as a
// public API. Some of the logic is still implemented on the CLI commands but
// we want to slowly move it to public function under this struct.
type Tool struct {
	Authenticator *auth.Authenticator
	Options       options.Options
	impl          toolImplementation
}

// GetRepoControls returns the controls that are enabled in a repository branch.
func (t *Tool) GetBranchControls(r *models.Repository, branch *models.Branch) (*slsa.ControlStatus, error) {
	backend, err := t.impl.GetVcsBackend(r)
	if err != nil {
		return nil, fmt.Errorf("getting VCS backend: %w", err)
	}

	controls, err := t.impl.GetBranchControls(context.Background(), backend, r, branch)
	if err != nil {
		return nil, fmt.Errorf("getting branch controls: %w", err)
	}

	return controls, err
}

// OnboardRepository configures a repository to set up the required controls
// to meet SLSA Source L3.
func (t *Tool) OnboardRepository(repo *models.Repository, branches []*models.Branch) error {
	backend, err := t.impl.GetVcsBackend(repo)
	if err != nil {
		return fmt.Errorf("getting VCS backend: %w", err)
	}

	if err := t.impl.CheckForks(&t.Options); err != nil {
		return fmt.Errorf("checking repository forks: %w", err)
	}

	if err := t.impl.VerifyOptionsForFullOnboard(&t.Options); err != nil {
		return fmt.Errorf("verifying options: %w", err)
	}

	if err = backend.ConfigureControls(
		repo, branches, []models.ControlConfiguration{
			models.CONFIG_BRANCH_RULES, models.CONFIG_GEN_PROVENANCE,
		},
	); err != nil {
		return fmt.Errorf("configuring controls: %w", err)
	}

	// FIXME: Compute the policy here
	_, err = t.impl.CreatePolicyPR(t.Authenticator, &t.Options, repo, nil)
	if err != nil {
		return fmt.Errorf("opening the policy pull request: %w", err)
	}

	return nil
}

// ConfigureControls sets up a control in the repo
func (t *Tool) ConfigureControls(repo *models.Repository, branches []*models.Branch, configs []models.ControlConfiguration) error {
	backend, err := t.impl.GetVcsBackend(repo)
	if err != nil {
		return fmt.Errorf("getting VCS backend: %w", err)
	}

	// The policy configuration is not handled by the backend
	if slices.Contains(configs, models.CONFIG_POLICY) {
		if err := t.impl.CheckPolicyFork(&t.Options); err != nil {
			return fmt.Errorf("checking policy repo fork: %w", err)
		}
		// FIXME: Generate the policy heer
		if _, err := t.impl.CreatePolicyPR(t.Authenticator, &t.Options, repo, nil); err != nil {
			return fmt.Errorf("opening the policy pull request: %w", err)
		}
	}

	return t.impl.ConfigureControls(backend, repo, branches, configs)
}

// ControlConfigurationDescr returns a description of the controls
func (t *Tool) ControlConfigurationDescr(branch *models.Branch, config models.ControlConfiguration) string {
	backend, err := t.impl.GetVcsBackend(branch.Repository)
	if err != nil {
		return ""
	}

	return backend.ControlConfigurationDescr(branch, config)
}

type PullRequestDetails struct {
	Owner  string
	Repo   string
	Number int
}

func (t *Tool) FindPolicyPR(repo *models.Repository) (*PullRequestDetails, error) {
	policyRepoOwner := policy.SourcePolicyRepoOwner
	policyRepoRepo := policy.SourcePolicyRepo
	o, r, ok := strings.Cut(t.Options.PolicyRepo, "/")
	if ok {
		policyRepoOwner = o
		policyRepoRepo = r
	}

	prNr, err := t.impl.SearchPullRequest(t.Authenticator, &models.Repository{
		Hostname: "github.com",
		Path:     fmt.Sprintf("%s/%s", policyRepoOwner, policyRepoRepo),
	}, fmt.Sprintf("Add %s SLSA Source policy file", repo.Path))
	if err != nil {
		return nil, fmt.Errorf("searching for policy pull request: %w", err)
	}

	if prNr == 0 {
		return nil, nil
	}

	return &PullRequestDetails{
		Owner:  policyRepoOwner,
		Repo:   policyRepoRepo,
		Number: prNr,
	}, nil
}

func (t *Tool) CheckPolicyRepoFork(repo *models.Repository) (bool, error) {
	if err := t.impl.CheckPolicyFork(&t.Options); err != nil {
		if strings.Contains(err.Error(), "404 Not Found") {
			return false, nil
		}
		return false, err
	} else {
		return true, nil
	}
}

// CreateBranchPolicy creates a repository policy
func (t *Tool) CreateBranchPolicy(ctx context.Context, r *models.Repository, branch *models.Branch) (*policy.RepoPolicy, error) {
	backend, err := t.impl.GetVcsBackend(r)
	if err != nil {
		return nil, fmt.Errorf("getting backend: %w", err)
	}

	// Get the branch latest commit from the backend
	latestCommit, err := backend.GetLatestCommit(ctx, r, branch)
	if err != nil {
		return nil, fmt.Errorf("could not get latest commit: %w", err)
	}

	reader, err := t.impl.GetAttestationReader(nil)
	if err != nil {
		return nil, fmt.Errorf("getting attestation reader")
	}

	// Get the latest commit provenance attestation
	_, predicate, err := reader.GetCommitProvenance(ctx, branch, latestCommit)
	if err != nil {
		return nil, fmt.Errorf("could not get provenance for latest commit: %w", err)
	}

	var controls *slsa.Controls
	if predicate != nil {
		controls = &predicate.Controls
	}

	return t.createPolicy(r, branch, latestCommit, controls)
}

// This function should probably live in the policy package
func (t *Tool) createPolicy(r *models.Repository, branch *models.Branch, commit *models.Commit, controls *slsa.Controls) (*policy.RepoPolicy, error) {
	// Default to SLSA1 since unset date
	eligibleSince := &time.Time{}
	eligibleLevel := slsa.SlsaSourceLevel1
	var err error
	// Unless there is previous provenance metadata, then we can compute
	// a higher level
	if controls != nil {
		eligibleLevel = policy.ComputeEligibleSlsaLevel(*controls)
		eligibleSince, err = policy.ComputeEligibleSince(*controls, eligibleLevel)
		if err != nil {
			return nil, fmt.Errorf("could not compute eligible_since: %w", err)
		}
	}

	p := &policy.RepoPolicy{
		CanonicalRepo: r.GetHttpURL(),
		ProtectedBranches: []policy.ProtectedBranch{
			{
				Name:                  branch.FullRef(),
				Since:                 *eligibleSince,
				TargetSlsaSourceLevel: eligibleLevel,
			},
		},
	}
	return p, nil
}
