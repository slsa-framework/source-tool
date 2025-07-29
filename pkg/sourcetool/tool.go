// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package sourcetool

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slsa-framework/slsa-source-poc/pkg/auth"
	"github.com/slsa-framework/slsa-source-poc/pkg/policy"
	"github.com/slsa-framework/slsa-source-poc/pkg/slsa"
	"github.com/slsa-framework/slsa-source-poc/pkg/sourcetool/models"
	"github.com/slsa-framework/slsa-source-poc/pkg/sourcetool/options"
)

var ControlConfigurations = []models.ControlConfiguration{
	models.CONFIG_POLICY, models.CONFIG_GEN_PROVENANCE, models.CONFIG_BRANCH_RULES, models.CONFIG_TAG_RULES,
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
func (t *Tool) GetBranchControls(r *models.Repository, branch *models.Branch) (*slsa.ControlSetStatus, error) {
	ctx := context.Background()
	backend, err := t.impl.GetVcsBackend(r)
	if err != nil {
		return nil, fmt.Errorf("getting VCS backend: %w", err)
	}

	controls, err := t.impl.GetBranchControls(ctx, backend, r, branch)
	if err != nil {
		return nil, fmt.Errorf("getting branch controls: %w", err)
	}

	// We also abstract the repository policy as a control to report its status
	status, err := t.impl.GetPolicyStatus(ctx, t.Authenticator, &t.Options, r)
	if err != nil {
		return nil, fmt.Errorf("reading policy status: %w", err)
	}

	controls.Controls = append(controls.Controls, *status)

	return controls, err
}

// OnboardRepository configures a repository to set up the required controls
// to meet SLSA Source L3.
func (t *Tool) OnboardRepository(repo *models.Repository, branches []*models.Branch) error {
	backend, err := t.impl.GetVcsBackend(repo)
	if err != nil {
		return fmt.Errorf("getting VCS backend: %w", err)
	}

	if err := t.impl.VerifyOptionsForFullOnboard(t.Authenticator, &t.Options); err != nil {
		return fmt.Errorf("verifying options: %w", err)
	}

	if err = backend.ConfigureControls(
		repo, branches, []models.ControlConfiguration{
			models.CONFIG_BRANCH_RULES, models.CONFIG_GEN_PROVENANCE, models.CONFIG_TAG_RULES,
		},
	); err != nil {
		return fmt.Errorf("configuring controls: %w", err)
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

		// Build the policy here:
		pcy, err := t.CreateBranchPolicy(context.Background(), repo, branches)
		if err != nil {
			return fmt.Errorf("creating policy for: %w", err)
		}

		if _, err := t.impl.CreatePolicyPR(t.Authenticator, &t.Options, repo, pcy); err != nil {
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

func (t *Tool) FindPolicyPR(repo *models.Repository) (*models.PullRequest, error) {
	policyRepoOwner := policy.SourcePolicyRepoOwner
	policyRepoRepo := policy.SourcePolicyRepo
	o, r, ok := strings.Cut(t.Options.PolicyRepo, "/")
	if ok {
		policyRepoOwner = o
		policyRepoRepo = r
	}

	pr, err := t.impl.SearchPullRequest(context.Background(), t.Authenticator, &models.Repository{
		Hostname: "github.com",
		Path:     fmt.Sprintf("%s/%s", policyRepoOwner, policyRepoRepo),
	}, fmt.Sprintf("Add %s SLSA Source policy file", repo.Path))
	if err != nil {
		return nil, fmt.Errorf("searching for policy pull request: %w", err)
	}

	return pr, nil
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
func (t *Tool) CreateBranchPolicy(ctx context.Context, r *models.Repository, branches []*models.Branch) (*policy.RepoPolicy, error) {
	if len(branches) > 1 {
		// Change this once we support merging policies
		return nil, fmt.Errorf("only one branch is supported at a time")
	}
	if branches == nil {
		return nil, errors.New("no branches defined")
	}
	backend, err := t.impl.GetVcsBackend(r)
	if err != nil {
		return nil, fmt.Errorf("getting backend: %w", err)
	}

	controls, err := t.impl.GetBranchControls(ctx, backend, r, branches[0])
	if err != nil {
		return nil, fmt.Errorf("getting branch controls: %w", err)
	}

	return t.createPolicy(r, branches[0], controls)
}

// This function will be moved to the policy package once we start integrating
// it with the global data models (if we do).
func (t *Tool) createPolicy(r *models.Repository, branch *models.Branch, controls *slsa.ControlSetStatus) (*policy.RepoPolicy, error) {
	// Default to SLSA1 since unset date
	eligibleSince := &time.Time{}
	eligibleLevel := slsa.SlsaSourceLevel1

	var err error
	// Unless there is previous provenance metadata, then we can compute
	// a higher level
	if controls != nil {
		eligibleLevel = policy.ComputeEligibleSlsaLevel(*controls.GetActiveControls())
		eligibleSince, err = policy.ComputeEligibleSince(*controls.GetActiveControls(), eligibleLevel)
		if err != nil {
			return nil, fmt.Errorf("could not compute eligible_since: %w", err)
		}
	}

	p := &policy.RepoPolicy{
		CanonicalRepo: r.GetHttpURL(),
		ProtectedBranches: []*policy.ProtectedBranch{
			{
				Name:                  branch.FullRef(),
				Since:                 timestamppb.New(*eligibleSince),
				TargetSlsaSourceLevel: string(eligibleLevel),
			},
		},
	}
	return p, nil
}

// GetRepositoryPolicy retrieves the policy of repo from the community
func (t *Tool) GetRepositoryPolicy(ctx context.Context, r *models.Repository) (*policy.RepoPolicy, error) {
	pe := policy.NewPolicyEvaluator()
	p, _, err := pe.GetPolicy(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("getting repository policy: %w", err)
	}

	return p, nil
}

// CreateRepositoryPolicy creates a policy for a repository
func (t *Tool) CreateRepositoryPolicy(ctx context.Context, r *models.Repository, branches []*models.Branch) (*policy.RepoPolicy, *models.PullRequest, error) {
	pcy, err := t.CreateBranchPolicy(ctx, r, branches)
	if err != nil {
		return nil, nil, fmt.Errorf("creating policy for: %w", err)
	}

	var pr *models.PullRequest

	// If the option is set, open the pull request
	if t.Options.CreatePolicyPR {
		pr, err = t.impl.CreatePolicyPR(t.Authenticator, &t.Options, r, pcy)
		if err != nil {
			return nil, nil, fmt.Errorf("opening the policy pull request: %w", err)
		}
	}
	return pcy, pr, nil
}
