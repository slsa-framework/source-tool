//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package sourcetool

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	kgithub "sigs.k8s.io/release-sdk/github"

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
func (t *Tool) GetBranchControls(branch *models.Branch) (*slsa.Controls, error) {
	backend, err := t.impl.GetVcsBackend(branch.Repository)
	if err != nil {
		return nil, fmt.Errorf("getting VCS backend: %w", err)
	}

	controls, err := t.impl.GetBranchControls(context.Background(), backend, branch)
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

	if err := t.impl.CreatePolicyPR(t.Options, repo, nil); err != nil {
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
		if err := t.impl.CreatePolicyPR(t.Options, repo, branches); err != nil {
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

func (t *Tool) CheckPolicyFork(opts *options.Options) error {
	policyOrg, policyRepo, ok := strings.Cut(opts.PolicyRepo, "/")
	if !ok || policyRepo == "" {
		return fmt.Errorf("unable to parse policy repository slug")
	}

	if opts.UserForkOrg == "" {
		user, err := t.Authenticator.WhoAmI()
		if err != nil {
			return err
		}
		opts.UserForkOrg = user.GetLogin()
	}

	userForkOrg := opts.UserForkOrg
	userForkRepo := policyRepo // For now we only support forks with the same name

	if userForkOrg == "" {
		return errors.New("unable to check for for, user org not set")
	}

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
