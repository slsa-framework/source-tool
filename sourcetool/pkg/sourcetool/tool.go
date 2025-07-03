//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package sourcetool

import (
	"fmt"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/options"
)

type ControlConfiguration string

const (
	CONFIG_POLICY              ControlConfiguration = "CONFIG_POLICY"
	CONFIG_PROVENANCE_WORKFLOW ControlConfiguration = "CONFIG_PROVENANCE_WORKFLOW"
	CONFIG_BRANCH_RULES        ControlConfiguration = "CONFIG_BRANCH_RULES"
)

var ControlConfigurations = []ControlConfiguration{
	CONFIG_POLICY, CONFIG_PROVENANCE_WORKFLOW, CONFIG_BRANCH_RULES,
}

// New initializes a new source tool instance.
func New(funcs ...options.Fn) (*Tool, error) {
	opts := options.Default
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return nil, err
		}
	}

	return &Tool{
		Options: opts,
		impl:    &defaultToolImplementation{},
	}, nil
}

// Tool is the main object intended to expose sourcetool's functionality as a
// public API. Some of the logic is still implemented on the CLI commands but
// we want to slowly move it to public function under this struct.
type Tool struct {
	Options options.Options
	impl    toolImplementation
}

// GetRepoControls returns the controls that are enabled in a repository.
func (t *Tool) GetRepoControls(funcs ...options.Fn) (slsa.Controls, error) {
	opts := t.Options
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return nil, err
		}
	}

	return t.impl.GetActiveControls(&opts)
}

// OnboardRepository configures a repository to set up the required controls
// to meet SLSA Source L3.
func (t *Tool) OnboardRepository(funcs ...options.Fn) error {
	opts := t.Options
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return err
		}
	}

	if err := t.impl.EnsureDefaults(&opts); err != nil {
		return fmt.Errorf("ensuring runtime defaults: %w", err)
	}

	if err := t.impl.CheckForks(&opts); err != nil {
		return fmt.Errorf("checking repository forks: %w", err)
	}

	if err := t.impl.VerifyOptionsForFullOnboard(&opts); err != nil {
		return fmt.Errorf("verifying options: %w", err)
	}

	if err := t.impl.CreateRepoRuleset(&opts); err != nil {
		return fmt.Errorf("creating rules in the repository: %w", err)
	}

	if err := t.impl.CreateWorkflowPR(&opts); err != nil {
		return fmt.Errorf("opening SLSA source workflow pull request: %w", err)
	}

	if err := t.impl.CreatePolicyPR(&opts); err != nil {
		return fmt.Errorf("opening the policy pull request: %w", err)
	}

	return nil
}

// ConfigureControls setsup a control in the repo
func (t *Tool) ConfigureControls(configs []ControlConfiguration, funcs ...options.Fn) error {
	opts := t.Options
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return err
		}
	}

	if err := t.impl.EnsureDefaults(&opts); err != nil {
		return fmt.Errorf("ensuring default option values: %w", err)
	}

	for _, config := range configs {
		switch config {
		case CONFIG_BRANCH_RULES:
			if err := t.impl.CreateRepoRuleset(&opts); err != nil {
				return fmt.Errorf("creating rules in the repository: %w", err)
			}
		case CONFIG_PROVENANCE_WORKFLOW:
			if err := t.impl.CheckWorkflowFork(&opts); err != nil {
				return fmt.Errorf("checking repository fork: %w", err)
			}
			if err := t.impl.CreateWorkflowPR(&opts); err != nil {
				return fmt.Errorf("opening SLSA source workflow pull request: %w", err)
			}
		case CONFIG_POLICY:
			if err := t.impl.CheckPolicyFork(&opts); err != nil {
				return fmt.Errorf("checking policy repo fork: %w", err)
			}
			if err := t.impl.CreatePolicyPR(&opts); err != nil {
				return fmt.Errorf("opening the policy pull request: %w", err)
			}
		default:
			return fmt.Errorf("unknown configuration flag: %q", config)
		}
	}
	return nil
}

// ControlConfigurationDescr
func (t *Tool) ControlConfigurationDescr(config ControlConfiguration, funcs ...options.Fn) string {
	opts := t.Options
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return ""
		}
	}
	switch config {
	case CONFIG_BRANCH_RULES:
		return fmt.Sprintf(
			"Enable push and delete protection on branch %q of %s/%s",
			opts.Branch, opts.Owner, opts.Repo,
		)
	case CONFIG_PROVENANCE_WORKFLOW:
		return fmt.Sprintf(
			"Open a pull request on %s/%s to add the provenance generation workflow",
			opts.Owner, opts.Repo,
		)
	case CONFIG_POLICY:
		return fmt.Sprintf(
			"Open a pull request on %s to check-in the %s/%s SLSA source policy",
			opts.PolicyRepo, opts.Owner, opts.Repo,
		)
	default:
		return ""
	}
}
