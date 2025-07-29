// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"slices"

	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/util"

	"github.com/slsa-framework/slsa-source-poc/pkg/sourcetool"
	"github.com/slsa-framework/slsa-source-poc/pkg/sourcetool/models"
)

type setupOpts struct {
	branchOptions
	policyRepo  string
	userForkOrg string
	enforce     bool
	interactive bool
}

func (so *setupOpts) AddFlags(cmd *cobra.Command) {
	so.branchOptions.AddFlags(cmd)

	cmd.PersistentFlags().BoolVar(
		&so.enforce, "enforce", false, "create enforcement rules",
	)
	cmd.PersistentFlags().StringVar(
		&so.userForkOrg, "user-fork", "", "GitHub organization to look for forks of repos (for pull requests)",
	)
	// Uncomment when we support custom policy repos
	// cmd.PersistentFlags().StringVar(
	// 	&so.policyRepo, "policy-repo", fmt.Sprintf("%s/%s", policy.SourcePolicyRepoOwner, policy.SourcePolicyRepo), "repository to store the SLSA source policy",
	// )

	cmd.PersistentFlags().BoolVar(
		&so.interactive, "interactive", true, "confirm before performing changes",
	)
}

// Validate checks the options in context with arguments
func (so *setupOpts) Validate() error {
	errs := []error{
		so.branchOptions.Validate(),
	}
	return errors.Join(errs...)
}

func addSetup(parentCmd *cobra.Command) {
	setupCmd := &cobra.Command{
		Short: "configure SLSA source features in a repository",
		Long: fmt.Sprintf(`
%s %s

The setup subcommands can be used to protect a repository with the
SLSA Source tooling by automatically configuring the required security
controls in a repository.

The setup family has two subcommands:

%s
A "one shot" setup process enabling all the security controls required
at once. This is ideal for new repositories or when you are sure the
changes will not disrupt existing repositories.

%s
Enables fine-grained control when configuring security features in a 
repository. The setup control subcommand can configure each security
control individually.

`, w("sourcetool setup:"), w2("configure SLSA source controls on a repository"),
			w("sourcetool setup repo"), w("sourcetool setup controls")),
		Use:           "setup",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	AddSetupRepo(setupCmd)
	AddSetupControls(setupCmd)
	parentCmd.AddCommand(setupCmd)
}

func AddSetupRepo(parent *cobra.Command) {
	opts := &setupOpts{}
	setupRepoCmd := &cobra.Command{
		Short: "configure all the SLSA source features in a repository",
		Long: `The setup repo subcommand is a "one shot" setup process enabling all
the security controls required to get a repository to SLSA Source level 3.

This command is ideal for new repositories or when you are sure the implemented
changes will not disrupt existing workflows.

To run this command make sure sourcetool is authorized on the repository
(try sourcetool auth whoami ) or export a GitHub token as an environment
variable called GITHUB_TOKEN. The token needs admin permissions on the repo
to configure the branch rules.

If the SLSA controls are already enforce in the repository they will be left
untouched.

Alternatively, to enable each control individually use: sourcetool setup controls.

`,
		Use:           "repo owner/repo",
		SilenceUsage:  false,
		SilenceErrors: true,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				if err := opts.ParseLocator(args[0]); err != nil {
					return err
				}
			}

			// Validate early the repository options to provide a more
			// useful message to the user
			if err := opts.repoOptions.Validate(); err != nil {
				return err
			}

			if err := opts.EnsureDefaults(); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if err := opts.Validate(); err != nil {
				return err
			}

			// At this point options are valid, no help needed.
			cmd.SilenceUsage = true

			authenticator, err := CheckAuth()
			if err != nil {
				return err
			}

			// Create a new sourcetool object
			srctool, err := sourcetool.New(
				sourcetool.WithAuthenticator(authenticator),
				sourcetool.WithEnforce(opts.enforce),
				sourcetool.WithUserForkOrg(opts.userForkOrg),
				sourcetool.WithPolicyRepo(opts.policyRepo),
			)
			if err != nil {
				return err
			}

			if opts.interactive {
				fmt.Printf(`
sourcetool is about to perform the following actions on your behalf:

  - %s.
  - %s.
  - %s.

`,
					srctool.ControlConfigurationDescr(opts.GetBranch(), models.CONFIG_TAG_RULES),
					srctool.ControlConfigurationDescr(opts.GetBranch(), models.CONFIG_GEN_PROVENANCE),
					srctool.ControlConfigurationDescr(opts.GetBranch(), models.CONFIG_BRANCH_RULES),
				)

				_, s, err := util.Ask("Type 'yes' if you want to continue?", "yes|no|no", 3)
				if err != nil {
					return err
				}

				if !s {
					fmt.Println("Cancelled.")
					return nil
				}
			}

			err = srctool.OnboardRepository(
				opts.GetBranch().Repository, []*models.Branch{opts.GetBranch()},
			)
			if err != nil {
				return fmt.Errorf("onboarding repo: %w", err)
			}

			fmt.Println()
			fmt.Println(w("✅ Controls have been configured successfully."))
			fmt.Println()
			fmt.Printf("Please run %s\n", w2("sourcetool status "+opts.GetRepository().Path))
			fmt.Println("to check the status of the new controls and for the next steps.")
			fmt.Println()

			return nil
		},
	}
	opts.AddFlags(setupRepoCmd)
	parent.AddCommand(setupRepoCmd)
}

type setupCtlOpts struct {
	setupOpts
	configs []string
}

func (so *setupCtlOpts) AddFlags(cmd *cobra.Command) {
	so.setupOpts.AddFlags(cmd)

	cmd.PersistentFlags().StringSliceVar(
		&so.configs, "config", []string{}, fmt.Sprintf("control to configure %+v", sourcetool.ControlConfigurations),
	)
}

// Validate checks the options in context with arguments
func (so *setupCtlOpts) Validate() error {
	errs := []error{
		so.setupOpts.Validate(),
	}
	if len(so.configs) == 0 {
		errs = append(errs, fmt.Errorf("at least one config value must be set %v", sourcetool.ControlConfigurations))
	}
	for _, c := range so.configs {
		if !slices.Contains(sourcetool.ControlConfigurations, models.ControlConfiguration(c)) {
			errs = append(errs, fmt.Errorf("unknown configuration: %q", c))
		}
	}
	return errors.Join(errs...)
}

func AddSetupControls(parent *cobra.Command) {
	opts := &setupCtlOpts{}
	setupControlsCmd := &cobra.Command{
		Short: "configure specific SLSA controls in a repository",
		Long: fmt.Sprintf(`
%s %s

The setup controls subcommand configures the specified SLSA security
controls in a repository. As opposed to "setup repo", this subcommand lets you
configure each security control individually.

To use this subcommand you need to export a GitHub token as an environment
variable called GITHUB_TOKEN. To configure the branch rules, the token needs
admin permissions on the repo. For the other configuration it is only required
as an identity source.

The values for --config are as follows:

%s
Configures push and delete branch protection in the repository, required to reach
SLSA source level 2+. 

%s
Configures udpate, push and delete protection for all tags in the repository,
this is required to reach SLSA source level 2+. 

%s
Opens a pull request in the repository to add the provenance generation workflow
after every push. 

%s
Opens a pull request on the SLSA policy repository to check in a SLSA Source 
policy for the repository.

Setting up repository forks

The controls that open pull requests require that you have a fork of the
repositories. Make sure you have a fork of the SLSA source policy repo and
a fork of the repository you want to protect.

`, w("sourcetool setup controls"), w2("configure a repository for SLSA source"),
			w2(models.CONFIG_BRANCH_RULES), w2(models.CONFIG_TAG_RULES),
			w2(models.CONFIG_GEN_PROVENANCE), w2(models.CONFIG_POLICY)),
		Use:           "controls owner/repo --config=CONTROL1 --config=CONTROL2",
		SilenceUsage:  false,
		SilenceErrors: true,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				if err := opts.ParseLocator(args[0]); err != nil {
					return err
				}
			}

			// Validate early the repository options to provide a more
			// useful message to the user
			if err := opts.repoOptions.Validate(); err != nil {
				return err
			}

			if err := opts.EnsureDefaults(); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if err := opts.Validate(); err != nil {
				return err
			}

			authenticator, err := CheckAuth()
			if err != nil {
				return err
			}

			// At this point options are valid, no help needed.
			cmd.SilenceUsage = true

			// Create a new sourcetool object
			srctool, err := sourcetool.New(
				sourcetool.WithAuthenticator(authenticator),
				// Uncomment when we support other policy repo
				// sourcetool.WithPolicyRepo(opts.policyRepo),
				sourcetool.WithUserForkOrg(opts.userForkOrg),
				sourcetool.WithEnforce(opts.enforce),
			)
			if err != nil {
				return err
			}
			cs := []models.ControlConfiguration{}
			if opts.interactive {
				// Check if we need the policy fork
				if slices.Contains(opts.configs, string(models.CONFIG_POLICY)) {
					if err := ensureOrCreatePolicyFork(srctool); err != nil {
						return err
					}
				}

				fmt.Println()
				fmt.Println("sourcetool is about to perform the following actions on your behalf:")
				fmt.Println()

				for _, c := range opts.configs {
					cs = append(cs, models.ControlConfiguration(c))
					fmt.Printf("  - %s.\n", srctool.ControlConfigurationDescr(opts.GetBranch(), models.ControlConfiguration(c)))
				}
				fmt.Println("")

				_, s, err := util.Ask("Type 'yes' if you want to continue?", "yes|no|no", 3)
				if err != nil {
					return err
				}

				if !s {
					fmt.Println("Cancelled.")
					return nil
				}
			} else {
				for _, c := range opts.configs {
					cs = append(cs, models.ControlConfiguration(c))
				}
			}
			err = srctool.ConfigureControls(
				opts.GetBranch().Repository, []*models.Branch{opts.GetBranch()}, cs,
			)
			if err != nil {
				// if strings.Contains(err.Error(), models.ErrProtectionAlreadyInPlace.Error()) {
				if errors.Is(err, models.ErrProtectionAlreadyInPlace) {
					fmt.Printf("\n   ℹ️  Controls already enabled on %s\n\n", opts.GetRepository().Path)
					return nil
				}
				return fmt.Errorf("configuring controls: %w", err)
			}

			return nil
		},
	}
	opts.AddFlags(setupControlsCmd)
	parent.AddCommand(setupControlsCmd)
}
