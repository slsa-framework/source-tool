// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/slsa-source-poc/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/pkg/policy"
	"github.com/slsa-framework/slsa-source-poc/pkg/slsa"
	"github.com/slsa-framework/slsa-source-poc/pkg/sourcetool"
)

var (
	w  = color.New(color.FgHiWhite, color.BgBlack).SprintFunc()
	w2 = color.New(color.Faint, color.FgWhite, color.BgBlack).SprintFunc()
)

// statusOptions
type statusOptions struct {
	commitOptions
}

// Validate checks the options
func (so *statusOptions) Validate() error {
	errs := []error{}
	errs = append(errs, so.commitOptions.Validate())

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (so *statusOptions) AddFlags(cmd *cobra.Command) {
	so.commitOptions.AddFlags(cmd)
}

// TODO(puerco): Most of the logic in this subcommand (except maybe the output)
// will be moved to a sourcetool object in the future to consolidate it into
// a reusable library.
func addStatus(parentCmd *cobra.Command) {
	opts := &statusOptions{}
	statusCmd := &cobra.Command{
		Short: "Check the SLSA Source status of a repo/branch",
		Long: `
sourcetool status: Check the SLSA Source status of a repo/branch

The status subcommand reads the current controls enabled for a branch
and reports the SLSA source level that the repository can claim. This
command is intended to help maintainers implementing SLSA controls
understand the next steps to secure their repos and progress in their
SLSA journey. 
`,
		Use:           "status [flags] owner/repo@branch",
		SilenceUsage:  false,
		SilenceErrors: true,
		Example: `Check the SLSA tooling status on a repository:
sourcetool status myorg/myrepo

A branch other than the default can be specified by appending it to
the repository slug:

sourcetool status myorg/myrepo@mybranch
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
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
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate the options
			if err := opts.Validate(); err != nil {
				return err
			}

			cmd.SilenceUsage = true

			authenticator, err := CheckAuth()
			if err != nil {
				return err
			}

			// Create a new sourcetool object
			srctool, err := sourcetool.New(
				sourcetool.WithAuthenticator(authenticator),
			)
			if err != nil {
				return err
			}

			// Get the active repository controls
			controls, err := srctool.GetBranchControls(opts.GetRepository(), opts.GetBranch())
			if err != nil {
				return fmt.Errorf("fetching active controls: %w", err)
			}

			// Compute the maximum level possible:
			toplevel := policy.ComputeEligibleSlsaLevel(*controls.GetActiveControls())

			title := fmt.Sprintf(
				"\nSLSA Source Status for %s/%s@%s", opts.owner, opts.repository,
				ghcontrol.BranchToFullRef(opts.branch),
			)

			fmt.Println(w(title))
			fmt.Println(strings.Repeat("=", len(title)))

			var policyControlStatus *slsa.ControlStatus
			for _, c := range controls.Controls {
				if c.Name == slsa.PolicyAvailable {
					policyControlStatus = &c
					continue
				}
				fmt.Printf("%-35s  ", c.Name)
				switch c.State {
				case slsa.StateActive:
					fmt.Println("✅")
				case slsa.StateInProgress:
					fmt.Print("⏳")
					if c.Message != "" {
						fmt.Print(w2(c.Message))
					}
					fmt.Println()
				case slsa.StateNotEnabled:
					fmt.Println("🚫")
				}
			}

			fmt.Println()
			if policyControlStatus != nil {
				fmt.Printf("%-35s  ", "Repo policy found:")
				switch policyControlStatus.State {
				case slsa.StateActive:
					fmt.Println("✅")
				case slsa.StateNotEnabled:
					fmt.Println("🚫")
				case slsa.StateInProgress:
					fmt.Print("⏳")
					if policyControlStatus.Message != "" {
						fmt.Printf(" (%s)", policyControlStatus.Message)
					}
					fmt.Println()
				}
				fmt.Println()
			}

			fmt.Println(w("Current SLSA Source level: " + toplevel))
			fmt.Println("")
			titled := false
			for _, status := range controls.Controls {
				if status.RecommendedAction == nil {
					continue
				}

				// Suggest creating the policy but only when reaching SLSA3+
				if status.Name == slsa.PolicyAvailable && !slsa.IsLevelHigherOrEqualTo(toplevel, slsa.SlsaSourceLevel3) {
					continue
				}

				if !titled {
					fmt.Println(w2("✨ Recommended actions:"))
					titled = true
				}

				fmt.Printf(" - %s\n", status.RecommendedAction.Message)
				if status.RecommendedAction.Command != "" {
					fmt.Printf("   > %s\n", status.RecommendedAction.Command)
				}
				fmt.Println()
			}

			return nil
		},
	}
	opts.AddFlags(statusCmd)
	parentCmd.AddCommand(statusCmd)
}
