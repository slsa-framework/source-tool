// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/policy"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
)

var w = color.New(color.FgHiWhite, color.BgBlack).SprintFunc()

type repoOptions struct {
	owner      string
	repository string
}

func (ro *repoOptions) Validate() error {
	errs := []error{}
	if ro.owner == "" {
		errs = append(errs, errors.New("repository owner not set"))
	}
	if ro.repository == "" {
		errs = append(errs, errors.New(""))
	}
	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (ro *repoOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&ro.repository, "repository", "", "name of the repository",
	)

	cmd.PersistentFlags().StringVar(
		&ro.owner, "owner", "", "user or oganization that owns the repo",
	)
}

func (bo *branchOptions) Validate() error {
	errs := []error{}
	errs = append(errs, bo.repoOptions.Validate())

	if bo.branch == "" {
		return errors.New("branch not set")
	}
	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (bo *branchOptions) AddFlags(cmd *cobra.Command) {
	bo.repoOptions.AddFlags(cmd)

	cmd.PersistentFlags().StringVar(
		&bo.branch, "branch", "", "name of the branch",
	)
}

type branchOptions struct {
	repoOptions
	branch string
}

// statusOptions
type statusOptions struct {
	branchOptions
	commit string
}

// Validate checks the options
func (so *statusOptions) Validate() error {
	errs := []error{}
	errs = append(errs, so.branchOptions.Validate())

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (so *statusOptions) AddFlags(cmd *cobra.Command) {
	so.branchOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(
		&so.commit, "commit", "", "commit to check",
	)
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
		Use:           "status",
		SilenceUsage:  false,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate the options
			if err := opts.Validate(); err != nil {
				return err
			}

			cmd.SilenceUsage = true

			ctx := context.Background()
			ghc := ghcontrol.NewGhConnection(opts.owner, opts.repository, opts.branch)

			// If we didn't get a commit, assume HEAD
			if opts.commit == "" {
				commitSha, err := ghc.GetLatestCommit(ctx, opts.branch)
				if err != nil {
					return fmt.Errorf("fetching latest commit hash: %w", err)
				}
				opts.commit = commitSha
			}

			// Get the active controls
			activeControls, err := ghc.GetBranchControls(ctx, opts.commit, ghcontrol.BranchToFullRef(opts.branch))
			if err != nil {
				return fmt.Errorf("checking status: %w", err)
			}

			activeLabels := []string{}
			for _, c := range activeControls.Controls {
				activeLabels = append(activeLabels, string(c.Name))
			}

			// We need to manually check for PROVENANCE_AVAILABLE
			attestor := attest.NewProvenanceAttestor(
				ghcontrol.NewGhConnection(opts.owner, opts.repository, opts.branch),
				attest.GetDefaultVerifier(),
			)

			// Fetch the attestation, if found then add the control
			attestation, _, err := attestor.GetProvenance(ctx, opts.commit, "refs/heads/"+opts.branch)
			if err != nil {
				return fmt.Errorf("attempting to read provenance from commit: %w", err)
			}
			if attestation != nil {
				activeLabels = append(activeLabels, "PROVENANCE_AVAILABLE")
			}

			// Check if there is a policy:
			pcy, _, err := policy.NewPolicyEvaluator().GetPolicy(ctx, ghc)
			if err != nil {
				return fmt.Errorf("checking if the repository has a policy %w", err)
			}

			// Compute the maximum level possible:
			var toplevel slsa.SlsaSourceLevel
			for _, level := range []slsa.SlsaSourceLevel{
				slsa.SlsaSourceLevel1, slsa.SlsaSourceLevel2,
				slsa.SlsaSourceLevel3, slsa.SlsaSourceLevel4,
			} {
				if met, _ := level.MetByControls(slsa.StringsToControlNames(activeLabels)); met {
					toplevel = level
				}
			}

			title := fmt.Sprintf("SLSA Source Status for %s/%s", opts.owner, opts.repository)
			fmt.Printf("")
			fmt.Println(w(title))
			fmt.Println(strings.Repeat("=", len(title)))

			for _, c := range slsa.ControlNames {
				fmt.Printf("%-35s  ", c)
				if slices.Contains(activeLabels, string(c)) {
					fmt.Println("✅")
				} else {
					fmt.Println("🚫")
				}
			}

			fmt.Println("")
			fmt.Printf("%-35s  ", "Repo policy found:")
			if pcy == nil {
				fmt.Println("🚫")
			} else {
				fmt.Println("✅")
			}
			fmt.Println("")

			fmt.Println(w("Current SLSA Source level: " + toplevel))
			fmt.Println("")

			return nil
		},
	}
	opts.AddFlags(statusCmd)
	parentCmd.AddCommand(statusCmd)
}
