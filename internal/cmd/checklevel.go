// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/policy"
	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

type checkLevelOpts struct {
	commitOptions
	outputVsa, outputUnsignedVsa, useLocalPolicy string
	allowMergeCommits                            bool
}

func (clo *checkLevelOpts) Validate() error {
	errs := []error{
		clo.commitOptions.Validate(),
	}

	return errors.Join(errs...)
}

func (clo *checkLevelOpts) AddFlags(cmd *cobra.Command) {
	clo.commitOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(&clo.outputVsa, "output_vsa", "", "The path to write a signed VSA with the determined level.")
	cmd.PersistentFlags().StringVar(&clo.outputUnsignedVsa, "output_unsigned_vsa", "", "The path to write an unsigned vsa with the determined level.")
	cmd.PersistentFlags().StringVar(&clo.useLocalPolicy, "use_local_policy", "", "UNSAFE: Use the policy at this local path instead of the official one.")
	cmd.PersistentFlags().BoolVar(&clo.allowMergeCommits, "allow-merge-commits", false, "[EXPERIMENTAL] Allow merge commits in branch.")
}

func addCheckLevel(parentCmd *cobra.Command) {
	opts := checkLevelOpts{}

	checklevelCmd := &cobra.Command{
		Use:     "checklevel",
		GroupID: "assessment",
		Short:   "Determines the SLSA Source Level of the repo",
		Long: `Determines the SLSA Source Level of the repo.

This is meant to be run within the corresponding GitHub Actions workflow.`,
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
			if err := opts.Validate(); err != nil {
				return err
			}

			authenticator, err := CheckAuth()
			if err != nil {
				return err
			}

			// Create a new sourcetool object
			srctool, err := sourcetool.New(
				sourcetool.WithAuthenticator(authenticator),
				sourcetool.WithAllowMergeCommits(opts.allowMergeCommits),
			)
			if err != nil {
				return err
			}

			controlStatus, err := srctool.GetBranchControlsAtCommit(cmd.Context(), opts.GetBranch(), &models.Commit{SHA: opts.commit})
			if err != nil {
				return err
			}

			pe := policy.NewPolicyEvaluator()
			pe.UseLocalPolicy = opts.useLocalPolicy
			verifiedLevels, policyPath, err := pe.EvaluateControl(cmd.Context(), opts.GetRepository(), opts.GetBranch(), controlStatus)
			if err != nil {
				return err
			}
			for _, level := range verifiedLevels {
				if slsa.IsSlsaSourceLevel(level) {
					fmt.Print(level)
					break
				}
			}

			unsignedVsa, err := attest.CreateUnsignedSourceVsa(
				opts.GetBranch(), opts.GetCommit(), verifiedLevels, policyPath,
			)
			if err != nil {
				return err
			}
			if opts.outputUnsignedVsa != "" {
				if err := os.WriteFile(opts.outputUnsignedVsa, []byte(unsignedVsa), 0o644); err != nil { //nolint:gosec
					return err
				}
			}

			if opts.outputVsa != "" {
				// This will output in the sigstore bundle format.
				signedVsa, err := attest.Sign(unsignedVsa)
				if err != nil {
					return err
				}
				err = os.WriteFile(opts.outputVsa, []byte(signedVsa), 0o644) //nolint:gosec
				if err != nil {
					return err
				}
			}

			return nil
		},
	}
	opts.AddFlags(checklevelCmd)
	parentCmd.AddCommand(checklevelCmd)
}
