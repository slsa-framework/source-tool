// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/sourcetool"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

type checkTagOptions struct {
	verifierOptions
	revisionOpts
	pushOptions
	allowMergeCommitsOptions
	actor                string
	outputSignedBundle   string
	outputUnsignedBundle string
	useLocalPolicy       string
	vsaRetries           uint8
}

func (cto *checkTagOptions) Validate() error {
	errs := []error{
		cto.revisionOpts.Validate(),
		cto.verifierOptions.Validate(),
	}
	return errors.Join(errs...)
}

func (cto *checkTagOptions) AddFlags(cmd *cobra.Command) {
	cto.revisionOpts.AddFlags(cmd)
	cto.verifierOptions.AddFlags(cmd)
	cto.pushOptions.AddFlags(cmd)
	cto.allowMergeCommitsOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(&cto.actor, "actor", "", "The username of the actor that pushed the tag.")
	cmd.PersistentFlags().StringVar(&cto.outputSignedBundle, "output_signed_bundle", "", "The path to write a bundle of signed attestations.")
	cmd.PersistentFlags().StringVar(&cto.outputUnsignedBundle, "output_unsigned_bundle", "", "The path to write a bundle of unsigned attestations.")
	cmd.PersistentFlags().StringVar(&cto.useLocalPolicy, "use_local_policy", "", "UNSAFE: Use the policy at this local path instead of the official one.")
	cmd.PersistentFlags().Uint8Var(&cto.vsaRetries, "retries", 3, "Number of times to retry fetching the commit's VSA")

	// Hidden alias for backwards compatibility with the old --tag_name flag.
	cmd.PersistentFlags().StringVar(&cto.tag, "tag_name", "", "Git tag within the repository")
	cmd.PersistentFlags().MarkHidden("tag_name") //nolint:errcheck,gosec
}

func addCheckTag(parentCmd *cobra.Command) {
	opts := &checkTagOptions{}

	checktagCmd := &cobra.Command{
		Use:     "checktag",
		GroupID: "assessment",
		Short:   "Checks to see if the tag operation should be allowed and issues a VSA",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				if err := opts.ParseLocator(args[0]); err != nil {
					return err
				}
			}

			if err := opts.repoOptions.Validate(); err != nil {
				return err
			}

			if err := opts.EnsureDefaults(); err != nil {
				return err
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Here we need to translate the CLI options to the sourcetool
			// options. Some of these will be deprecated as some point for
			// a more concise options set.
			signAttestation := false
			outputPath := ""

			switch {
			case opts.outputSignedBundle != "":
				outputPath = opts.outputSignedBundle
				signAttestation = true
			case opts.outputUnsignedBundle != "":
				outputPath = opts.outputUnsignedBundle
			}

			var githubStorer, notesStorer, pushAttestations bool
			switch {
			case slices.Contains(opts.pushLocation, "github"):
				pushAttestations = true
				githubStorer = true
			case slices.Contains(opts.pushLocation, "notes"):
				pushAttestations = true
				notesStorer = true
			case len(opts.pushRepositories) > 0:
				pushAttestations = true
			}

			rev := opts.GetRevision()
			if rev == nil {
				return errors.New("unable to get revision from configured options")
			}
			if _, ok := rev.(*models.Tag); !ok {
				return errors.New("revision is not a tag")
			}

			// Create the authenticator
			authenticator, err := CheckAuth()
			if err != nil {
				return err
			}

			// Initialize sourcetool
			srctool, err := sourcetool.New(
				sourcetool.WithAuthenticator(authenticator),
				sourcetool.WithAllowMergeCommits(opts.allowMergeCommits),
				sourcetool.WithNotesStorer(notesStorer),
				sourcetool.WithGithubStorer(githubStorer),
			)
			if err != nil {
				return fmt.Errorf("creating sourcetool: %w", err)
			}

			// Attest the commit passing the options
			verifiedLevels, err := srctool.AttestRevision(
				cmd.Context(), opts.GetBranch(), opts.GetRevision(),
				sourcetool.WithLocalPolicy(opts.useLocalPolicy),
				sourcetool.WithOutputPath(outputPath),
				sourcetool.WithSign(signAttestation),
				sourcetool.WithUseStdout(true),
				sourcetool.WithPush(pushAttestations),
			)
			if err != nil {
				return fmt.Errorf("attesting commit: %w", err)
			}

			fmt.Print(verifiedLevels.Levels())
			return nil
		},
	}

	opts.AddFlags(checktagCmd)
	parentCmd.AddCommand(checktagCmd)
}
