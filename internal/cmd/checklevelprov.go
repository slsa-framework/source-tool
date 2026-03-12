// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/sourcetool"
)

type pushOptions struct {
	pushLocation     []string
	pushRepositories []string
}

// Support repository types to push
var supportedPushRepos = []string{"github", "note"}

// Validate checks the push options
func (po *pushOptions) Validate() error {
	errs := []error{}
	if len(po.pushLocation) == 0 {
		return nil
	}

	// Check the supported schemes
	for _, repouri := range po.pushLocation {
		if slices.Contains(supportedPushRepos, repouri) {
			continue
		}

		s, _, ok := strings.Cut(repouri, ":")
		if ok && slices.Contains(supportedPushRepos, s) {
			continue
		}

		errs = append(errs, fmt.Errorf("unsupported repository type: %q", repouri))
	}

	return errors.Join(errs...)
}

func (po *pushOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringSliceVar(&po.pushLocation, "push", []string{}, fmt.Sprintf("Push signed attestations to storage %v", supportedPushRepos))
}

type checkLevelProvOpts struct {
	revisionOpts
	verifierOptions
	pushOptions
	allowMergeCommitsOptions
	prevBundlePath       string
	prevCommit           string
	outputUnsignedBundle string
	outputSignedBundle   string
	useLocalPolicy       string
}

func (clp *checkLevelProvOpts) Validate() error {
	return errors.Join([]error{
		clp.revisionOpts.Validate(),
		clp.verifierOptions.Validate(),
	}...)
}

func (clp *checkLevelProvOpts) AddFlags(cmd *cobra.Command) {
	clp.revisionOpts.AddFlags(cmd)
	clp.pushOptions.AddFlags(cmd)
	clp.allowMergeCommitsOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(&clp.prevBundlePath, "prev_bundle_path", "", "Path to the file with the attestations for the previous commit (as an in-toto bundle).")
	cmd.PersistentFlags().StringVar(&clp.prevCommit, "prev_commit", "", "The commit to check.")
	cmd.PersistentFlags().StringVar(&clp.outputUnsignedBundle, "output_unsigned_bundle", "", "The path to write a bundle of unsigned attestations.")
	cmd.PersistentFlags().StringVar(&clp.outputSignedBundle, "output_signed_bundle", "", "The path to write a bundle of signed attestations.")
	cmd.PersistentFlags().StringVar(&clp.useLocalPolicy, "use_local_policy", "", "UNSAFE: Use the policy at this local path instead of the official one.")
}

func addCheckLevelProv(parentCmd *cobra.Command) {
	opts := &checkLevelProvOpts{}

	checklevelprovCmd := &cobra.Command{
		Use:     "checklevelprov",
		GroupID: "assessment",
		Example: `sourcetool checklevelprov owner/repo --push=note`,
		Short:   "Checks the given commit against policy using & creating provenance",
		Long: `Checks the given commit against policy using & creating provenance.

The checklevelprov subcommand computes the SLSA level of a commit by retrieving
the source policy of the repository and the provenance of its parent revision.

Based on the verification, the subcommand generates the commit's provenance
attestation and a verification summary attestation which can optionally be
signed using Sigstore.

The signed attestations can be pushed to a storage repository: either to the
GitHub attestations API (--push=github) or stored and in the commit's git notes
and pushed to its remote (--push=note).
`,
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

	opts.AddFlags(checklevelprovCmd)
	parentCmd.AddCommand(checklevelprovCmd)
}
