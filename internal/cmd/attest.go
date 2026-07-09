// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/sourcetool"
)

type attestOptions struct {
	revisionOpts
	pushOptions
	allowMergeCommitsOptions
	provenance      bool
	vsa             bool
	sign            bool
	output          string
	useLocalPolicy  string
	silentDowngrade bool
}

func (ao *attestOptions) Validate() error {
	errs := []error{
		ao.revisionOpts.Validate(),
		ao.pushOptions.Validate(),
	}
	if !ao.provenance && !ao.vsa {
		errs = append(errs, errors.New("nothing to generate: enable --provenance and/or --vsa"))
	}
	return errors.Join(errs...)
}

func (ao *attestOptions) AddFlags(cmd *cobra.Command) {
	ao.revisionOpts.AddFlags(cmd)
	ao.pushOptions.AddFlags(cmd)
	ao.allowMergeCommitsOptions.AddFlags(cmd)
	cmd.PersistentFlags().BoolVar(&ao.provenance, "provenance", true, "write the provenance attestation")
	cmd.PersistentFlags().BoolVar(&ao.vsa, "vsa", true, "write the verification summary attestation (VSA)")
	cmd.PersistentFlags().BoolVar(&ao.sign, "sign", true, "sign the attestations")
	cmd.PersistentFlags().StringVar(&ao.output, "output", "", "path to write the attestation bundle (default: stdout)")
	cmd.PersistentFlags().StringVar(&ao.useLocalPolicy, "use-local-policy", "", "path to a local policy file to evaluate instead of the community policy")
	cmd.PersistentFlags().BoolVar(&ao.silentDowngrade, "silent-downgrade", false, "warn instead of failing when the achieved level is below the policy target")
}

func addAttest(parentCmd *cobra.Command) {
	opts := attestOptions{}
	attestCmd := &cobra.Command{
		Use:     "attest [flags] owner/repo[@ref]",
		GroupID: cmdGroupAttestation,
		Short:   "Generate the source attestations for a revision",
		Long: `Generate the SLSA source attestations for a revision.

attest creates the source provenance and the verification summary
attestation (VSA) for a commit or a tag. Use --provenance and --vsa to
select which of the two are written. When the VSA is disabled the
repository policy is not evaluated and only the provenance is produced.

The attestations are written to stdout as a JSONL bundle unless --output
is given, and can be pushed to storage with --push.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				if err := opts.ParseLocator(args[0]); err != nil {
					return err
				}
			}

			if err := opts.repoOptions.Validate(); err != nil {
				return err
			}

			return opts.EnsureDefaults()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return fmt.Errorf("validating options: %w", err)
			}

			var githubStorer, notesStorer, pushAttestations bool
			if slices.Contains(opts.pushLocation, pushRepoGithub) {
				pushAttestations = true
				githubStorer = true
			}
			if slices.Contains(opts.pushLocation, pushRepoNote) {
				pushAttestations = true
				notesStorer = true
			}

			authenticator, err := CheckAuth()
			if err != nil {
				return err
			}

			srctool, err := sourcetool.New(
				sourcetool.WithAuthenticator(authenticator),
				sourcetool.WithAllowMergeCommits(opts.allowMergeCommits),
				sourcetool.WithNotesStorer(notesStorer),
				sourcetool.WithGithubStorer(githubStorer),
			)
			if err != nil {
				return fmt.Errorf("creating sourcetool: %w", err)
			}

			result, err := srctool.AttestRevision(
				cmd.Context(), opts.GetBranch(), opts.GetRevision(),
				sourcetool.WithProvenance(opts.provenance),
				sourcetool.WithVSA(opts.vsa),
				sourcetool.WithSign(opts.sign),
				sourcetool.WithLocalPolicy(opts.useLocalPolicy),
				sourcetool.WithOutputPath(opts.output),
				sourcetool.WithUseStdout(opts.output == ""),
				sourcetool.WithPush(pushAttestations),
			)
			if err != nil {
				return fmt.Errorf("attesting revision: %w", err)
			}

			// The attestations are generated (and optionally pushed) regardless
			// of the policy outcome. When the achieved level is below the policy
			// target return exit code 2, or just a warning with --silent-downgrade.
			if result.Shortfall != nil {
				msg := fmt.Sprintf(
					"policy target level %s not met; achieved %s: %s",
					result.Shortfall.TargetLevel, result.Shortfall.AchievedLevel, result.Shortfall.Reason,
				)
				if opts.silentDowngrade {
					fmt.Fprintf(os.Stderr, "warning: %s\n", msg)
					return nil
				}
				return &exitError{code: 2, err: errors.New(msg)}
			}

			return nil
		},
	}
	opts.AddFlags(attestCmd)
	parentCmd.AddCommand(attestCmd)
}
