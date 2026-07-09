// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/sourcetool"
)

type getOptions struct {
	revisionOpts
	provenance      bool
	vsa             bool
	requireVerified bool
}

func (o *getOptions) Validate() error {
	errs := []error{o.revisionOpts.Validate()}
	if !o.provenance && !o.vsa {
		errs = append(errs, errors.New("nothing to get: enable --provenance and/or --vsa"))
	}
	return errors.Join(errs...)
}

func (o *getOptions) AddFlags(cmd *cobra.Command) {
	o.revisionOpts.AddFlags(cmd)
	cmd.PersistentFlags().BoolVar(&o.provenance, "provenance", true, "fetch the source provenance attestation")
	cmd.PersistentFlags().BoolVar(&o.vsa, "vsa", true, "fetch the verification summary attestation (VSA)")
	cmd.PersistentFlags().BoolVar(&o.requireVerified, "require-verified", false, "exit non-zero when a fetched attestation fails verification")
}

func addGet(parentCmd *cobra.Command) {
	opts := getOptions{}
	getCmd := &cobra.Command{
		Use:     "get [flags] owner/repo[@ref]",
		GroupID: cmdGroupVerification,
		Short:   "Fetch and print the attestations for a revision",
		Long: `Fetch and print the stored attestations for a revision.

get retrieves the source provenance and the verification summary
attestation (VSA) for a commit or a tag and prints them to stdout. Use
--provenance and --vsa to select which of the two are fetched.

Every attestation is verified: if verification fails, a message is
written to stderr but the attestation is still printed. Pass
--require-verified to exit non-zero when verification fails.`,
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

			authenticator, err := CheckAuth()
			if err != nil {
				return err
			}

			srctool, err := sourcetool.New(
				sourcetool.WithAuthenticator(authenticator),
			)
			if err != nil {
				return fmt.Errorf("creating sourcetool: %w", err)
			}

			fetched, err := srctool.GetRevisionAttestations(
				cmd.Context(), opts.GetBranch(), opts.GetRevision(), opts.provenance, opts.vsa,
			)
			if err != nil {
				return fmt.Errorf("fetching attestations: %w", err)
			}

			if len(fetched) == 0 {
				fmt.Fprintln(os.Stderr, "no attestations found for the revision")
				return nil
			}

			verificationFailed := false
			for _, att := range fetched {
				fmt.Printf("%s\n", string(att.Data))
				if att.VerifyErr != nil {
					verificationFailed = true
					fmt.Fprintf(os.Stderr, "warning: %s attestation failed verification: %v\n", att.PredicateType, att.VerifyErr)
				}
			}

			if verificationFailed && opts.requireVerified {
				return &exitError{code: 2, err: errors.New("one or more attestations failed verification")}
			}

			return nil
		},
	}
	opts.AddFlags(getCmd)
	parentCmd.AddCommand(getCmd)
}
