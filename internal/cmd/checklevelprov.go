// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/slsa-framework/slsa-source-poc/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/pkg/policy"
)

type checkLevelProvOpts struct {
	commitOptions
	verifierOptions
	prevBundlePath       string
	prevCommit           string
	outputUnsignedBundle string
	outputSignedBundle   string
	useLocalPolicy       string
	allowMergeCommits    bool
}

func (clp *checkLevelProvOpts) Validate() error {
	return errors.Join([]error{
		clp.commitOptions.Validate(),
		clp.verifierOptions.Validate(),
	}...)
}

func (clp *checkLevelProvOpts) AddFlags(cmd *cobra.Command) {
	clp.commitOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(&clp.prevBundlePath, "prev_bundle_path", "", "Path to the file with the attestations for the previous commit (as an in-toto bundle).")
	cmd.PersistentFlags().StringVar(&clp.prevCommit, "prev_commit", "", "The commit to check.")
	cmd.PersistentFlags().StringVar(&clp.outputUnsignedBundle, "output_unsigned_bundle", "", "The path to write a bundle of unsigned attestations.")
	cmd.PersistentFlags().StringVar(&clp.outputSignedBundle, "output_signed_bundle", "", "The path to write a bundle of signed attestations.")
	cmd.PersistentFlags().StringVar(&clp.useLocalPolicy, "use_local_policy", "", "UNSAFE: Use the policy at this local path instead of the official one.")
	cmd.PersistentFlags().BoolVar(&clp.allowMergeCommits, "allow-merge-commits", false, "[EXPERIMENTAL] Allow merge commits in branch")
}

func addCheckLevelProv(parentCmd *cobra.Command) {
	opts := &checkLevelProvOpts{}

	checklevelprovCmd := &cobra.Command{
		Use:   "checklevelprov",
		Short: "Checks the given commit against policy using & creating provenance",
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
			return doCheckLevelProv(opts)
		},
	}

	opts.AddFlags(checklevelprovCmd)
	parentCmd.AddCommand(checklevelprovCmd)
}

func doCheckLevelProv(checkLevelProvArgs *checkLevelProvOpts) error {
	ghconnection := ghcontrol.NewGhConnection(checkLevelProvArgs.owner, checkLevelProvArgs.repository, ghcontrol.BranchToFullRef(checkLevelProvArgs.branch)).WithAuthToken(githubToken)
	ghconnection.Options.AllowMergeCommits = checkLevelProvArgs.allowMergeCommits
	ctx := context.Background()

	prevCommit := checkLevelProvArgs.prevCommit
	var err error
	if prevCommit == "" {
		prevCommit, err = ghconnection.GetPriorCommit(ctx, checkLevelProvArgs.commit)
		if err != nil {
			return err
		}
	}

	pa := attest.NewProvenanceAttestor(ghconnection, getVerifier(&checkLevelProvArgs.verifierOptions))
	prov, err := pa.CreateSourceProvenance(ctx, checkLevelProvArgs.prevBundlePath, checkLevelProvArgs.commit, prevCommit, ghconnection.GetFullRef())
	if err != nil {
		return err
	}

	// check p against policy
	pe := policy.NewPolicyEvaluator()
	pe.UseLocalPolicy = checkLevelProvArgs.useLocalPolicy
	verifiedLevels, policyPath, err := pe.EvaluateSourceProv(ctx, checkLevelProvArgs.GetRepository(), checkLevelProvArgs.GetBranch(), prov)
	if err != nil {
		return err
	}

	// create vsa
	unsignedVsa, err := attest.CreateUnsignedSourceVsa(ghconnection.GetRepoUri(), ghconnection.GetFullRef(), checkLevelProvArgs.commit, verifiedLevels, policyPath)
	if err != nil {
		return err
	}

	unsignedProv, err := protojson.Marshal(prov)
	if err != nil {
		return err
	}

	// Store both the unsigned provenance and vsa
	switch {
	case checkLevelProvArgs.outputUnsignedBundle != "":
		f, err := os.OpenFile(checkLevelProvArgs.outputUnsignedBundle, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644) //nolint:gosec
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck

		if _, err := f.WriteString(string(unsignedProv) + "\n" + unsignedVsa + "\n"); err != nil {
			return fmt.Errorf("writing signed bundle: %w", err)
		}
	case checkLevelProvArgs.outputSignedBundle != "":
		f, err := os.OpenFile(checkLevelProvArgs.outputSignedBundle, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644) //nolint:gosec
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck

		signedProv, err := attest.Sign(string(unsignedProv))
		if err != nil {
			return err
		}

		signedVsa, err := attest.Sign(unsignedVsa)
		if err != nil {
			return err
		}

		if _, err := f.WriteString(signedProv + "\n" + signedVsa + "\n"); err != nil {
			return fmt.Errorf("writing bundle data: %w", err)
		}
	default:
		log.Printf("unsigned prov: %s\n", unsignedProv)
		log.Printf("unsigned vsa: %s\n", unsignedVsa)
	}
	fmt.Print(verifiedLevels)
	return nil
}
