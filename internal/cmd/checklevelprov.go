// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/policy"
	"github.com/slsa-framework/source-tool/pkg/sourcetool"
)

type pushOptions struct {
	pushLocation []string
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
	commitOptions
	verifierOptions
	pushOptions
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
	clp.pushOptions.AddFlags(cmd)
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
			authenticator, err := CheckAuth()
			if err != nil {
				return err
			}

			// Create a new sourcetool object
			srctool, err := sourcetool.New(
				sourcetool.WithAuthenticator(authenticator),
				sourcetool.WithAllowMergeCommits(opts.allowMergeCommits),
				sourcetool.WithNotesStorer(slices.Contains(opts.pushLocation, "notes")),
				sourcetool.WithGithubStorer(slices.Contains(opts.pushLocation, "github")),
			)
			if err != nil {
				return fmt.Errorf("creating sourcetool: %w", err)
			}

			// Create the provenance attestation
			prov, err := srctool.Attester().CreateSourceProvenance(
				cmd.Context(), opts.GetBranch(), opts.GetCommit(),
			)
			if err != nil {
				return err
			}

			// check p against policy
			pe := policy.NewPolicyEvaluator()
			pe.UseLocalPolicy = opts.useLocalPolicy
			verifiedLevels, policyPath, err := pe.EvaluateSourceProv(cmd.Context(), opts.GetRepository(), opts.GetBranch(), prov)
			if err != nil {
				return err
			}

			// create vsa
			unsignedVsa, err := attest.CreateUnsignedSourceVsa(
				opts.GetBranch(), opts.GetCommit(), verifiedLevels, policyPath,
			)
			if err != nil {
				return err
			}

			unsignedProv, err := protojson.Marshal(prov)
			if err != nil {
				return err
			}

			// Store both the unsigned provenance and vsa
			switch {
			case opts.outputUnsignedBundle != "":
				f, err := os.OpenFile(opts.outputUnsignedBundle, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644) //nolint:gosec
				if err != nil {
					return err
				}
				defer f.Close() //nolint:errcheck

				if _, err := f.WriteString(string(unsignedProv) + "\n" + unsignedVsa + "\n"); err != nil {
					return fmt.Errorf("writing signed bundle: %w", err)
				}
			case opts.outputSignedBundle != "" || len(opts.pushLocation) > 0:
				var f *os.File
				if opts.outputSignedBundle != "" {
					f, err = os.OpenFile(opts.outputSignedBundle, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644) //nolint:gosec
					if err != nil {
						return err
					}
				}
				defer func() {
					if f != nil {
						f.Close() //nolint:errcheck,gosec
					}
				}()

				signedProv, err := attest.Sign(string(unsignedProv))
				if err != nil {
					return err
				}

				signedVsa, err := attest.Sign(unsignedVsa)
				if err != nil {
					return err
				}

				// If a file was specified, write the attestations
				if f != nil {
					if _, err := f.WriteString(signedProv + "\n" + signedVsa + "\n"); err != nil {
						return fmt.Errorf("writing bundle data: %w", err)
					}
				}
			default:
				log.Printf("unsigned prov: %s\n", unsignedProv)
				log.Printf("unsigned vsa: %s\n", unsignedVsa)
			}
			fmt.Print(verifiedLevels)
			return nil
		},
	}

	opts.AddFlags(checklevelprovCmd)
	parentCmd.AddCommand(checklevelprovCmd)
}
