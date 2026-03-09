// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/policy"
	"github.com/slsa-framework/source-tool/pkg/sourcetool"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

type checkTagOptions struct {
	repoOptions
	verifierOptions
	commitOptions
	tagName            string
	actor              string
	outputSignedBundle string
	useLocalPolicy     string
	vsaRetries         uint8
}

func (cto *checkTagOptions) Validate() error {
	errs := []error{
		cto.commitOptions.Validate(),
		cto.repoOptions.Validate(),
		cto.verifierOptions.Validate(),
	}
	return errors.Join(errs...)
}

func (cto *checkTagOptions) AddFlags(cmd *cobra.Command) {
	cto.repoOptions.AddFlags(cmd)
	cto.verifierOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(&cto.commit, "commit", "", "The commit to check - required.")
	cmd.PersistentFlags().StringVar(&cto.tagName, "tag_name", "", "The name of the new tag - required.")
	cmd.PersistentFlags().StringVar(&cto.actor, "actor", "", "The username of the actor that pushed the tag.")
	cmd.PersistentFlags().StringVar(&cto.outputSignedBundle, "output_signed_bundle", "", "The path to write a bundle of signed attestations.")
	cmd.PersistentFlags().StringVar(&cto.useLocalPolicy, "use_local_policy", "", "UNSAFE: Use the policy at this local path instead of the official one.")
	cmd.PersistentFlags().Uint8Var(&cto.vsaRetries, "retries", 3, "Number of times to retry fetching the commit's VSA")
}

func (cto *checkTagOptions) GetTag() *models.Tag {
	return &models.Tag{
		Name:   cto.tagName,
		Commit: cto.GetCommit(),
	}
}

func addCheckTag(parentCmd *cobra.Command) {
	opts := &checkTagOptions{}

	checktagCmd := &cobra.Command{
		Use:     "checktag",
		GroupID: "assessment",
		Short:   "Checks to see if the tag operation should be allowed and issues a VSA",
		RunE: func(cmd *cobra.Command, args []string) error {
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

			// Create tag provenance.
			// pa.Options.VsaRetries = opts.vsaRetries // Retry fetching the commit's VSA

			prov, err := srctool.Attester().CreateTagProvenance(cmd.Context(), opts.GetBranch(), opts.GetTag(), opts.actor)
			if err != nil {
				return fmt.Errorf("creating tag provenance metadata: %w", err)
			}

			// check p against policy
			pe := policy.NewPolicyEvaluator()
			pe.UseLocalPolicy = opts.useLocalPolicy
			verifiedLevels, policyPath, err := pe.EvaluateTagProv(cmd.Context(), opts.GetRepository(), prov)
			if err != nil {
				return fmt.Errorf("evaluating the tag provenance metadata: %w", err)
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

			if opts.outputSignedBundle != "" {
				f, err := os.OpenFile(opts.outputSignedBundle, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644) //nolint:gosec
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
					return fmt.Errorf("writing bundledata: %w", err)
				}
			} else {
				log.Printf("unsigned prov: %s\n", unsignedProv)
				log.Printf("unsigned vsa: %s\n", unsignedVsa)
			}
			fmt.Print(verifiedLevels)
			return nil
		},
	}

	opts.AddFlags(checktagCmd)
	parentCmd.AddCommand(checktagCmd)
}
