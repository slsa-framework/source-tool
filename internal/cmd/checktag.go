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

type checkTagOptions struct {
	repoOptions
	verifierOptions
	commit             string
	tagName            string
	actor              string
	outputSignedBundle string
	useLocalPolicy     string
}

func (cto *checkTagOptions) Validate() error {
	errs := []error{
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
}

func addCheckTag(parentCmd *cobra.Command) {
	opts := &checkTagOptions{}

	checktagCmd := &cobra.Command{
		Use:   "checktag",
		Short: "Checks to see if the tag operation should be allowed and issues a VSA",
		RunE: func(cmd *cobra.Command, args []string) error {
			return doCheckTag(opts)
		},
	}

	opts.AddFlags(checktagCmd)
	parentCmd.AddCommand(checktagCmd)
}

func doCheckTag(args *checkTagOptions) error {
	ghconnection := ghcontrol.NewGhConnection(args.owner, args.repository, ghcontrol.TagToFullRef(args.tagName)).WithAuthToken(githubToken)
	ctx := context.Background()
	verifier := getVerifier(&args.verifierOptions)

	// Create tag provenance.
	pa := attest.NewProvenanceAttestor(ghconnection, verifier)
	prov, err := pa.CreateTagProvenance(ctx, args.commit, ghcontrol.TagToFullRef(args.tagName), args.actor)
	if err != nil {
		return err
	}

	// check p against policy
	pe := policy.NewPolicyEvaluator()
	pe.UseLocalPolicy = args.useLocalPolicy
	verifiedLevels, policyPath, err := pe.EvaluateTagProv(ctx, args.GetRepository(), prov)
	if err != nil {
		return err
	}

	// create vsa
	unsignedVsa, err := attest.CreateUnsignedSourceVsa(ghconnection.GetRepoUri(), ghconnection.GetFullRef(), args.commit, verifiedLevels, policyPath)
	if err != nil {
		return err
	}

	unsignedProv, err := protojson.Marshal(prov)
	if err != nil {
		return err
	}

	if args.outputSignedBundle != "" {
		f, err := os.OpenFile(args.outputSignedBundle, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644) //nolint:gosec
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
}
