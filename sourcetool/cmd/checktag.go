/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/policy"
)

type CheckTagArgs struct {
	commit             string
	owner              string
	repo               string
	tagName            string
	actor              string
	outputSignedBundle string
	useLocalPolicy     string
}

var (
	checkTagArgs = &CheckTagArgs{}

	// checktagCmd represents the checktag command
	checktagCmd = &cobra.Command{
		Use:   "checktag",
		Short: "Checks to see if the tag operation should be allowed and issues a VSA",
		Run: func(cmd *cobra.Command, args []string) {
			if err := doCheckTag(checkTagArgs); err != nil {
				log.Fatal(err)
			}
		},
	}
)

func doCheckTag(args *CheckTagArgs) error {
	ghconnection := ghcontrol.NewGhConnection(args.owner, args.repo, ghcontrol.TagToFullRef(args.tagName)).WithAuthToken(githubToken)
	ctx := context.Background()
	verifier := getVerifier()

	// Create tag provenance.
	pa := attest.NewProvenanceAttestor(ghconnection, verifier)
	prov, err := pa.CreateTagProvenance(ctx, args.commit, ghcontrol.TagToFullRef(args.tagName), args.actor)
	if err != nil {
		return err
	}

	// check p against policy
	pe := policy.NewPolicyEvaluator()
	pe.UseLocalPolicy = args.useLocalPolicy
	verifiedLevels, policyPath, err := pe.EvaluateTagProv(ctx, ghconnection, prov)
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

func init() {
	rootCmd.AddCommand(checktagCmd)

	checktagCmd.Flags().StringVar(&checkTagArgs.commit, "commit", "", "The commit to check - required.")
	checktagCmd.Flags().StringVar(&checkTagArgs.owner, "owner", "", "The GitHub repository owner - required.")
	checktagCmd.Flags().StringVar(&checkTagArgs.repo, "repo", "", "The GitHub repository name - required.")
	checktagCmd.Flags().StringVar(&checkTagArgs.tagName, "tag_name", "", "The name of the new tag - required.")
	checktagCmd.Flags().StringVar(&checkTagArgs.actor, "actor", "", "The username of the actor that pushed the tag.")
	checktagCmd.Flags().StringVar(&checkTagArgs.outputSignedBundle, "output_signed_bundle", "", "The path to write a bundle of signed attestations.")
	checktagCmd.Flags().StringVar(&checkTagArgs.useLocalPolicy, "use_local_policy", "", "UNSAFE: Use the policy at this local path instead of the official one.")
}
