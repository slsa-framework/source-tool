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

type CheckLevelProvArgs struct {
	prevBundlePath       string
	commit               string
	prevCommit           string
	owner                string
	repo                 string
	branch               string
	outputUnsignedBundle string
	outputSignedBundle   string
	expectedIssuer       string
	expectedSan          string
	useLocalPolicy       string
	allowMergeCommits    bool
}

// checklevelprovCmd represents the checklevelprov command
var (
	checkLevelProvArgs = &CheckLevelProvArgs{}

	checklevelprovCmd = &cobra.Command{
		Use:   "checklevelprov",
		Short: "Checks the given commit against policy using & creating provenance",
		Run: func(cmd *cobra.Command, args []string) {
			if err := doCheckLevelProv(checkLevelProvArgs); err != nil {
				log.Fatal(err)
			}
		},
	}
)

func doCheckLevelProv(checkLevelProvArgs *CheckLevelProvArgs) error {
	ghconnection := ghcontrol.NewGhConnection(checkLevelProvArgs.owner, checkLevelProvArgs.repo, ghcontrol.BranchToFullRef(checkLevelProvArgs.branch)).WithAuthToken(githubToken)
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

	pa := attest.NewProvenanceAttestor(ghconnection, getVerifier())
	prov, err := pa.CreateSourceProvenance(ctx, checkLevelProvArgs.prevBundlePath, checkLevelProvArgs.commit, prevCommit, ghconnection.GetFullRef())
	if err != nil {
		return err
	}

	// check p against policy
	pe := policy.NewPolicyEvaluator()
	pe.UseLocalPolicy = checkLevelProvArgs.useLocalPolicy
	verifiedLevels, policyPath, err := pe.EvaluateSourceProv(ctx, ghconnection, prov)
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

func init() {
	rootCmd.AddCommand(checklevelprovCmd)

	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.prevBundlePath, "prev_bundle_path", "", "Path to the file with the attestations for the previous commit (as an in-toto bundle).")
	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.commit, "commit", "", "The commit to check.")
	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.prevCommit, "prev_commit", "", "The commit to check.")
	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.owner, "owner", "", "The GitHub repository owner - required.")
	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.repo, "repo", "", "The GitHub repository name - required.")
	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.branch, "branch", "", "The branch within the repository - required.")
	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.outputUnsignedBundle, "output_unsigned_bundle", "", "The path to write a bundle of unsigned attestations.")
	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.outputSignedBundle, "output_signed_bundle", "", "The path to write a bundle of signed attestations.")
	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.useLocalPolicy, "use_local_policy", "", "UNSAFE: Use the policy at this local path instead of the official one.")
	checklevelprovCmd.Flags().BoolVar(&checkLevelProvArgs.allowMergeCommits, "allow-merge-commits", false, "[EXPERIMENTAL] Allow merge commits in branch")
}
