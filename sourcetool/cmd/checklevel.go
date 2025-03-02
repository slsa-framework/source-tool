/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/gh_control"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/policy"

	"github.com/spf13/cobra"
)

type CheckLevelArgs struct {
	commit, owner, repo, branch, outputVsa, outputUnsignedVsa string
}

// checklevelCmd represents the checklevel command
var (
	checkLevelArgs CheckLevelArgs

	checklevelCmd = &cobra.Command{
		Use:   "checklevel",
		Short: "Determines the SLSA Source Level of the repo",
		Long: `Determines the SLSA Source Level of the repo.

This is meant to be run within the corresponding GitHub Actions workflow.`,
		Run: func(cmd *cobra.Command, args []string) {
			doCheckLevel(checkLevelArgs.commit, checkLevelArgs.owner, checkLevelArgs.repo, checkLevelArgs.branch, checkLevelArgs.outputVsa, checkLevelArgs.outputUnsignedVsa)
		},
	}
)

func doCheckLevel(commit, owner, repo, branch, outputVsa, outputUnsignedVsa string) {
	if commit == "" || owner == "" || repo == "" || branch == "" {
		log.Fatal("Must set commit, owner, repo, and branch flags.")
	}

	gh_connection := gh_control.NewGhConnection(owner, repo, branch).WithAuthToken(githubToken)
	ctx := context.Background()

	controlStatus, err := gh_connection.GetControls(ctx, commit)
	if err != nil {
		log.Fatal(err)
	}
	verifiedLevels, policyPath, err := policy.EvaluateControl(ctx, gh_connection, controlStatus)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(verifiedLevels)

	unsignedVsa, err := attest.CreateUnsignedSourceVsa(gh_connection, commit, verifiedLevels, policyPath)
	if err != nil {
		log.Fatal(err)
	}
	if outputUnsignedVsa != "" {
		err = os.WriteFile(outputUnsignedVsa, []byte(unsignedVsa), 0644)
		if err != nil {
			log.Fatal(err)
		}
	}

	if outputVsa != "" {
		// This will output in the sigstore bundle format.
		signedVsa, err := attest.Sign(unsignedVsa)
		if err != nil {
			log.Fatal(err)
		}
		err = os.WriteFile(outputVsa, []byte(signedVsa), 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func init() {
	rootCmd.AddCommand(checklevelCmd)

	// Here you will define your flags and configuration settings.

	checklevelCmd.Flags().StringVar(&checkLevelArgs.commit, "commit", "", "The commit to check.")
	checklevelCmd.Flags().StringVar(&checkLevelArgs.owner, "owner", "", "The GitHub repository owner - required.")
	checklevelCmd.Flags().StringVar(&checkLevelArgs.repo, "repo", "", "The GitHub repository name - required.")
	checklevelCmd.Flags().StringVar(&checkLevelArgs.branch, "branch", "", "The branch within the repository - required.")
	checklevelCmd.Flags().StringVar(&checkLevelArgs.outputVsa, "output_vsa", "", "The path to write a signed VSA with the determined level.")
	checklevelCmd.Flags().StringVar(&checkLevelArgs.outputUnsignedVsa, "output_unsigned_vsa", "", "The path to write an unsigned vsa with the determined level.")
}
