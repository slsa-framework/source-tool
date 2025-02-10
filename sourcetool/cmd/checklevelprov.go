/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/policy"

	"github.com/google/go-github/v68/github"
	"github.com/spf13/cobra"
)

type CheckLevelProvArgs struct {
	prevBundlePath       string
	commit               string
	prevCommit           string
	owner                string
	repo                 string
	branch               string
	outputUnsignedBundle string
}

// checklevelprovCmd represents the checklevelprov command
var (
	checkLevelProvArgs CheckLevelProvArgs

	checklevelprovCmd = &cobra.Command{
		Use:   "checklevelprov",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		Run: func(cmd *cobra.Command, args []string) {
			doCheckLevelProv(checkLevelProvArgs)
		},
	}
)

func doCheckLevelProv(checkLevelProvArgs CheckLevelProvArgs) {
	gh_client := github.NewClient(nil)
	ctx := context.Background()

	p, err := attest.CreateSourceProvenance(ctx, gh_client, checkLevelProvArgs.prevBundlePath, checkLevelProvArgs.commit, checkLevelProvArgs.prevCommit, checkLevelProvArgs.owner, checkLevelProvArgs.repo, checkLevelProvArgs.branch)
	if err != nil {
		log.Fatal(err)
	}

	// check p against policy
	level, err := policy.EvaluateProv(ctx, gh_client, checkLevelProvArgs.owner, checkLevelProvArgs.repo, checkLevelProvArgs.branch, p)
	if err != nil {
		log.Fatal(err)
	}

	// create vsa
	unsignedVsa, err := attest.CreateUnsignedSourceVsa(checkLevelProvArgs.owner, checkLevelProvArgs.repo, checkLevelProvArgs.commit, level)
	if err != nil {
		log.Fatal(err)
	}

	unsignedProv, err := json.Marshal(p)
	if err != nil {
		log.Fatal(err)
	}

	// Store both the provenance and the vsa
	f, err := os.OpenFile(checkLevelProvArgs.outputUnsignedBundle, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	f.WriteString(string(unsignedProv))
	f.WriteString("\n")
	f.WriteString(unsignedVsa)
}

func init() {
	rootCmd.AddCommand(checklevelprovCmd)

	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.prevBundlePath, "prev_bundle_path", "", "Path to the file with the attestations for the previous commit (as an in-toto bundle).")
	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.commit, "commit", "", "The commit to check.")
	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.prevCommit, "prev_commit", "", "The commit to check.")
	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.owner, "owner", "", "The GitHub repository owner - required.")
	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.repo, "repo", "", "The GitHub repository name - required.")
	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.branch, "branch", "", "The branch within the repository - required.")
	checklevelprovCmd.Flags().StringVar(&checkLevelProvArgs.outputUnsignedBundle, "outputUnsignedBundle", "", "The path to write a bundle of unsigned attestations.")
}
