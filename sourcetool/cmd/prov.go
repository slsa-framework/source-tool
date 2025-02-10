/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"

	"github.com/google/go-github/v68/github"
	"github.com/spf13/cobra"
)

type ProvArgs struct {
	prevAttPath, commit, prevCommit, owner, repo, branch string
}

// provCmd represents the prov command
var (
	provArgs ProvArgs
	provCmd  = &cobra.Command{
		Use:   "prov",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		Run: func(cmd *cobra.Command, args []string) {
			doProv(provArgs.prevAttPath, provArgs.commit, provArgs.prevCommit, provArgs.owner, provArgs.repo, provArgs.branch)
		},
	}
)

func doProv(prevAttPath, commit, prevCommit, owner, repo, branch string) {
	gh_client := github.NewClient(nil)
	ctx := context.Background()
	newProv, err := attest.CreateSourceProvenance(ctx, gh_client, prevAttPath, commit, prevCommit, owner, repo, branch)
	if err != nil {
		log.Fatal(err)
	}
	provStr, err := json.Marshal(newProv)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(provStr))
}

func init() {
	rootCmd.AddCommand(provCmd)

	provCmd.Flags().StringVar(&provArgs.prevAttPath, "prev_att_path", "", "Path to the file with the attestations for the previous commit (as an in-toto bundle).")
	provCmd.Flags().StringVar(&provArgs.commit, "commit", "", "The commit to check.")
	provCmd.Flags().StringVar(&provArgs.prevCommit, "prev_commit", "", "The commit prior to 'commit'.")
	provCmd.Flags().StringVar(&provArgs.owner, "owner", "", "The GitHub repository owner - required.")
	provCmd.Flags().StringVar(&provArgs.repo, "repo", "", "The GitHub repository name - required.")
	provCmd.Flags().StringVar(&provArgs.branch, "branch", "", "The branch within the repository - required.")
}
