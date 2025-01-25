/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/checklevel"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/vsa"

	"github.com/google/go-github/v68/github"
	"github.com/spf13/cobra"
)

// checklevelCmd represents the checklevel command
var (
	commit, owner, repo, branch, outputVsa string
	minDays                                int

	checklevelCmd = &cobra.Command{
		Use:   "checklevel",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		Run: func(cmd *cobra.Command, args []string) {
			doCheckLevel()
		},
	}
)

func doCheckLevel() {
	if commit == "" || owner == "" || repo == "" || branch == "" {
		log.Fatal("Must set commit, owner, repo, and branch flags.")
	}

	gh_client := github.NewClient(nil)
	ctx := context.Background()

	sourceLevel, err := checklevel.DetermineSourceLevel(ctx, gh_client, commit, owner, repo, branch, minDays)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(sourceLevel)

	if outputVsa != "" {
		// This will output in the sigstore bundle format.
		signedVsa, err := vsa.CreateSignedSourceVsa(owner, repo, commit, sourceLevel)
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

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// checklevelCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// checklevelCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	checklevelCmd.Flags().StringVar(&commit, "commit", "", "The commit to check.")
	checklevelCmd.Flags().StringVar(&owner, "owner", "", "The GitHub repository owner - required.")
	checklevelCmd.Flags().StringVar(&repo, "repo", "", "The GitHub repository name - required.")
	checklevelCmd.Flags().StringVar(&branch, "branch", "", "The branch within the repository - required.")
	checklevelCmd.Flags().IntVar(&minDays, "min_days", 1, "The minimum duration that the rules need to have been enabled for.")
	checklevelCmd.Flags().StringVar(&outputVsa, "output_vsa", "", "The path to write a signed VSA with the determined level.")
}
