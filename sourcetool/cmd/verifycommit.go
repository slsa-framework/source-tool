/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

type VerifyCommitArgs struct {
	owner, repo, branch, commit string
}

// checklevelCmd represents the checklevel command
var (
	verifyCommitArgs VerifyCommitArgs
	verifycommitCmd  = &cobra.Command{
		Use:   "verifycommit",
		Short: "Verifies the specified commit is valid",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("verifycommit called")
		},
	}
)

func doVerifyCommit(commit, owner, repo, branch string) {
	if commit == "" || owner == "" || repo == "" || branch == "" {
		log.Fatal("Must set commit, owner, repo, and branch flags.")
	}

	gh_connection := gh_control.NewGhConnection(owner, repo, branch).WithAuthToken(githubToken)
	ctx := context.Background()
}

func init() {
	rootCmd.AddCommand(verifycommitCmd)

	verifycommitCmd.Flags().StringVar(&verifyCommitArgs.owner, "owner", "", "The GitHub repository owner - required.")
	verifycommitCmd.Flags().StringVar(&verifyCommitArgs.repo, "repo", "", "The GitHub repository name - required.")
	verifycommitCmd.Flags().StringVar(&verifyCommitArgs.branch, "branch", "", "The branch within the repository - required.")
	verifycommitCmd.Flags().StringVar(&verifyCommitArgs.commit, "commit", "", "The commit to check - required.")

}
