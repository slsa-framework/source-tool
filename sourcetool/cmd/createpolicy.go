/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"log"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/gh_control"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/policy"

	"github.com/spf13/cobra"
)

type CreatePolicyArgs struct {
	policyRepoPath, owner, repo, branch string
}

var (
	createPolicyArgs CreatePolicyArgs

	// createpolicyCmd represents the createpolicy command
	createpolicyCmd = &cobra.Command{
		Use:   "createpolicy",
		Short: "Creates a policy in a local copy of slsa-source-poc",
		Long: `Creates a SLSA source policy in a local copy of slsa-source-poc.

		The created policy should then be sent as a PR to slsa-framework/slsa-source-poc.`,
		Run: func(cmd *cobra.Command, args []string) {
			doCreatePolicy(createPolicyArgs.policyRepoPath, createPolicyArgs.owner, createPolicyArgs.repo, createPolicyArgs.branch)
		},
	}
)

func doCreatePolicy(policyRepoPath, owner, repo, branch string) {
	gh_connection := gh_control.NewGhConnection(owner, repo, gh_control.BranchToFullRef(branch)).WithAuthToken(githubToken)
	ctx := context.Background()
	outpath, err := policy.CreateLocalPolicy(ctx, gh_connection, policyRepoPath)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Wrote policy to %s\n", outpath)
}

func init() {
	rootCmd.AddCommand(createpolicyCmd)

	// Here you will define your flags and configuration settings.

	createpolicyCmd.Flags().StringVar(&createPolicyArgs.policyRepoPath, "policy_repo_path", "./", "Path to the directory with a clean clone of github.com/slsa-framework/slsa-source-poc.")
	createpolicyCmd.Flags().StringVar(&createPolicyArgs.owner, "owner", "", "The GitHub repository owner - required.")
	createpolicyCmd.Flags().StringVar(&createPolicyArgs.repo, "repo", "", "The GitHub repository name - required.")
	createpolicyCmd.Flags().StringVar(&createPolicyArgs.branch, "branch", "", "The branch within the repository - required.")
}
