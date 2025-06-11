/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/policy"
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return doCreatePolicy(createPolicyArgs.policyRepoPath, createPolicyArgs.owner, createPolicyArgs.repo, createPolicyArgs.branch)
		},
	}
)

func doCreatePolicy(policyRepoPath, owner, repo, branch string) error {
	ghconnection := ghcontrol.NewGhConnection(owner, repo, ghcontrol.BranchToFullRef(branch)).WithAuthToken(githubToken)
	ctx := context.Background()
	outpath, err := policy.CreateLocalPolicy(ctx, ghconnection, policyRepoPath)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote policy to %s\n", outpath)
	return nil
}

func init() {
	rootCmd.AddCommand(createpolicyCmd)

	// Here you will define your flags and configuration settings.

	createpolicyCmd.Flags().StringVar(&createPolicyArgs.policyRepoPath, "policy_repo_path", "./", "Path to the directory with a clean clone of github.com/slsa-framework/slsa-source-poc.")
	createpolicyCmd.Flags().StringVar(&createPolicyArgs.owner, "owner", "", "The GitHub repository owner - required.")
	createpolicyCmd.Flags().StringVar(&createPolicyArgs.repo, "repo", "", "The GitHub repository name - required.")
	createpolicyCmd.Flags().StringVar(&createPolicyArgs.branch, "branch", "", "The branch within the repository - required.")
}
