/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"log"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/ghcontrol"
	"github.com/spf13/cobra"
)

type VerifyCommitArgs struct {
	owner, repo, branch, commit, tag string
}

// checklevelCmd represents the checklevel command
var (
	verifyCommitArgs VerifyCommitArgs
	verifycommitCmd  = &cobra.Command{
		Use:   "verifycommit",
		Short: "Verifies the specified commit is valid",
		Run: func(cmd *cobra.Command, args []string) {
			doVerifyCommit(verifyCommitArgs.commit, verifyCommitArgs.owner, verifyCommitArgs.repo, verifyCommitArgs.branch, verifyCommitArgs.tag)
		},
	}
)

func doVerifyCommit(commit, owner, repo, branch, tag string) {
	if commit == "" || owner == "" || repo == "" {
		log.Fatal("Must set commit, owner and repo.")
	}

	ref := ""
	if branch != "" {
		ref = ghcontrol.BranchToFullRef(branch)
	} else if tag != "" {
		ref = ghcontrol.TagToFullRef(tag)
	} else {
		log.Fatal("Must specify either branch or tag.")
	}

	ghconnection := ghcontrol.NewGhConnection(owner, repo, ref).WithAuthToken(githubToken)
	ctx := context.Background()

	_, vsaPred, err := attest.GetVsa(ctx, ghconnection, getVerifier(), commit, ghconnection.GetFullRef())
	if err != nil {
		log.Fatal(err)
	}
	if vsaPred == nil {
		fmt.Printf("FAILED: no VSA matching commit '%s' on branch '%s' found in github.com/%s/%s\n", commit, branch, owner, repo)
		return
	}

	fmt.Printf("SUCCESS: commit %s verified with %v\n", commit, vsaPred.VerifiedLevels)
}

func init() {
	rootCmd.AddCommand(verifycommitCmd)

	verifycommitCmd.Flags().StringVar(&verifyCommitArgs.owner, "owner", "", "The GitHub repository owner - required.")
	verifycommitCmd.Flags().StringVar(&verifyCommitArgs.repo, "repo", "", "The GitHub repository name - required.")
	verifycommitCmd.Flags().StringVar(&verifyCommitArgs.branch, "branch", "", "The branch within the repository.")
	verifycommitCmd.Flags().StringVar(&verifyCommitArgs.tag, "tag", "", "The tag within the repository.")
	verifycommitCmd.Flags().StringVar(&verifyCommitArgs.commit, "commit", "", "The commit to check - required.")

}
