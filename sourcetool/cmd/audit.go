/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/audit"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/ghcontrol"
)

type AuditArgs struct {
	owner      string
	repo       string
	branch     string
	auditDepth int
}

func (aa *AuditArgs) Validate() error {
	if aa.owner == "" || aa.repo == "" || aa.branch == "" {
		return errors.New("must set owner, repo, and branch flags")
	}
	return nil
}

var (
	auditArgs = &AuditArgs{}

	auditCmd = &cobra.Command{
		Use:   "audit",
		Short: "Audits the SLSA properties and controls of a repository",
		Run: func(cmd *cobra.Command, args []string) {
			err := doAudit(auditArgs)
			if err != nil {
				log.Fatal(err)
			}
		},
	}
)

func printAuditResult(ar *audit.AuditCommitResult) {
	fmt.Printf("commit: %s\n", ar.Commit)
	if ar.VsaPred != nil {
		fmt.Printf("\tvsa: %v\n", ar.VsaPred.GetVerifiedLevels())
	} else {
		fmt.Printf("\tvsa: none\n")
	}
	if ar.ProvPred != nil {
		fmt.Print("\tprov:\n")
		fmt.Printf("\t\tcontrols: %v\n", ar.ProvPred.Controls)
		if ar.ProvPred.PrevCommit == ar.GhPriorCommit {
			fmt.Printf("\t\tPrevCommit matches GH commit: true\n")
		} else {
			fmt.Printf("\t\tPrevCommit matches GH commit: false: %s != %s\n", ar.ProvPred.PrevCommit, ar.GhPriorCommit)
		}
	} else {
		fmt.Printf("\tprov: none\n")
	}
	if ar.GhControlStatus != nil {
		fmt.Printf("\tgh controls: %v\n", ar.GhControlStatus.Controls)
	}
}

func doAudit(auditArgs *AuditArgs) error {
	err := auditArgs.Validate()
	if err != nil {
		return err
	}

	ghc := ghcontrol.NewGhConnection(auditArgs.owner, auditArgs.repo, ghcontrol.BranchToFullRef(auditArgs.branch)).WithAuthToken(githubToken)
	ctx := context.Background()
	verifier := getVerifier()
	pa := attest.NewProvenanceAttestor(ghc, verifier)

	auditor := audit.NewAuditor(ghc, pa, verifier)

	latestCommit, err := ghc.GetLatestCommit(ctx, auditArgs.branch)
	if err != nil {
		return fmt.Errorf("could not get latest commit for %s", auditArgs.branch)
	}

	fmt.Printf("Auditing branch %s starting from revision %s\n", auditArgs.branch, latestCommit)

	count := 1
	for ar, err := range auditor.AuditBranch(ctx, auditArgs.branch) {
		if ar == nil {
			return err
		}
		if auditArgs.auditDepth > 0 && count > auditArgs.auditDepth {
			return nil
		}
		if err != nil {
			fmt.Printf("\terror: %v\n", err)
		}
		printAuditResult(ar)
		count++
	}

	return nil
}

func init() {
	rootCmd.AddCommand(auditCmd)

	auditCmd.Flags().StringVar(&auditArgs.owner, "owner", "", "The GitHub repository owner - required.")
	auditCmd.Flags().StringVar(&auditArgs.repo, "repo", "", "The GitHub repository name - required.")
	auditCmd.Flags().StringVar(&auditArgs.branch, "branch", "", "The branch within the repository - required.")
	auditCmd.Flags().IntVar(&auditArgs.auditDepth, "depth", 0, "The max number of revisions to audit (depth <= audit all revisions).")
}
