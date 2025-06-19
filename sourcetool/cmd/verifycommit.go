/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/ghcontrol"
)

type verifyCommitOptions struct {
	tag string
	commitOptions
}

func (vco *verifyCommitOptions) Validate() error {
	errs := []error{
		vco.commitOptions.Validate(),
	}
	return errors.Join(errs...)
}

func (vco *verifyCommitOptions) AddFlags(cmd *cobra.Command) {
	vco.commitOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(
		&vco.tag, "tag", "", "The tag within the repository",
	)
}

func addVerifyCommit(cmd *cobra.Command) {
	opts := verifyCommitOptions{}
	verifyCommitCmd := &cobra.Command{
		Use:   "verifycommit",
		Short: "Verifies the specified commit is valid",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				if err := opts.ParseLocator(args[0]); err != nil {
					return err
				}
			}

			if err := opts.EnsureDefaults(); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return fmt.Errorf("validating options: %w", err)
			}
			return doVerifyCommit(opts.commit, opts.owner, opts.repository, opts.branch, opts.tag)
		},
	}
	opts.AddFlags(cmd)
	cmd.AddCommand(verifyCommitCmd)
}

func doVerifyCommit(commit, owner, repo, branch, tag string) error {
	if commit == "" || owner == "" || repo == "" {
		return fmt.Errorf("must set commit, owner and repo")
	}

	var ref string
	switch {
	case branch != "":
		ref = ghcontrol.BranchToFullRef(branch)
	case tag != "":
		ref = ghcontrol.TagToFullRef(tag)
	default:
		return fmt.Errorf("must specify either branch or tag")
	}

	ghconnection := ghcontrol.NewGhConnection(owner, repo, ref).WithAuthToken(githubToken)
	ctx := context.Background()

	_, vsaPred, err := attest.GetVsa(ctx, ghconnection, getVerifier(), commit, ghconnection.GetFullRef())
	if err != nil {
		return err
	}
	if vsaPred == nil {
		fmt.Printf("FAILED: no VSA matching commit '%s' on branch '%s' found in github.com/%s/%s\n", commit, branch, owner, repo)
		return nil
	}

	fmt.Printf("SUCCESS: commit %s verified with %v\n", commit, vsaPred.GetVerifiedLevels())
	return nil
}
