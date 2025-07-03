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
	commitOptions
	verifierOptions
	tag string
}

func (vco *verifyCommitOptions) Validate() error {
	errs := []error{
		vco.commitOptions.Validate(),
		vco.verifierOptions.Validate(),
	}
	return errors.Join(errs...)
}

func (vco *verifyCommitOptions) AddFlags(cmd *cobra.Command) {
	vco.commitOptions.AddFlags(cmd)
	vco.verifierOptions.AddFlags(cmd)
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

			// Validate early the repository options to provide a more
			// useful message to the user
			if err := opts.repoOptions.Validate(); err != nil {
				return err
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
			return doVerifyCommit(&opts)
		},
	}
	opts.AddFlags(cmd)
	cmd.AddCommand(verifyCommitCmd)
}

func doVerifyCommit(opts *verifyCommitOptions) error {
	var ref string
	switch {
	case opts.branch != "":
		ref = ghcontrol.BranchToFullRef(opts.branch)
	case opts.tag != "":
		ref = ghcontrol.TagToFullRef(opts.tag)
	default:
		return fmt.Errorf("must specify either branch or tag")
	}

	ghconnection := ghcontrol.NewGhConnection(opts.owner, opts.repository, ref).WithAuthToken(githubToken)
	ctx := context.Background()

	_, vsaPred, err := attest.GetVsa(ctx, ghconnection, getVerifier(&opts.verifierOptions), opts.commit, ghconnection.GetFullRef())
	if err != nil {
		return err
	}
	if vsaPred == nil {
		fmt.Printf(
			"FAILED: no VSA matching commit '%s' on branch '%s' found in github.com/%s/%s\n",
			opts.commit, opts.branch, opts.owner, opts.repository,
		)
		return nil
	}

	fmt.Printf("SUCCESS: commit %s on %s verified with %v\n", opts.commit, opts.branch, vsaPred.GetVerifiedLevels())
	return nil
}
