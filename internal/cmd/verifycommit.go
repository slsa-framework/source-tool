// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/ghcontrol"
)

type verifyCommitOptions struct {
	commitOptions
	verifierOptions
	outputOptions
	tag string
}

// VerifyCommitResult represents the result of a commit verification
type VerifyCommitResult struct {
	Success        bool     `json:"success"`
	Commit         string   `json:"commit"`
	Ref            string   `json:"ref"`
	RefType        string   `json:"ref_type"` // "branch" or "tag"
	Owner          string   `json:"owner"`
	Repository     string   `json:"repository"`
	VerifiedLevels []string `json:"verified_levels,omitempty"`
	Message        string   `json:"message,omitempty"`
}

// String implements fmt.Stringer for text output
func (v VerifyCommitResult) String() string {
	if !v.Success {
		return fmt.Sprintf("FAILED: %s\n", v.Message)
	}
	return fmt.Sprintf("SUCCESS: commit %s on %s verified with %v\n", v.Commit, v.Ref, v.VerifiedLevels)
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
	vco.format = OutputFormatText
	cmd.PersistentFlags().StringVar(&vco.format, "format", OutputFormatText, "Output format: 'text' (default) or 'json'")
}

//nolint:dupl
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
	var refType string
	var refName string
	switch {
	case opts.branch != "":
		ref = ghcontrol.BranchToFullRef(opts.branch)
		refType = "branch"
		refName = opts.branch
	case opts.tag != "":
		ref = ghcontrol.TagToFullRef(opts.tag)
		refType = "tag"
		refName = opts.tag
	default:
		return fmt.Errorf("must specify either branch or tag")
	}

	ghconnection := ghcontrol.NewGhConnection(opts.owner, opts.repository, ref).WithAuthToken(githubToken)
	ctx := context.Background()

	_, vsaPred, err := attest.GetVsa(ctx, ghconnection, getVerifier(&opts.verifierOptions), opts.commit, ghconnection.GetFullRef())
	if err != nil {
		return err
	}

	result := VerifyCommitResult{
		Success:    vsaPred != nil,
		Commit:     opts.commit,
		Ref:        refName,
		RefType:    refType,
		Owner:      opts.owner,
		Repository: opts.repository,
	}

	if vsaPred == nil {
		result.Message = fmt.Sprintf(
			"no VSA matching commit '%s' on %s '%s' found in github.com/%s/%s",
			opts.commit, refType, refName, opts.owner, opts.repository,
		)
		return opts.writeResult(result)
	}

	result.VerifiedLevels = vsaPred.GetVerifiedLevels()
	return opts.writeResult(result)
}
