// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/policy"
)

type createPolicyOptions struct {
	branchOptions
	policyRepoPath string
}

func (cpo *createPolicyOptions) Validate() error {
	return cpo.branchOptions.Validate()
}

func (cpo *createPolicyOptions) AddFlags(cmd *cobra.Command) {
	cpo.branchOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(&cpo.policyRepoPath, "policy_repo_path", "./", "Path to the directory with a clean clone of github.com/slsa-framework/source-policies.")
}

func addCreatePolicy(parentCmd *cobra.Command) {
	opts := createPolicyOptions{}

	createpolicyCmd := &cobra.Command{
		Use:     "createpolicy",
		GroupID: "configuration",
		Short:   "Creates a policy in a local copy of source-policies",
		Long: `Creates a SLSA source policy in a local copy of source-policies.

		The created policy should then be sent as a PR to slsa-framework/source-policies.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			return doCreatePolicy(&opts)
		},
	}
	opts.AddFlags(createpolicyCmd)
	parentCmd.AddCommand(createpolicyCmd)
}

func doCreatePolicy(opts *createPolicyOptions) error {
	evaluator := policy.NewPolicyEvaluator()
	outpath, err := evaluator.CreateLocalPolicy(
		context.Background(), opts.GetRepository(), opts.GetBranch(), opts.policyRepoPath,
	)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote policy to %s\n", outpath)
	return nil
}
