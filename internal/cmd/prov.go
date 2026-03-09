// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/slsa-framework/source-tool/pkg/sourcetool"
)

type provOptions struct {
	commitOptions
	verifierOptions
	prevAttPath, prevCommit string
}

func (po *provOptions) Validate() error {
	return errors.Join([]error{
		po.commitOptions.Validate(),
		po.verifierOptions.Validate(),
	}...)
}

func (po *provOptions) AddFlags(cmd *cobra.Command) {
	po.commitOptions.AddFlags(cmd)
	po.verifierOptions.AddFlags(cmd)

	cmd.PersistentFlags().StringVar(&po.prevAttPath, "prev_att_path", "", "Path to the file with the attestations for the previous commit (as an in-toto bundle).")
	cmd.PersistentFlags().StringVar(&po.prevCommit, "prev_commit", "", "The commit prior to 'commit'.")
}

//nolint:dupl
func addProv(parentCmd *cobra.Command) {
	opts := provOptions{}
	provCmd := &cobra.Command{
		Use:     "prov",
		GroupID: "assessment",
		Short:   "Creates provenance for the given commit, but does not check policy.",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				if err := opts.ParseLocator(args[0]); err != nil {
					return err
				}
			}

			// Validate the repo opts here to provide a useful error
			// when checking defaults
			if err := opts.repoOptions.Validate(); err != nil {
				return err
			}

			// Ensure we operate on the latest commit and the default
			// branch if not spcified
			if err := opts.EnsureDefaults(); err != nil {
				return err
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return fmt.Errorf("validating options: %w", err)
			}

			authenticator, err := CheckAuth()
			if err != nil {
				return err
			}

			// Create a new sourcetool object
			srctool, err := sourcetool.New(
				sourcetool.WithAuthenticator(authenticator),
			)
			if err != nil {
				return err
			}

			// var prevCommit *models.Commit
			// if opts.prevCommit != "" {
			// 	prevCommit = &models.Commit{SHA: opts.prevCommit}
			// } else {
			// 	prevCommit, err = srctool.GetPreviousCommit(cmd.Context(), opts.GetBranch(), opts.GetCommit())
			// 	if err != nil {
			// 		return err
			// 	}
			// }

			// opts.prevAttPath,
			newProv, err := srctool.Attester().CreateSourceProvenance(cmd.Context(), opts.GetBranch(), opts.GetCommit())
			if err != nil {
				return err
			}
			provStr, err := protojson.Marshal(newProv)
			if err != nil {
				return err
			}
			fmt.Println(string(provStr))
			return nil
		},
	}
	opts.AddFlags(provCmd)
	parentCmd.AddCommand(provCmd)
}
