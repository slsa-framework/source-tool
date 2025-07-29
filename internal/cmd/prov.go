/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/slsa-framework/slsa-source-poc/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/pkg/ghcontrol"
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
		Use:   "prov",
		Short: "Creates provenance for the given commit, but does not check policy.",
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
			return doProv(&opts)
		},
	}
	opts.AddFlags(provCmd)
	parentCmd.AddCommand(provCmd)
}

func doProv(opts *provOptions) error {
	ghconnection := ghcontrol.NewGhConnection(opts.owner, opts.repository, ghcontrol.BranchToFullRef(opts.branch)).WithAuthToken(githubToken)
	ctx := context.Background()
	pa := attest.NewProvenanceAttestor(ghconnection, getVerifier(&opts.verifierOptions))
	newProv, err := pa.CreateSourceProvenance(ctx, opts.prevAttPath, opts.commit, opts.prevCommit, ghconnection.GetFullRef())
	if err != nil {
		return err
	}
	provStr, err := protojson.Marshal(newProv)
	if err != nil {
		return err
	}
	fmt.Println(string(provStr))
	return nil
}
