package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

type repoOptions struct {
	owner      string
	repository string
}

func (ro *repoOptions) Validate() error {
	errs := []error{}
	if ro.owner == "" {
		errs = append(errs, errors.New("repository owner not set"))
	}
	if ro.repository == "" {
		errs = append(errs, errors.New(""))
	}
	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (ro *repoOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&ro.repository, "repo", "", "name of the repository",
	)

	cmd.PersistentFlags().StringVar(
		&ro.owner, "owner", "", "user or oganization that owns the repo",
	)
}

func (bo *branchOptions) Validate() error {
	errs := []error{}
	errs = append(errs, bo.repoOptions.Validate())

	if bo.branch == "" {
		return errors.New("branch not set")
	}
	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (bo *branchOptions) AddFlags(cmd *cobra.Command) {
	bo.repoOptions.AddFlags(cmd)

	cmd.PersistentFlags().StringVar(
		&bo.branch, "branch", "", "name of the branch",
	)
}

type branchOptions struct {
	repoOptions
	branch string
}

// commitOptions defines the fields and flags to ask the user for the data of a commit
type commitOptions struct {
	branchOptions
	commit string
}

func (co *commitOptions) AddFlags(cmd *cobra.Command) {
	co.branchOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVarP(
		&co.commit, "commit", "c", "", "commit digest (sha1)",
	)
}

func (co *commitOptions) Validate() error {
	errs := []error{
		co.branchOptions.Validate(),
	}
	if co.commit == "" {
		errs = append(errs, errors.New("commit digest must be set"))
	}
	return errors.Join(errs...)
}
