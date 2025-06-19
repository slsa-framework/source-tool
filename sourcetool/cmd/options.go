package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/carabiner-dev/vcslocator"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/ghcontrol"
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

func (ro *repoOptions) ParseSlug(lString string) error {
	pts := strings.Split(strings.TrimPrefix(strings.TrimSuffix(lString, "/"), "/"), "/")
	if len(pts) != 2 {
		return errors.New("repository slug malformed, must be owner/repo")
	}
	ro.owner = pts[0]
	ro.repository = pts[1]
	return nil
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

func (bo *branchOptions) ParseLocator(lString string) error {
	components, err := vcslocator.Locator(lString).Parse()
	if err != nil {
		return fmt.Errorf("parsing repository slug: %w", err)
	}

	if err := bo.ParseSlug(components.RepoPath); err != nil {
		return err
	}

	if components.Branch != "" {
		bo.branch = components.Branch
	}

	return nil
}

func (bo *branchOptions) EnsureDefaults() error {
	if bo.branch != "" {
		return nil
	}

	gcx := ghcontrol.NewGhConnection(bo.owner, bo.repository, "").WithAuthToken(githubToken)
	branch, err := gcx.GetDefaultBranch(context.Background())
	if err != nil {
		return fmt.Errorf("reading repository default branch: %w", err)
	}
	bo.branch = branch
	return nil
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

func (co *commitOptions) ParseLocator(lString string) error {
	components, err := vcslocator.Locator(lString).Parse()
	if err != nil {
		return fmt.Errorf("parsing repository slug: %w", err)
	}

	if err := co.ParseSlug(components.RepoPath); err != nil {
		return err
	}

	if components.Commit != "" {
		co.commit = components.Commit
	}

	return nil
}

func (co *commitOptions) EnsureDefaults() error {
	if err := co.branchOptions.EnsureDefaults(); err != nil {
		return fmt.Errorf("fetching default branch of %s/%s: %w", co.owner, co.repository, err)
	}

	if co.commit == "" {
		gcx := ghcontrol.NewGhConnection(co.owner, co.repository, "").WithAuthToken(githubToken)
		digest, err := gcx.GetLatestCommit(context.Background(), co.branch)
		if err != nil {
			return fmt.Errorf("fetching last commit from %q: %w", co.branch, err)
		}
		co.commit = digest
	}
	return nil
}
