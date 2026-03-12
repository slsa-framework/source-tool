// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/carabiner-dev/vcslocator"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/auth"
	"github.com/slsa-framework/source-tool/pkg/ghcontrol"
	"github.com/slsa-framework/source-tool/pkg/sourcetool"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
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
		errs = append(errs, errors.New("repository name not set"))
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

func (ro *repoOptions) GetRepository() *models.Repository {
	return &models.Repository{
		Hostname: "github.com",
		Path:     fmt.Sprintf("%s/%s", ro.owner, ro.repository),
	}
}

func (bo *branchOptions) Validate() error {
	errs := []error{}
	errs = append(errs, bo.repoOptions.Validate())

	if bo.branch == "" {
		errs = append(errs, errors.New("branch not set"))
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

func (bo *branchOptions) GetBranch() *models.Branch {
	return &models.Branch{
		Name: bo.branch,
		Repository: &models.Repository{
			Hostname: "github.com",
			Path:     fmt.Sprintf("%s/%s", bo.owner, bo.repository),
		},
	}
}

type branchOptions struct {
	repoOptions
	branch string
}

// ParseLocator parses an SPDX locator string and assigns its components
// to the branch options fields.
func (bo *branchOptions) ParseLocator(lString string) error {
	components, err := vcslocator.Locator(lString).Parse(vcslocator.WithRefAsBranch(true))
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
	if bo.owner == "" || bo.repository == "" {
		return errors.New("unable to fetch branch defaults, repository data incomplete")
	}

	if bo.branch != "" {
		return nil
	}

	// Create a new sourcetool object
	srctool, err := sourcetool.New(
		sourcetool.WithAuthenticator(auth.New()),
	)
	if err != nil {
		return err
	}

	branch, err := srctool.Backend().GetDefaultBranch(context.Background(), bo.GetRepository())
	if err != nil {
		return fmt.Errorf("getting default branch: %w", err)
	}
	bo.branch = branch.GetName()
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
	if co.owner == "" || co.repository == "" {
		return fmt.Errorf("unable to fetch commit defaults, repository data incomplete")
	}

	if err := co.branchOptions.EnsureDefaults(); err != nil {
		return fmt.Errorf("fetching default branch of %s/%s: %w", co.owner, co.repository, err)
	}

	if co.commit == "" {
		t := githubToken
		var err error
		if t == "" {
			t, err = auth.New().ReadToken()
			if err != nil {
				return err
			}
		}

		gcx := ghcontrol.NewGhConnection(co.owner, co.repository, "").WithAuthToken(t)
		digest, err := gcx.GetLatestCommit(context.Background(), co.branch)
		if err != nil {
			return fmt.Errorf("fetching last commit from %q: %w", co.branch, err)
		}
		co.commit = digest
	}
	return nil
}

func (co *commitOptions) GetCommit() *models.Commit {
	return &models.Commit{
		SHA: co.commit,
	}
}

type verifierOptions struct {
	expectedIssuer string
	expectedSan    string
}

func (vo *verifierOptions) Validate() error {
	return nil
}

func (vo *verifierOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&vo.expectedIssuer, "expected_issuer", "", "The expected issuer of the attestation signer certificate")
	cmd.PersistentFlags().StringVar(&vo.expectedSan, "expected_san", "", "The expected SAN string in the attestation signer certificate")
}

type tagOptions struct {
	branchOptions
	tag string
}

func (to *tagOptions) Validate() error {
	return nil
}

func (to *tagOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&to.tag, "tag", "", "Git tag within the repository")
}

type revisionOpts struct {
	repoOptions
	tagOptions
	branchOptions
	commitOptions
}

func (ro *revisionOpts) Validate() error {
	errs := []error{}
	if ro.tag == "" && ro.commit == "" {
		errs = append(errs, errors.New("unable to compute revision: no commit or tag set"))
	}
	return errors.Join(errs...)
}

func (ro *revisionOpts) AddFlags(cmd *cobra.Command) {
	// branchOptions.AddFlags already registers repo, owner, and branch flags
	ro.branchOptions.AddFlags(cmd)
	// Only register tag; tagOptions.AddFlags doesn't chain to branchOptions
	ro.tagOptions.AddFlags(cmd)
	// Register commit flag directly to avoid re-registering branch/repo flags
	cmd.PersistentFlags().StringVarP(
		&ro.commit, "commit", "c", "", "commit digest (sha1)",
	)
}

func (ro *revisionOpts) GetRevision() models.Revision {
	if ro.tag != "" {
		return &models.Tag{
			Name:       ro.tag,
			Commit:     ro.GetCommit(),
			Repository: ro.GetRepository(),
		}
	} else if ro.commit != "" {
		return ro.GetCommit()
	}
	return nil
}

func (ro *revisionOpts) ParseLocator(lString string) error {
	if err := ro.branchOptions.ParseLocator(lString); err != nil {
		return err
	}
	components, err := vcslocator.Locator(lString).Parse()
	if err != nil {
		return fmt.Errorf("parsing repository slug: %w", err)
	}

	if err := ro.ParseSlug(components.RepoPath); err != nil {
		return err
	}

	if components.Commit != "" {
		ro.commit = components.Commit
	}

	if components.Tag != "" {
		ro.tag = components.Tag
	}

	if components.Branch != "" {
		ro.tag = components.Branch
	}

	return nil
}

func (ro *revisionOpts) EnsureDefaults() error {
	if err := ro.branchOptions.EnsureDefaults(); err != nil {
		return err
	}

	if ro.tag != "" {
		ro.tagOptions.branchOptions = ro.branchOptions

		srctool, err := sourcetool.New(
			sourcetool.WithAuthenticator(auth.New()),
		)
		if err != nil {
			return err
		}

		commit, err := srctool.Backend().GetRevisionCommit(context.Background(), ro.GetRepository(), &models.Tag{
			Name: ro.tag,
		})
		if err != nil {
			return err
		}

		ro.commit = commit.SHA
	}

	if ro.commit != "" {
		ro.commitOptions.branchOptions = ro.branchOptions
		if err := ro.commitOptions.EnsureDefaults(); err != nil {
			return err
		}
	}

	// If no tag and not commit where specified, get the commit at the branch tip
	if ro.commit == "" && ro.tag == "" {
		srctool, err := sourcetool.New(
			sourcetool.WithAuthenticator(auth.New()),
		)
		if err != nil {
			return err
		}

		commit, err := srctool.Backend().GetLatestCommit(context.Background(), ro.GetRepository(), ro.GetBranch())
		if err != nil {
			return err
		}
		ro.commit = commit.SHA
	}

	return nil
}

type allowMergeCommitsOptions struct {
	allowMergeCommits bool
}

// AddFlags adds the subcommands flags
func (o *allowMergeCommitsOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&o.allowMergeCommits, "allow-merge-commits", false, "[EXPERIMENTAL] Allow merge commits in branch.")
}
