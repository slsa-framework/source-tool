// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-github/v88/github"
	"golang.org/x/mod/semver"

	"github.com/slsa-framework/source-tool/pkg/repo"
	"github.com/slsa-framework/source-tool/pkg/repo/options"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

const (
	// ActionsOrg and ActionsRepo point to the repository hosting the reusable
	// provenance workflow the generated workflow calls.
	ActionsOrg   = "slsa-framework"
	ActionsRepo  = "actions"
	workflowPath = ".github/workflows/compute_slsa_source.yaml"

	// githubActionsBotLogin and githubActionsBotEmail are the login and email
	// GitHub uses for the actions bot. It is not a regular noreply.github.com
	githubActionsBotLogin = "github-actions[bot]"
	githubActionsBotEmail = "41898282+github-actions[bot]@users.noreply.github.com"

	// workflowCommitMessage will be used as the commit message and the PR title
	workflowCommitMessage = "Add SLSA Source Provenance Workflow"

	// workflowUpdateCommitMessage is the commit message and PR title of the
	// pull request updating workflows calling the actions from a legacy repo.
	workflowUpdateCommitMessage = "Update SLSA Source Provenance Workflow"

	// workflowUpdatePRBody is the body of the pull request moving the provenance
	// workflow off a legacy actions repo. It takes the current actions repo
	// (twice) and the pinned tag.
	workflowUpdatePRBody = `This pull request updates the SLSA Source provenance workflow to call the ` +
		`SLSA actions from their new repository at [%s](https://github.com/%s).` + "\n\n" +
		`The previous locations are deprecated and will no longer receive updates. ` +
		`The actions are now pinned to the digest of the %s release, recording the ` +
		`version in a comment so that dependabot can keep it up to date.` + "\n\n" +
		`Note: This is an automated PR created using the ` +
		`[SLSA sourcetool](https://github.com/slsa-framework/source-tool) utility.` + "\n"

	// workflowBumpPRBody is the body of the pull request updating a provenance
	// workflow already calling the current actions repo to its latest release.
	// It takes the current actions repo (twice) and the pinned tag.
	workflowBumpPRBody = `This pull request updates the SLSA Source provenance workflow to call the ` +
		`latest release of the SLSA actions from [%s](https://github.com/%s).` + "\n\n" +
		`The actions are now pinned to the digest of the %s release, recording the ` +
		`version in a comment so that dependabot can keep it up to date.` + "\n\n" +
		`Note: This is an automated PR created using the ` +
		`[SLSA sourcetool](https://github.com/slsa-framework/source-tool) utility.` + "\n"

	// workflowPRBody is the body of the pull request that adds the provenance workflow
	workflowPRBody = `This pull request adds a new workflow to the repository to generate ` +
		`[SLSA](https://slsa.dev/) Source provenance data on every push.` + "\n\n" +
		`Every time a new commit merges to the specified branch, attestations will ` +
		`be automatically signed and stored in git notes in this repository.` + "\n\n" +
		`Note: This is an automated PR created using the ` +
		`[SLSA sourcetool](https://github.com/slsa-framework/source-tool) utility.` + "\n"

	workflowData = `---
name: SLSA Source
on:
  push:
    branches: [ %s ]
    tags: ['**']
permissions: {}

jobs:
  # Whenever new source is pushed recompute the slsa source information.
  generate-provenance:
    permissions:
      contents: write # needed for storing the vsa in the repo.
      id-token: write # meeded to mint yokens for signing
    uses: %s/%s/.github/workflows/compute_slsa_source.yml@%s # %s

`

	// actionsTagsPerPage is the page size used when listing the actions repo tags
	actionsTagsPerPage = 100
)

// checkPushAccess
func (b *Backend) checkPushAccess(r *models.Repository) (bool, error) {
	client, err := b.authenticator.GetGitHubClient()
	if err != nil {
		return false, err
	}
	owner, repoName, err := r.PathAsGitHubOwnerName()
	if err != nil {
		return false, err
	}

	//nolint:noctx
	resp, err := client.Client().Get(fmt.Sprintf("https://api.github.com/repos/%s/%s/collaborators", owner, repoName))
	if resp.StatusCode == http.StatusForbidden {
		return false, nil
	}
	if err != nil {
		resp.Body.Close() //nolint:errcheck,gosec
		return false, fmt.Errorf("checking repository access: %w", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec
	return true, nil
}

// CreateWorkflowPR creates the pull request to add the provenance workflow
// to the specified repository.
func (b *Backend) CreateWorkflowPR(ctx context.Context, r *models.Repository, branches []*models.Branch) (*models.PullRequest, error) {
	if len(branches) == 0 {
		return nil, errors.New("no branches specified")
	}

	// Get the actions repo tag
	actionsTag, actionsHash, err := b.GetLatestActionsTag(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting latest actions tag: %w", err)
	}

	workflowYAML := buildWorkflowYAML(branches, actionsTag, actionsHash)

	//nolint:contextcheck // the pull request manager does not take a context
	return b.openWorkflowPR(r, workflowCommitMessage, workflowPRBody, []*repo.PullRequestFileEntry{
		{
			Path:   workflowPath,
			Reader: strings.NewReader(workflowYAML),
		},
	})
}

// updateWorkflowPR creates a pull request updating the specified workflows
// to call the SLSA actions from the current repository, pinned to the digest
// of its latest release (actionsTag). Workflows already calling the actions
// at that digest are skipped.
func (b *Backend) updateWorkflowPR(
	r *models.Repository, workflows []*provenanceWorkflow, actionsTag, actionsHash string,
) (*models.PullRequest, error) {
	files := []*repo.PullRequestFileEntry{}
	legacy := false
	for _, wf := range workflows {
		content, changed := migrateActionsReferences(wf.Content, actionsTag, actionsHash)
		if changed == 0 {
			continue
		}
		legacy = legacy || wf.IsLegacy()
		files = append(files, &repo.PullRequestFileEntry{
			Path:   wf.Path,
			Reader: strings.NewReader(content),
		})
	}

	if len(files) == 0 {
		return nil, errors.New("none of the workflows need to be updated")
	}

	// The body explains the repository move only when a workflow is migrated
	bodyTemplate := workflowBumpPRBody
	if legacy {
		bodyTemplate = workflowUpdatePRBody
	}
	actionsRepo := ActionsOrg + "/" + ActionsRepo
	body := fmt.Sprintf(bodyTemplate, actionsRepo, actionsRepo, actionsTag)
	return b.openWorkflowPR(r, workflowUpdateCommitMessage, body, files)
}

// configureProvenanceWorkflow ensures the repository has a workflow generating
// provenance which calls the current SLSA actions. It opens a pull request
// adding the workflow when the repository has none, or updating the existing
// workflows when they call the actions from a legacy repository or when they
// are not pinned to the latest actions release. It returns
// a nil pull request when there is nothing to do: either the workflows are up
// to date or a pull request adding or updating them is already open.
func (b *Backend) configureProvenanceWorkflow(ctx context.Context, r *models.Repository, branches []*models.Branch) (*models.PullRequest, error) {
	// Check if there is an open PR already adding or updating the workflow
	pr, err := b.FindWorkflowPR(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("checking for an open workflow pull request: %w", err)
	}
	if pr != nil {
		return nil, nil
	}

	owner, repoName, err := r.PathAsGitHubOwnerName()
	if err != nil {
		return nil, err
	}

	client, err := b.authenticator.GetGitHubClient()
	if err != nil {
		return nil, fmt.Errorf("getting GitHub client: %w", err)
	}

	// Look for provenance workflows in the default branch, where the pull
	// request will be opened. Workflows are detected by their contents, not
	// by their file name.
	workflows, err := findProvenanceWorkflows(ctx, client, owner, repoName, r.DefaultBranch)
	if err != nil {
		return nil, fmt.Errorf("checking for existing provenance workflows: %w", err)
	}

	// No workflow found, add it
	if len(workflows) == 0 {
		return b.CreateWorkflowPR(ctx, r, branches)
	}

	// Get the actions repo tag
	actionsTag, actionsHash, err := b.GetLatestActionsTag(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting latest actions tag: %w", err)
	}

	outdated := []*provenanceWorkflow{}
	for _, wf := range workflows {
		if wf.NeedsUpdate(actionsHash) {
			outdated = append(outdated, wf)
		}
	}

	// Workflows already call the latest release of the actions, nothing to do
	if len(outdated) == 0 {
		return nil, nil
	}

	//nolint:contextcheck // the pull request manager does not take a context
	return b.updateWorkflowPR(r, outdated, actionsTag, actionsHash)
}

// openWorkflowPR opens a pull request in the repository checking in the
// specified files. If the user does not have push access to the repository,
// the pull request is opened from the user's fork.
func (b *Backend) openWorkflowPR(
	r *models.Repository, title, body string, files []*repo.PullRequestFileEntry,
) (*models.PullRequest, error) {
	user, err := b.authenticator.WhoAmI()
	if err != nil {
		return nil, err
	}

	// We need to determine if the user needs a fork
	hasPush, err := b.checkPushAccess(r)
	if err != nil {
		return nil, fmt.Errorf("checking for repository push access: %w", err)
	}

	// If user does not have push access, use a fork
	if !hasPush {
		if err := b.CheckWorkflowFork(r); err != nil {
			return nil, fmt.Errorf("checking for required repository fork: %w", err)
		}
	}

	// Create a PR manager
	prManager := repo.NewPullRequestManager(repo.WithAuthenticator(b.authenticator))
	prManager.Options.UseFork = !hasPush

	// Open the pull request
	pr, err := prManager.PullRequestFileList(
		r,
		&options.PullRequestFileListOptions{
			Title: title,
			Body:  body,
			CommitOptions: options.CommitOptions{
				Name:  user.GetLogin(),
				Email: commitEmailForActor(user),
			},
		},
		files,
	)
	if err != nil {
		return nil, fmt.Errorf("creating workflow pull request: %w", err)
	}

	// Success!
	return pr, nil
}

// buildWorkflowYAML renders the provenance workflow that will be added to the
// repository. The reusable workflow is pinned to the commit digest of the
// actions repository tag, while the tag name is added as a comment so that
// dependabot can keep the pin updated.
func buildWorkflowYAML(branches []*models.Branch, actionsTag, actionsDigest string) string {
	quotedBranchesList := make([]string, 0, len(branches))
	for _, b := range branches {
		quotedBranchesList = append(quotedBranchesList, fmt.Sprintf("%q", b.Name))
	}
	return fmt.Sprintf(
		workflowData, strings.Join(quotedBranchesList, ", "),
		ActionsOrg, ActionsRepo, actionsDigest, actionsTag,
	)
}

// commitEmailForActor returns the no-reply email address to use when authoring
// commits as the given actor. It's intended to handle the actions bot which
// uses a different email.
func commitEmailForActor(user *models.Actor) string {
	if user.GetLogin() == githubActionsBotLogin {
		return githubActionsBotEmail
	}
	return user.GetLogin() + "@users.noreply.github.com"
}

// CheckWorkflowFork verifies that the user has a fork of the repository
// we are configuring.
func (b *Backend) CheckWorkflowFork(r *models.Repository) error {
	// Create a PR manager
	prManager := repo.NewPullRequestManager(repo.WithAuthenticator(b.authenticator))

	// TODO(puerco): Support forkname from options
	_, err := prManager.CheckFork(r, "")
	return err
}

// searchPullRequestsByTitle searches the last open pull requests of a repo for
// the first one whose title contains any of the query strings.
func searchPullRequestsByTitle(ctx context.Context, client *github.Client, owner, repoName string, queries ...string) (*github.PullRequest, error) {
	prs, _, err := client.PullRequests.List(
		ctx, owner, repoName, &github.PullRequestListOptions{
			State: "open",
			// Search only the last 100
			ListOptions: github.ListOptions{
				Page:    0,
				PerPage: 100,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("listing pull requests: %w", err)
	}

	for _, pr := range prs {
		for _, query := range queries {
			if strings.Contains(pr.GetTitle(), query) {
				return pr, nil
			}
		}
	}
	return nil, nil
}

// FindWorkflowPR looks for an open pull request adding or updating the
// provenance workflow in the repository. Returns nil if none is found.
func (b *Backend) FindWorkflowPR(ctx context.Context, r *models.Repository) (*models.PullRequest, error) {
	owner, repoName, err := r.PathAsGitHubOwnerName()
	if err != nil {
		return nil, err
	}

	client, err := b.authenticator.GetGitHubClient()
	if err != nil {
		return nil, fmt.Errorf("getting GitHub client: %w", err)
	}

	pr, err := searchPullRequestsByTitle(
		ctx, client, owner, repoName, workflowCommitMessage, workflowUpdateCommitMessage,
	)
	if err != nil {
		return nil, fmt.Errorf("searching for provenance workflow pull request: %w", err)
	}

	if pr == nil {
		return nil, nil
	}

	return &models.PullRequest{
		Title:  pr.GetTitle(),
		Body:   pr.GetBody(),
		Number: pr.GetNumber(),
		Repo:   r,
	}, nil
}

func (b *Backend) CreateRepoRuleset(r *models.Repository, branches []*models.Branch) error {
	if r == nil {
		return errors.New("unable to create repo ruleset, repository not defined")
	}

	if branches == nil {
		return errors.New("unable to create repo ruleset, branch not set")
	}

	if len(branches) > 1 {
		return errors.New("protecting more than one branch at a time is not yet supported")
	}

	ghc, err := b.getGitHubConnection(r, branches[0].FullRef())
	if err != nil {
		return err
	}

	if err := ghc.EnableBranchRules(context.Background()); err != nil {
		return fmt.Errorf("enabling branch protection rules: %w", err)
	}

	return nil
}

func (b *Backend) CreateTagRuleset(r *models.Repository) error {
	if r == nil {
		return errors.New("unable to create tag ruleset, repository not defined")
	}

	ghc, err := b.getGitHubConnection(r, "")
	if err != nil {
		return err
	}

	if err := ghc.EnableTagRules(context.Background()); err != nil {
		return fmt.Errorf("enabling tag protection rules: %w", err)
	}

	return nil
}

// CreateRepositoryFork creates a fork of a repo into the logged-in user's org.
// Optionally the fork can have a different name than the original.
func (b *Backend) createRepositoryFork(
	src *models.Repository, forkName string,
) error {
	client, err := b.authenticator.GetGitHubClient()
	if err != nil {
		return fmt.Errorf("creating GitHub client: %w", err)
	}

	srcOrg, srcName, err := src.PathAsGitHubOwnerName()
	if err != nil {
		return err
	}

	if forkName == "" {
		forkName = srcName
	}

	// Create the fork
	_, resp, err := client.Repositories.CreateFork(
		context.Background(), srcOrg, srcName, &github.RepositoryCreateForkOptions{
			Name: forkName,
		},
	)

	// GitHub will return 202 for larger repos that are cloned async
	if err != nil && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("creating repository fork: %w", err)
	}

	return nil
}

// ControlPrecheck  checks if the prerequisites to enable the controls are OK
func (b *Backend) ControlPrecheck(
	r *models.Repository, branches []*models.Branch, config models.ControlConfiguration,
) (ok bool, remediationMessage string, remediateFn models.ControlPreRemediationFn, err error) {
	//nolint:exhaustive // Not all configs have prechecks
	switch config {
	case models.CONFIG_GEN_PROVENANCE:
		sino, err := b.checkPushAccess(r)
		if err != nil {
			return false, "", nil, fmt.Errorf("checking for push access: %w", err)
		}
		// If user has push access, everything is OK
		if sino {
			return true, "", nil, nil
		}

		// No push access, check if user has a fork
		if err := b.CheckWorkflowFork(r); err == nil {
			// Fork found, all ok
			return true, "", nil, nil
		}
		msg := "No fork found of repository %s\n"
		msg += "and user has no push access.\n\n"
		msg += "Would you like to create a fork in your account?\n"
		return false, fmt.Sprintf(msg, r.Path), func() (string, error) {
			if err := b.createRepositoryFork(r, ""); err != nil {
				return "", fmt.Errorf("creating repository fork: %w", err)
			}
			return "successfully created the repository fork", nil
		}, nil
	default:
		return true, "", nil, nil
	}
}

// ConfigureControls configure the SLSA controls in the repository
func (b *Backend) ConfigureControls(r *models.Repository, branches []*models.Branch, configs []models.ControlConfiguration) error {
	errs := []error{}
	for _, config := range configs {
		switch config {
		case models.CONFIG_BRANCH_RULES:
			if err := b.CreateRepoRuleset(r, branches); err != nil {
				if !errors.Is(err, models.ErrProtectionAlreadyInPlace) {
					errs = append(errs, fmt.Errorf("creating rules in the repository: %w", err))
				}
			}
		case models.CONFIG_GEN_PROVENANCE:
			if _, err := b.configureProvenanceWorkflow(context.Background(), r, branches); err != nil {
				if !errors.Is(err, models.ErrProtectionAlreadyInPlace) {
					errs = append(errs, fmt.Errorf("configuring SLSA source workflow: %w", err))
				}
			}
		case models.CONFIG_TAG_RULES:
			if err := b.CreateTagRuleset(r); err != nil {
				if !errors.Is(err, models.ErrProtectionAlreadyInPlace) {
					errs = append(errs, fmt.Errorf("opening SLSA source workflow pull request: %w", err))
				}
			}
		case models.CONFIG_POLICY:
			// Noop, this is not handled by the VCS handler
		default:
			errs = append(errs, fmt.Errorf("unknown configuration flag: %q", config))
		}
	}
	return errors.Join(errs...)
}

// GetLatestActionsTag queries GitHub and returns the name and commit digest
// of the latest release tag of the actions repository (ActionsOrg/ActionsRepo).
func (b *Backend) GetLatestActionsTag(ctx context.Context) (tag, digest string, err error) {
	client, err := b.authenticator.GetGitHubClient()
	if err != nil {
		return "", "", fmt.Errorf("getting GitHub client: %w", err)
	}

	return latestActionsTag(ctx, client)
}

// latestActionsTag lists all the tags of the actions repository and returns
// the name and commit digest of the tag with the highest release version.
func latestActionsTag(ctx context.Context, client *github.Client) (tag, digest string, err error) {
	tags := []*github.RepositoryTag{}
	opts := &github.ListOptions{PerPage: actionsTagsPerPage}
	for {
		page, resp, listErr := client.Repositories.ListTags(ctx, ActionsOrg, ActionsRepo, opts)
		if listErr != nil {
			return "", "", fmt.Errorf("listing tags of %s/%s: %w", ActionsOrg, ActionsRepo, listErr)
		}
		tags = append(tags, page...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	latest := latestReleaseTag(tags)
	if latest == nil {
		return "", "", fmt.Errorf("no release tags found in %s/%s", ActionsOrg, ActionsRepo)
	}

	if latest.GetCommit().GetSHA() == "" {
		return "", "", fmt.Errorf("tag %s of %s/%s has no commit digest", latest.GetName(), ActionsOrg, ActionsRepo)
	}

	return latest.GetName(), latest.GetCommit().GetSHA(), nil
}

// latestReleaseTag returns the tag with the highest release version. Only tags
// named as full semantic versions (vMAJOR.MINOR.PATCH) are considered, so
// prereleases, floating tags (eg v1) and tags not following the semver format
// are ignored. Returns nil when the list has no release tags.
func latestReleaseTag(tags []*github.RepositoryTag) *github.RepositoryTag {
	var latest *github.RepositoryTag
	for _, t := range tags {
		name := t.GetName()
		if !semver.IsValid(name) || semver.Canonical(name) != name || semver.Prerelease(name) != "" {
			continue
		}
		if latest == nil || semver.Compare(name, latest.GetName()) > 0 {
			latest = t
		}
	}
	return latest
}
