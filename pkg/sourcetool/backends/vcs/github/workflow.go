// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/google/go-github/v88/github"

	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

// workflowsDir is the directory where GitHub looks for actions workflows
const workflowsDir = ".github/workflows"

// legacyActionsRepos maps the repositories that hosted the SLSA source
// actions before they moved to ActionsOrg/ActionsRepo to the directory the
// actions lived in. Workflows calling actions from these locations need to
// be updated.
var legacyActionsRepos = map[string]string{
	"slsa-framework/source-actions":  "",
	"slsa-framework/slsa-source-poc": "actions/",
}

// actionsUsesRegexp matches the `uses:` lines of a workflow calling an action
// or a reusable workflow hosted in the current or any of the legacy SLSA
// actions repositories. The submatches capture the line prefix (up to and
// including any opening quote), the repository, the path of the action in the
// repository, the git reference, the closing quote and any trailing comment.
var actionsUsesRegexp = buildActionsUsesRegexp()

func buildActionsUsesRegexp() *regexp.Regexp {
	repos := make([]string, 0, len(legacyActionsRepos)+1)
	repos = append(repos, regexp.QuoteMeta(ActionsOrg+"/"+ActionsRepo))
	for _, r := range slices.Sorted(maps.Keys(legacyActionsRepos)) {
		repos = append(repos, regexp.QuoteMeta(r))
	}
	return regexp.MustCompile(
		`^(\s*(?:-\s+)?uses:\s*["']?)(` + strings.Join(repos, "|") + `)/([^@\s"']+)@([^\s"'#]+)(["']?)(\s*#.*)?\s*$`,
	)
}

// actionsReference is a reference to a SLSA action or reusable workflow
// found in a workflow file.
type actionsReference struct {
	// Line is the 1-based line number where the reference was found
	Line int
	// Repo is the GitHub repository (owner/name) hosting the action
	Repo string
	// Path of the action or reusable workflow inside the repository
	Path string
	// Ref is the git reference (branch, tag or digest) the action is pinned to
	Ref string
}

// IsLegacy returns true when the reference calls the action from a
// repository that no longer hosts the SLSA actions.
func (ar *actionsReference) IsLegacy() bool {
	_, ok := legacyActionsRepos[ar.Repo]
	return ok
}

// IsOutdated returns true when the reference calls the action from the
// current actions repository but is not pinned to the specified digest.
func (ar *actionsReference) IsOutdated(digest string) bool {
	return !ar.IsLegacy() && ar.Ref != digest
}

// CurrentPath returns the path of the referenced action in the current
// actions repository (ActionsOrg/ActionsRepo).
func (ar *actionsReference) CurrentPath() string {
	return strings.TrimPrefix(ar.Path, legacyActionsRepos[ar.Repo])
}

// findActionsReferences scans the contents of a workflow file and returns all
// the references to the SLSA actions it finds, current or legacy.
func findActionsReferences(content string) []*actionsReference {
	refs := []*actionsReference{}
	for i, line := range strings.Split(content, "\n") {
		m := actionsUsesRegexp.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		refs = append(refs, &actionsReference{
			Line: i + 1,
			Repo: m[2],
			Path: m[3],
			Ref:  m[4],
		})
	}
	return refs
}

// migrateActionsReferences rewrites the references to the SLSA actions found
// in a workflow which still call them from a legacy repository or which are
// not pinned to the specified digest. The rewritten references call the
// actions from ActionsOrg/ActionsRepo pinned to the digest of the specified
// tag, recording the tag in a comment so that dependabot can keep the pin
// updated. Returns the new contents and the number of lines changed.
func migrateActionsReferences(content, tag, digest string) (migrated string, changed int) {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		m := actionsUsesRegexp.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ref := &actionsReference{Repo: m[2], Path: m[3], Ref: m[4]}
		if !ref.IsLegacy() && !ref.IsOutdated(digest) {
			continue
		}
		lines[i] = fmt.Sprintf(
			"%s%s/%s/%s@%s%s # %s", m[1], ActionsOrg, ActionsRepo, ref.CurrentPath(), digest, m[5], tag,
		)
		changed++
	}
	return strings.Join(lines, "\n"), changed
}

// workflowFile is a GitHub actions workflow read from a repository
type workflowFile struct {
	// Path of the workflow file, relative to the repository root
	Path string
	// Content is the raw workflow file
	Content string
}

// readWorkflowFiles returns all the workflow files found in the repository
// at the specified git reference. If ref is empty, the repository default
// branch is read. Repositories without workflows return an empty list.
func readWorkflowFiles(ctx context.Context, client *github.Client, owner, repoName, ref string) ([]*workflowFile, error) {
	opts := &github.RepositoryContentGetOptions{Ref: ref}
	_, entries, resp, err := client.Repositories.GetContents(ctx, owner, repoName, workflowsDir, opts)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("listing %s: %w", workflowsDir, err)
	}

	files := []*workflowFile{}
	for _, entry := range entries {
		if entry.GetType() != "file" {
			continue
		}
		if ext := strings.ToLower(path.Ext(entry.GetName())); ext != ".yml" && ext != ".yaml" {
			continue
		}

		content, _, _, err := client.Repositories.GetContents(ctx, owner, repoName, entry.GetPath(), opts)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", entry.GetPath(), err)
		}
		if content == nil {
			return nil, fmt.Errorf("reading %s: no file contents returned", entry.GetPath())
		}
		data, err := content.GetContent()
		if err != nil {
			return nil, fmt.Errorf("decoding %s: %w", entry.GetPath(), err)
		}
		files = append(files, &workflowFile{
			Path:    entry.GetPath(),
			Content: data,
		})
	}
	return files, nil
}

// provenanceWorkflow is a workflow file calling the SLSA source actions
type provenanceWorkflow struct {
	*workflowFile
	// References are the calls to the SLSA actions found in the workflow
	References []*actionsReference
}

// IsLegacy returns true when the workflow calls any of the SLSA actions
// from a legacy repository.
func (pw *provenanceWorkflow) IsLegacy() bool {
	return slices.ContainsFunc(pw.References, func(ref *actionsReference) bool { return ref.IsLegacy() })
}

// IsOutdated returns true when the workflow calls any of the SLSA actions
// from the current actions repository without pinning them to the specified
// digest.
func (pw *provenanceWorkflow) IsOutdated(digest string) bool {
	return slices.ContainsFunc(pw.References, func(ref *actionsReference) bool { return ref.IsOutdated(digest) })
}

// NeedsUpdate returns true when the workflow calls any of the SLSA actions
// from a legacy repository or without pinning them to the specified digest.
func (pw *provenanceWorkflow) NeedsUpdate(digest string) bool {
	return pw.IsLegacy() || pw.IsOutdated(digest)
}

// LegacyRepos returns the deduplicated list of legacy repositories the
// workflow calls actions from, in the order they appear in the file.
func (pw *provenanceWorkflow) LegacyRepos() []string {
	repos := []string{}
	for _, ref := range pw.References {
		if ref.IsLegacy() && !slices.Contains(repos, ref.Repo) {
			repos = append(repos, ref.Repo)
		}
	}
	return repos
}

// toModel returns the public representation of the workflow, including the
// recommended action to update it when it calls actions from a legacy repo
// or when they are not pinned to the digest of the latest actions release
// (tag). When the digest is empty, only legacy references are checked.
func (pw *provenanceWorkflow) toModel(repo *models.Repository, tag, digest string) *models.ProvenanceWorkflow {
	res := &models.ProvenanceWorkflow{
		Path:               pw.Path,
		LegacyActionsRepos: pw.LegacyRepos(),
	}

	var message string
	switch {
	case res.IsLegacy():
		message = fmt.Sprintf(
			"Update %s to call the SLSA actions from %s/%s", pw.Path, ActionsOrg, ActionsRepo,
		)
	case digest != "" && pw.IsOutdated(digest):
		message = fmt.Sprintf(
			"Update %s to call the latest release of the SLSA actions (%s)", pw.Path, tag,
		)
	default:
		return res
	}

	res.RecommendedAction = &slsa.ControlRecommendedAction{
		Message: message,
		Command: fmt.Sprintf(
			"sourcetool setup controls --config=%s %s", models.CONFIG_GEN_PROVENANCE, repo.Path,
		),
	}
	return res
}

// findProvenanceWorkflows reads the workflows of a repository at the
// specified git reference and returns those calling the SLSA source actions.
func findProvenanceWorkflows(ctx context.Context, client *github.Client, owner, repoName, ref string) ([]*provenanceWorkflow, error) {
	files, err := readWorkflowFiles(ctx, client, owner, repoName, ref)
	if err != nil {
		return nil, fmt.Errorf("reading repository workflows: %w", err)
	}

	workflows := []*provenanceWorkflow{}
	for _, f := range files {
		refs := findActionsReferences(f.Content)
		if len(refs) == 0 {
			continue
		}
		workflows = append(workflows, &provenanceWorkflow{
			workflowFile: f,
			References:   refs,
		})
	}
	return workflows, nil
}

// FindProvenanceWorkflows returns the workflows in the branch that call the
// SLSA source actions, flagging those still calling them from a legacy
// repository or not pinned to the latest actions release.
func (b *Backend) FindProvenanceWorkflows(ctx context.Context, branch *models.Branch) ([]*models.ProvenanceWorkflow, error) {
	if branch == nil || branch.Repository == nil {
		return nil, errors.New("branch has no repository")
	}

	owner, repoName, err := branch.Repository.PathAsGitHubOwnerName()
	if err != nil {
		return nil, err
	}

	client, err := b.authenticator.GetGitHubClient()
	if err != nil {
		return nil, fmt.Errorf("getting GitHub client: %w", err)
	}

	workflows, err := findProvenanceWorkflows(ctx, client, owner, repoName, branch.GetName())
	if err != nil {
		return nil, err
	}

	// The latest release is only needed when there are workflows to check
	var actionsTag, actionsHash string
	if len(workflows) > 0 {
		actionsTag, actionsHash, err = latestActionsTag(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("getting latest actions tag: %w", err)
		}
	}

	res := make([]*models.ProvenanceWorkflow, 0, len(workflows))
	for _, wf := range workflows {
		res = append(res, wf.toModel(branch.Repository, actionsTag, actionsHash))
	}
	return res, nil
}
