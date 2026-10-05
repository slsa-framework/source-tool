// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

const (
	legacyWorkflow = `---
name: SLSA Source
on:
  push:
    branches: [ "main" ]
jobs:
  generate-provenance:
    permissions:
      contents: write
      id-token: write
    uses: slsa-framework/source-actions/.github/workflows/compute_slsa_source.yml@main
`
	currentWorkflow = `---
name: SLSA Source
jobs:
  generate-provenance:
    uses: slsa-framework/actions/.github/workflows/compute_slsa_source.yml@dea965cdca5e0cb422bf7b2653c9d15f678ad01c # v0.1.0
`
	unrelatedWorkflow = `---
name: Tests
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - run: go test ./...
`
)

func TestFindActionsReferences(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		content string
		expect  []*actionsReference
	}{
		{"empty", "", nil},
		{"no-references", unrelatedWorkflow, nil},
		{
			"reusable-workflow-legacy",
			legacyWorkflow,
			[]*actionsReference{{
				Line: 11, Repo: "slsa-framework/source-actions",
				Path: ".github/workflows/compute_slsa_source.yml", Ref: "main",
			}},
		},
		{
			"reusable-workflow-current-pinned",
			currentWorkflow,
			[]*actionsReference{{
				Line: 5, Repo: "slsa-framework/actions",
				Path: ".github/workflows/compute_slsa_source.yml", Ref: "dea965cdca5e0cb422bf7b2653c9d15f678ad01c",
			}},
		},
		{
			"step-action-poc-repo",
			"    steps:\n    - name: prov\n      uses: slsa-framework/slsa-source-poc/actions/slsa_with_provenance@main\n",
			[]*actionsReference{{
				Line: 3, Repo: "slsa-framework/slsa-source-poc",
				Path: "actions/slsa_with_provenance", Ref: "main",
			}},
		},
		{
			"quoted-reference",
			`      - uses: "slsa-framework/source-actions/slsa_with_provenance@v0.1.0"` + "\n",
			[]*actionsReference{{
				Line: 1, Repo: "slsa-framework/source-actions",
				Path: "slsa_with_provenance", Ref: "v0.1.0",
			}},
		},
		{
			"multiple-references",
			"    - uses: slsa-framework/source-actions/get_note@main\n    - uses: actions/checkout@v4\n    - uses: slsa-framework/actions/store_note@abc123 # v0.1.0\n",
			[]*actionsReference{
				{Line: 1, Repo: "slsa-framework/source-actions", Path: "get_note", Ref: "main"},
				{Line: 3, Repo: "slsa-framework/actions", Path: "store_note", Ref: "abc123"},
			},
		},
		{
			// Commented out lines and repos with similar names are ignored
			"ignored-lines",
			"    # uses: slsa-framework/source-actions/get_note@main\n    - uses: slsa-framework/actions-fork/get_note@main\n    - uses: other-org/source-actions/get_note@main\n",
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			refs := findActionsReferences(tc.content)
			if tc.expect == nil {
				assert.Empty(t, refs)
				return
			}
			assert.Equal(t, tc.expect, refs)
		})
	}
}

func TestActionsReferenceIsLegacy(t *testing.T) {
	t.Parallel()
	assert.True(t, (&actionsReference{Repo: "slsa-framework/source-actions"}).IsLegacy())
	assert.True(t, (&actionsReference{Repo: "slsa-framework/slsa-source-poc"}).IsLegacy())
	assert.False(t, (&actionsReference{Repo: "slsa-framework/actions"}).IsLegacy())
}

func TestActionsReferenceCurrentPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		repo, path, expect string
	}{
		{"slsa-framework/source-actions", ".github/workflows/compute_slsa_source.yml", ".github/workflows/compute_slsa_source.yml"},
		{"slsa-framework/source-actions", "slsa_with_provenance", "slsa_with_provenance"},
		{"slsa-framework/slsa-source-poc", ".github/workflows/compute_slsa_source.yml", ".github/workflows/compute_slsa_source.yml"},
		{"slsa-framework/slsa-source-poc", "actions/slsa_with_provenance", "slsa_with_provenance"},
		{"slsa-framework/actions", "store_note", "store_note"},
	} {
		assert.Equal(t, tc.expect, (&actionsReference{Repo: tc.repo, Path: tc.path}).CurrentPath(), tc.repo+"/"+tc.path)
	}
}

func TestMigrateActionsReferences(t *testing.T) {
	t.Parallel()
	const (
		tag    = "v0.1.0"
		digest = "dea965cdca5e0cb422bf7b2653c9d15f678ad01c"
	)
	for _, tc := range []struct {
		name          string
		content       string
		expect        string
		expectChanged int
	}{
		{"empty", "", "", 0},
		{"unrelated", unrelatedWorkflow, unrelatedWorkflow, 0},
		{"already-current", currentWorkflow, currentWorkflow, 0},
		{
			"reusable-workflow",
			legacyWorkflow,
			strings.Replace(
				legacyWorkflow,
				"    uses: slsa-framework/source-actions/.github/workflows/compute_slsa_source.yml@main",
				"    uses: slsa-framework/actions/.github/workflows/compute_slsa_source.yml@"+digest+" # "+tag,
				1,
			),
			1,
		},
		{
			// The poc repo hosted the actions under actions/, the path is fixed
			"poc-action-path",
			"    steps:\n    - name: prov\n      uses: slsa-framework/slsa-source-poc/actions/slsa_with_provenance@main\n      with:\n        version: v0.6.2\n",
			"    steps:\n    - name: prov\n      uses: slsa-framework/actions/slsa_with_provenance@" + digest + " # " + tag + "\n      with:\n        version: v0.6.2\n",
			1,
		},
		{
			// Quotes are preserved and old comments replaced
			"quoted-with-comment",
			`  uses: "slsa-framework/source-actions/get_note@abc123" # v0.0.1` + "\n",
			`  uses: "slsa-framework/actions/get_note@` + digest + `" # ` + tag + "\n",
			1,
		},
		{
			"mixed-references",
			"    - uses: slsa-framework/source-actions/get_note@main\n    - uses: actions/checkout@v4\n    - uses: slsa-framework/actions/store_note@abc123 # v0.0.9\n    - uses: slsa-framework/slsa-source-poc/actions/store_note@main\n",
			"    - uses: slsa-framework/actions/get_note@" + digest + " # " + tag + "\n    - uses: actions/checkout@v4\n    - uses: slsa-framework/actions/store_note@" + digest + " # " + tag + "\n    - uses: slsa-framework/actions/store_note@" + digest + " # " + tag + "\n",
			3,
		},
		{
			// References to the current repo on a branch are pinned
			"current-repo-branch",
			"    uses: slsa-framework/actions/.github/workflows/compute_slsa_source.yml@main\n",
			"    uses: slsa-framework/actions/.github/workflows/compute_slsa_source.yml@" + digest + " # " + tag + "\n",
			1,
		},
		{
			// References pinned to an older release are bumped
			"current-repo-old-release",
			"    uses: slsa-framework/actions/.github/workflows/compute_slsa_source.yml@0123456789abcdef0123456789abcdef01234567 # v0.0.9\n",
			"    uses: slsa-framework/actions/.github/workflows/compute_slsa_source.yml@" + digest + " # " + tag + "\n",
			1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, changed := migrateActionsReferences(tc.content, tag, digest)
			assert.Equal(t, tc.expectChanged, changed)
			assert.Equal(t, tc.expect, res)

			// Migrated content must not reference any legacy repo anymore
			// and all references must be pinned to the release digest
			for _, ref := range findActionsReferences(res) {
				assert.False(t, ref.IsLegacy(), "line %d still references %s", ref.Line, ref.Repo)
				assert.False(t, ref.IsOutdated(digest), "line %d is pinned to %s", ref.Line, ref.Ref)
			}
		})
	}
}

// contentsHandler returns a mock handler for the repository contents API
// serving the workflows directory listing and the file contents from files.
func contentsHandler(t *testing.T, files map[string]string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Directory listing
		if strings.HasSuffix(r.URL.Path, "/contents/"+workflowsDir) {
			listing := make([]*github.RepositoryContent, 0, len(files)+2)
			listing = append(listing,
				&github.RepositoryContent{Type: github.Ptr("dir"), Name: github.Ptr("scripts"), Path: github.Ptr(workflowsDir + "/scripts")},
				&github.RepositoryContent{Type: github.Ptr("file"), Name: github.Ptr("README.md"), Path: github.Ptr(workflowsDir + "/README.md")},
			)
			for name := range files {
				listing = append(listing, &github.RepositoryContent{
					Type: github.Ptr("file"), Name: github.Ptr(name), Path: github.Ptr(workflowsDir + "/" + name),
				})
			}
			_, err := w.Write(mock.MustMarshal(listing))
			assert.NoError(t, err)
			return
		}

		// File contents
		for name, content := range files {
			if !strings.HasSuffix(r.URL.Path, "/contents/"+workflowsDir+"/"+name) {
				continue
			}
			_, err := w.Write(mock.MustMarshal(&github.RepositoryContent{
				Type:     github.Ptr("file"),
				Name:     github.Ptr(name),
				Path:     github.Ptr(workflowsDir + "/" + name),
				Encoding: github.Ptr("base64"),
				Content:  github.Ptr(base64.StdEncoding.EncodeToString([]byte(content))),
			}))
			assert.NoError(t, err)
			return
		}
		mock.WriteError(w, http.StatusNotFound, "not found")
	})
}

func TestFindProvenanceWorkflows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		mockOption mock.MockBackendOption
		expect     []*models.ProvenanceWorkflow
		mustErr    bool
	}{
		{
			name: "legacy-and-current",
			mockOption: mock.WithRequestMatchHandler(
				mock.GetReposContentsByOwnerByRepoByPath,
				contentsHandler(t, map[string]string{
					"legacy.yml":  legacyWorkflow,
					"slsa.yaml":   currentWorkflow,
					"tests.yml":   unrelatedWorkflow,
					"notes.txt":   legacyWorkflow, // not a workflow, must be skipped
					"nested.YAML": "    - uses: slsa-framework/slsa-source-poc/actions/get_note@main\n    - uses: slsa-framework/source-actions/store_note@main\n",
				}),
			),
			expect: []*models.ProvenanceWorkflow{
				{
					Path:               workflowsDir + "/legacy.yml",
					LegacyActionsRepos: []string{"slsa-framework/source-actions"},
				},
				{
					Path:               workflowsDir + "/nested.YAML",
					LegacyActionsRepos: []string{"slsa-framework/slsa-source-poc", "slsa-framework/source-actions"},
				},
				{
					Path:               workflowsDir + "/slsa.yaml",
					LegacyActionsRepos: []string{},
				},
			},
		},
		{
			name: "no-workflows-dir",
			mockOption: mock.WithRequestMatchHandler(
				mock.GetReposContentsByOwnerByRepoByPath,
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					mock.WriteError(w, http.StatusNotFound, "not found")
				}),
			),
			expect: []*models.ProvenanceWorkflow{},
		},
		{
			name: "no-provenance-workflows",
			mockOption: mock.WithRequestMatchHandler(
				mock.GetReposContentsByOwnerByRepoByPath,
				contentsHandler(t, map[string]string{"tests.yml": unrelatedWorkflow}),
			),
			expect: []*models.ProvenanceWorkflow{},
		},
		{
			name: "api-error",
			mockOption: mock.WithRequestMatchHandler(
				mock.GetReposContentsByOwnerByRepoByPath,
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					mock.WriteError(w, http.StatusInternalServerError, "boom")
				}),
			),
			mustErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client, err := github.NewClient(github.WithHTTPClient(mock.NewMockedHTTPClient(tc.mockOption)))
			require.NoError(t, err)

			workflows, err := findProvenanceWorkflows(t.Context(), client, "owner", "repo", "main")
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Sort by path as the mock directory listing order is not stable
			res := make([]*models.ProvenanceWorkflow, 0, len(workflows))
			for _, wf := range workflows {
				res = append(res, wf.toModel(
					&models.Repository{Path: "owner/repo"}, "v0.1.0", "dea965cdca5e0cb422bf7b2653c9d15f678ad01c",
				))
			}
			sortWorkflows(res)

			require.Len(t, res, len(tc.expect))
			for i := range tc.expect {
				assert.Equal(t, tc.expect[i].Path, res[i].Path)
				assert.Equal(t, tc.expect[i].LegacyActionsRepos, res[i].LegacyActionsRepos)
				assert.Equal(t, tc.expect[i].IsLegacy(), res[i].IsLegacy())
				if tc.expect[i].IsLegacy() {
					require.NotNil(t, res[i].RecommendedAction)
					assert.Contains(t, res[i].RecommendedAction.Message, res[i].Path)
					assert.Contains(t, res[i].RecommendedAction.Message, ActionsOrg+"/"+ActionsRepo)
					assert.Equal(
						t, "sourcetool setup controls --config=CONFIG_GEN_PROVENANCE owner/repo",
						res[i].RecommendedAction.Command,
					)
				} else {
					assert.Nil(t, res[i].RecommendedAction)
				}
			}
		})
	}
}

func TestProvenanceWorkflowOutdated(t *testing.T) {
	t.Parallel()
	const (
		tag       = "v0.2.0"
		digest    = "0123456789abcdef0123456789abcdef01234567"
		oldDigest = "dea965cdca5e0cb422bf7b2653c9d15f678ad01c"
	)
	repo := &models.Repository{Path: "owner/repo"}
	wf := &provenanceWorkflow{
		workflowFile: &workflowFile{Path: workflowsDir + "/slsa.yaml", Content: currentWorkflow},
		References:   findActionsReferences(currentWorkflow),
	}

	// Pinned to the latest release: nothing to do
	assert.False(t, wf.IsOutdated(oldDigest))
	assert.False(t, wf.NeedsUpdate(oldDigest))
	assert.Nil(t, wf.toModel(repo, "v0.1.0", oldDigest).RecommendedAction)

	// A newer release is out: the workflow needs an update but is not legacy
	assert.True(t, wf.IsOutdated(digest))
	assert.True(t, wf.NeedsUpdate(digest))
	res := wf.toModel(repo, tag, digest)
	assert.False(t, res.IsLegacy())
	require.NotNil(t, res.RecommendedAction)
	assert.Contains(t, res.RecommendedAction.Message, wf.Path)
	assert.Contains(t, res.RecommendedAction.Message, tag)
	assert.Equal(
		t, "sourcetool setup controls --config=CONFIG_GEN_PROVENANCE owner/repo",
		res.RecommendedAction.Command,
	)

	// Without a release digest only legacy references are flagged
	assert.Nil(t, wf.toModel(repo, "", "").RecommendedAction)
}

func sortWorkflows(workflows []*models.ProvenanceWorkflow) {
	for i := range workflows {
		for j := i + 1; j < len(workflows); j++ {
			if workflows[j].Path < workflows[i].Path {
				workflows[i], workflows[j] = workflows[j], workflows[i]
			}
		}
	}
}
