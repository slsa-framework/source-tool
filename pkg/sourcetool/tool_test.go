// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package sourcetool

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models/modelsfakes"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/sourcetoolfakes"
)

func TestFindProvenanceWorkflows(t *testing.T) {
	t.Parallel()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		backend := &modelsfakes.FakeVcsBackend{}
		backend.FindProvenanceWorkflowsReturns([]*models.ProvenanceWorkflow{
			{Path: ".github/workflows/slsa.yml", LegacyActionsRepos: []string{"slsa-framework/source-actions"}},
		}, nil)
		tool := &Tool{backend: backend}
		res, err := tool.FindProvenanceWorkflows(t.Context(), &models.Branch{Name: "main", Repository: &models.Repository{}})
		require.NoError(t, err)
		require.Len(t, res, 1)
		require.True(t, res[0].IsLegacy())
		require.Equal(t, 1, backend.FindProvenanceWorkflowsCallCount())
	})
	t.Run("no-repository", func(t *testing.T) {
		t.Parallel()
		backend := &modelsfakes.FakeVcsBackend{}
		tool := &Tool{backend: backend}
		_, err := tool.FindProvenanceWorkflows(t.Context(), &models.Branch{Name: "main"})
		require.Error(t, err)
		require.Equal(t, 0, backend.FindProvenanceWorkflowsCallCount())
	})
	t.Run("backend-fails", func(t *testing.T) {
		t.Parallel()
		backend := &modelsfakes.FakeVcsBackend{}
		backend.FindProvenanceWorkflowsReturns(nil, errors.New("failed badly"))
		tool := &Tool{backend: backend}
		_, err := tool.FindProvenanceWorkflows(t.Context(), &models.Branch{Name: "main", Repository: &models.Repository{}})
		require.Error(t, err)
	})
}

func TestGetBranchControls(t *testing.T) {
	t.Parallel()
	t.Run("GetActiveControls-success", func(t *testing.T) {
		t.Parallel()
		i := &sourcetoolfakes.FakeToolImplementation{}
		i.GetPolicyStatusReturns(&slsa.Control{}, nil)
		i.GetBranchControlsReturns(&slsa.ControlSet{
			RepoUri: "github.com/ok/repo",
			Branch:  "main",
			Controls: []*slsa.Control{
				{
					Name:    slsa.SLSA_SOURCE_SCS_CONTINUITY,
					State:   slsa.StateNotEnabled,
					Message: "Continuity enforced",
				},
			},
		}, nil)
		tool := &Tool{
			impl: i,
		}
		res, err := tool.GetBranchControls(t.Context(), &models.Branch{Repository: &models.Repository{}})
		require.NoError(t, err)
		require.NotNil(t, res)
		// This always has one more as we add the synyhetic policy check
		require.Len(t, res.Controls, 2)
	})
	t.Run("GetActiveControls-fails", func(t *testing.T) {
		t.Parallel()
		i := &sourcetoolfakes.FakeToolImplementation{}
		i.GetBranchControlsReturns(nil, errors.New("failed badly"))
		tool := &Tool{
			impl: i,
		}
		_, err := tool.GetBranchControls(t.Context(), &models.Branch{})
		require.Error(t, err)
	})
}

func TestConfigureControls(t *testing.T) {
	t.Parallel()
	syntErr := errors.New("synthetic error")
	for _, tc := range []struct {
		name     string
		mustErr  bool
		controls []models.ControlConfiguration
		prepare  func(t *testing.T) toolImplementation
	}{
		{
			name: "success", mustErr: false,
			controls: []models.ControlConfiguration{models.CONFIG_BRANCH_RULES},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				return i
			},
		},
		{
			name: "CheckPolicyFork-fails", mustErr: true,
			controls: []models.ControlConfiguration{models.CONFIG_POLICY},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CheckPolicyForkReturns(syntErr)
				return i
			},
		},
		{
			name: "CreatePolicyPR-fails", mustErr: true,
			controls: []models.ControlConfiguration{models.CONFIG_POLICY},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CreatePolicyPRReturns(nil, syntErr)
				return i
			},
		},
		{
			name: "ConfigureControls-fails", mustErr: true,
			controls: []models.ControlConfiguration{models.CONFIG_GEN_PROVENANCE},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.ConfigureControlsReturns(nil, syntErr)
				return i
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			i := tc.prepare(t)
			tool := Tool{
				impl: i,
			}

			err := tool.ConfigureControls(t.Context(), &models.Repository{}, []*models.Branch{{}}, tc.controls)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestFindPolicyPR(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		mustErr bool
		expect  *models.PullRequest
		prepare func(t *testing.T) toolImplementation
	}{
		{
			"normal", false, nil, func(t *testing.T) toolImplementation {
				t.Helper()
				i := sourcetoolfakes.FakeToolImplementation{}
				return &i
			},
		},
		{
			"search-pr-fails", true, nil, func(t *testing.T) toolImplementation {
				t.Helper()
				i := sourcetoolfakes.FakeToolImplementation{}
				i.SearchPullRequestReturns(nil, errors.New("failed"))
				return &i
			},
		},
		{
			"pr-is-zero", false, nil, func(t *testing.T) toolImplementation {
				t.Helper()
				i := sourcetoolfakes.FakeToolImplementation{}
				i.SearchPullRequestReturns(nil, nil)
				return &i
			},
		},
		{
			"pr-is-found", false, &models.PullRequest{
				Repo: &models.Repository{
					Hostname:      "github.com",
					Path:          "slsa-framework/source-tool",
					DefaultBranch: "",
				},
				Number: 10,
				Title:  "Pull Request",
				Body:   "Here",
			}, func(t *testing.T) toolImplementation {
				t.Helper()
				i := sourcetoolfakes.FakeToolImplementation{}
				i.SearchPullRequestReturns(&models.PullRequest{
					Repo: &models.Repository{
						Hostname:      "github.com",
						Path:          "slsa-framework/source-tool",
						DefaultBranch: "",
					},
					Number: 10,
					Title:  "Pull Request",
					Body:   "Here",
				}, nil)
				return &i
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tool := Tool{
				impl: tc.prepare(t),
			}

			prd, err := tool.FindPolicyPR(t.Context(), &models.Repository{})
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expect, prd)
		})
	}
}

func TestCheckPolicyFork(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		mustErr bool
		expect  bool
		prepare func(t *testing.T) toolImplementation
	}{
		{
			"normal", false, true, func(t *testing.T) toolImplementation {
				t.Helper()
				i := sourcetoolfakes.FakeToolImplementation{}
				return &i
			},
		},
		{
			"call-fails", true, true, func(t *testing.T) toolImplementation {
				t.Helper()
				i := sourcetoolfakes.FakeToolImplementation{}
				i.CheckPolicyForkReturns(errors.New("some error"))
				return &i
			},
		},
		{
			"not-found", false, false, func(t *testing.T) toolImplementation {
				t.Helper()
				i := sourcetoolfakes.FakeToolImplementation{}
				i.CheckPolicyForkReturns(errors.New("404 Not Found"))
				return &i
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tool := Tool{impl: tc.prepare(t)}
			found, err := tool.CheckPolicyRepoFork(t.Context())
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expect, found)
		})
	}
}

func TestCreatePolicyRepoFork(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		getSut  func(t *testing.T) toolImplementation
		mustErr bool
	}{
		{"normal", func(t *testing.T) toolImplementation {
			t.Helper()
			timp := &sourcetoolfakes.FakeToolImplementation{}
			timp.CreateRepositoryForkReturns(nil)
			return timp
		}, false},
		{"create-fork-fails", func(t *testing.T) toolImplementation {
			t.Helper()
			timp := &sourcetoolfakes.FakeToolImplementation{}
			timp.CreateRepositoryForkReturns(errors.New("error"))
			return timp
		}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			impl := tt.getSut(t)
			tool, err := New()
			require.NoError(t, err)
			tool.impl = impl
			err = tool.CreatePolicyRepoFork(t.Context())
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestOnboardRepository(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		impl    func(t *testing.T) toolImplementation
		backend func(t *testing.T) models.VcsBackend
		mustErr bool
	}{
		{
			name: "normal",
			impl: func(t *testing.T) toolImplementation {
				t.Helper()
				timp := &sourcetoolfakes.FakeToolImplementation{}
				timp.VerifyOptionsForFullOnboardReturns(nil)
				return timp
			},
			backend: func(t *testing.T) models.VcsBackend {
				t.Helper()
				return &modelsfakes.FakeVcsBackend{}
			},
			mustErr: false,
		},
		{
			name: "get-verifyoptions-fails",
			impl: func(t *testing.T) toolImplementation {
				t.Helper()
				timp := &sourcetoolfakes.FakeToolImplementation{}
				timp.VerifyOptionsForFullOnboardReturns(errors.New("onboarderr"))
				return timp
			},
			backend: func(t *testing.T) models.VcsBackend {
				t.Helper()
				return &modelsfakes.FakeVcsBackend{}
			},
			mustErr: true,
		},
		{
			name: "backend-configure-controls-fails",
			impl: func(t *testing.T) toolImplementation {
				t.Helper()
				timp := &sourcetoolfakes.FakeToolImplementation{}
				timp.VerifyOptionsForFullOnboardReturns(nil)
				return timp
			},
			backend: func(t *testing.T) models.VcsBackend {
				t.Helper()
				bend := &modelsfakes.FakeVcsBackend{}
				bend.ConfigureControlsReturns(errors.New("configure-error"))
				return bend
			},
			mustErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tool := &Tool{
				impl:    tt.impl(t),
				backend: tt.backend(t),
			}
			err := tool.OnboardRepository(t.Context(), &models.Repository{Path: "example/repo"}, []*models.Branch{{Name: "main"}})
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// reportingBackend is a VCS backend that reports what it did when configuring
// the controls.
type reportingBackend struct {
	modelsfakes.FakeVcsBackend
	results []*models.ControlConfigurationResult
}

func (rb *reportingBackend) ConfigureControlsWithResults(
	*models.Repository, []*models.Branch, []models.ControlConfiguration,
) ([]*models.ControlConfigurationResult, error) {
	return rb.results, nil
}

func TestConfigureControlsWithResults(t *testing.T) {
	t.Parallel()
	repo := &models.Repository{Hostname: "github.com", Path: "example/repo"}
	branches := []*models.Branch{{Name: "main", Repository: repo}}

	t.Run("reporting-backend", func(t *testing.T) {
		t.Parallel()
		backend := &reportingBackend{
			results: []*models.ControlConfigurationResult{
				{Config: models.CONFIG_GEN_PROVENANCE, Message: "nothing to do"},
			},
		}
		tool := Tool{impl: &defaultToolImplementation{}, backend: backend}

		results, err := tool.ConfigureControlsWithResults(
			t.Context(), repo, branches, []models.ControlConfiguration{models.CONFIG_GEN_PROVENANCE},
		)
		require.NoError(t, err)
		require.Equal(t, backend.results, results)
		require.Zero(t, backend.ConfigureControlsCallCount())
	})

	t.Run("non-reporting-backend", func(t *testing.T) {
		t.Parallel()
		backend := &modelsfakes.FakeVcsBackend{}
		tool := Tool{impl: &defaultToolImplementation{}, backend: backend}

		results, err := tool.ConfigureControlsWithResults(
			t.Context(), repo, branches, []models.ControlConfiguration{models.CONFIG_BRANCH_RULES},
		)
		require.NoError(t, err)
		require.Empty(t, results)
		require.Equal(t, 1, backend.ConfigureControlsCallCount())
	})

	t.Run("policy-pull-request", func(t *testing.T) {
		t.Parallel()
		pr := &models.PullRequest{
			Number: 12,
			Repo:   &models.Repository{Hostname: "github.com", Path: "example/policy"},
		}
		impl := &sourcetoolfakes.FakeToolImplementation{}
		impl.CreatePolicyPRReturns(pr, nil)
		tool := Tool{impl: impl, backend: &modelsfakes.FakeVcsBackend{}}

		results, err := tool.ConfigureControlsWithResults(
			t.Context(), repo, branches, []models.ControlConfiguration{models.CONFIG_POLICY},
		)
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.Equal(t, models.CONFIG_POLICY, results[0].Config)
		require.True(t, results[0].Changed)
		require.Equal(t, pr, results[0].PullRequest)
		require.Contains(t, results[0].Message, "https://github.com/example/policy/pull/12")
	})
}

func TestOnboardRepositoryWithResults(t *testing.T) {
	t.Parallel()
	repo := &models.Repository{Hostname: "github.com", Path: "example/repo"}
	branches := []*models.Branch{{Name: "main", Repository: repo}}

	t.Run("reporting-backend", func(t *testing.T) {
		t.Parallel()
		backend := &reportingBackend{
			results: []*models.ControlConfigurationResult{
				{Config: models.CONFIG_BRANCH_RULES, Changed: true, Message: "enabled"},
				{Config: models.CONFIG_GEN_PROVENANCE, Message: "nothing to do"},
			},
		}
		tool := Tool{impl: &sourcetoolfakes.FakeToolImplementation{}, backend: backend}

		results, err := tool.OnboardRepositoryWithResults(t.Context(), repo, branches)
		require.NoError(t, err)
		require.Equal(t, backend.results, results)
		require.Zero(t, backend.ConfigureControlsCallCount())
	})

	t.Run("non-reporting-backend", func(t *testing.T) {
		t.Parallel()
		backend := &modelsfakes.FakeVcsBackend{}
		tool := Tool{impl: &sourcetoolfakes.FakeToolImplementation{}, backend: backend}

		results, err := tool.OnboardRepositoryWithResults(t.Context(), repo, branches)
		require.NoError(t, err)
		require.Empty(t, results)
		require.Equal(t, 1, backend.ConfigureControlsCallCount())
	})
}
