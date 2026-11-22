// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package sourcetool

import (
	"errors"
	"testing"
	"time"

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
				i.ConfigureControlsReturns(syntErr)
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

func TestCreateBranchPolicy(t *testing.T) {
	t.Parallel()
	since := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	controlSet := func(names slsa.ControlNameSet) *slsa.ControlSet {
		cs := &slsa.ControlSet{RepoUri: "github.com/ok/repo", Branch: "main"}
		for _, name := range names {
			cs.AddControl(&slsa.Control{Name: name, State: slsa.StateActive, Since: &since})
		}
		return cs
	}

	for _, tc := range []struct {
		name      string
		controls  *slsa.ControlSet
		zeroSince bool
	}{
		{
			name:     "all level 1 controls active",
			controls: controlSet(slsa.Level1),
		},
		{
			// The GitHub backend reports the legacy branch controls only, so
			// the set routinely lacks controls that level 1 requires.
			name:      "level 1 controls incomplete",
			controls:  controlSet(slsa.ControlNameSet{slsa.SLSA_SOURCE_SCS_CONTINUITY}),
			zeroSince: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			i := &sourcetoolfakes.FakeToolImplementation{}
			i.GetBranchControlsReturns(tc.controls, nil)
			tool := &Tool{impl: i}

			p, err := tool.CreateBranchPolicy(
				t.Context(),
				&models.Repository{Hostname: "github.com", Path: "ok/repo"},
				[]*models.Branch{{Name: "main"}},
			)
			require.NoError(t, err)
			require.Len(t, p.GetProtectedBranches(), 1)

			branch := p.GetProtectedBranches()[0]
			require.Equal(t, string(slsa.SlsaSourceLevel1), branch.GetTargetSlsaSourceLevel())
			if tc.zeroSince {
				require.True(t, branch.GetSince().AsTime().IsZero())
			} else {
				require.True(t, branch.GetSince().AsTime().Equal(since))
			}
		})
	}
}
