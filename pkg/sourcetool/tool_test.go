// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package sourcetool

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/slsa-source-poc/pkg/slsa"
	"github.com/slsa-framework/slsa-source-poc/pkg/sourcetool/models"
	"github.com/slsa-framework/slsa-source-poc/pkg/sourcetool/models/modelsfakes"
	"github.com/slsa-framework/slsa-source-poc/pkg/sourcetool/sourcetoolfakes"
)

func TestGetBranchControls(t *testing.T) {
	t.Parallel()
	t.Run("GetActiveControls-success", func(t *testing.T) {
		t.Parallel()
		i := &sourcetoolfakes.FakeToolImplementation{}
		i.GetPolicyStatusReturns(&slsa.ControlStatus{}, nil)
		i.GetBranchControlsReturns(&slsa.ControlSetStatus{
			RepoUri: "github.com/ok/repo",
			Branch:  "main",
			Controls: []slsa.ControlStatus{
				{
					Name:    slsa.ContinuityEnforced,
					State:   slsa.StateNotEnabled,
					Message: "Continuity enforced",
				},
			},
		}, nil)
		tool := &Tool{
			impl: i,
		}
		res, err := tool.GetBranchControls(&models.Repository{}, &models.Branch{})
		require.NotNil(t, res)
		// This always has one more as we add the synyhetic policy check
		require.Len(t, res.Controls, 2)
		require.NoError(t, err)
	})
	t.Run("GetActiveControls-fails", func(t *testing.T) {
		t.Parallel()
		i := &sourcetoolfakes.FakeToolImplementation{}
		i.GetBranchControlsReturns(nil, errors.New("failed badly"))
		tool := &Tool{
			impl: i,
		}
		_, err := tool.GetBranchControls(&models.Repository{}, &models.Branch{})
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
			name: "GetVcsBackend-fails", mustErr: true,
			controls: []models.ControlConfiguration{models.CONFIG_BRANCH_RULES},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.GetVcsBackendReturns(nil, syntErr)
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
				i.GetVcsBackendReturns(&modelsfakes.FakeVcsBackend{}, nil)
				i.GetAttestationReaderReturns(&modelsfakes.FakeAttestationStorageReader{}, nil)
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

			err := tool.ConfigureControls(&models.Repository{}, []*models.Branch{{}}, tc.controls)
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
					Path:          "slsa-framework/slsa-source-poc",
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
						Path:          "slsa-framework/slsa-source-poc",
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

			prd, err := tool.FindPolicyPR(&models.Repository{})
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
			found, err := tool.CheckPolicyRepoFork()
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
		getSut  func(t *testing.T) toolImplementation
		mustErr bool
	}{
		{"normal", func(t *testing.T) toolImplementation {
			t.Helper()
			timp := &sourcetoolfakes.FakeToolImplementation{}
			timp.GetVcsBackendReturns(&modelsfakes.FakeVcsBackend{}, nil)
			timp.VerifyOptionsForFullOnboardReturns(nil)
			timp.ConfigureControlsReturns(nil)
			return timp
		}, false},
		{"get-vcs-fails", func(t *testing.T) toolImplementation {
			t.Helper()
			timp := &sourcetoolfakes.FakeToolImplementation{}
			timp.GetVcsBackendReturns(nil, errors.New("vcsborked"))
			timp.VerifyOptionsForFullOnboardReturns(nil)
			timp.ConfigureControlsReturns(nil)
			return timp
		}, true},
		{"get-verifyoptions-fails", func(t *testing.T) toolImplementation {
			t.Helper()
			timp := &sourcetoolfakes.FakeToolImplementation{}
			timp.GetVcsBackendReturns(&modelsfakes.FakeVcsBackend{}, nil)
			timp.VerifyOptionsForFullOnboardReturns(errors.New("onboarderr"))
			return timp
		}, true},
		{"backend-configure-controls-fails", func(t *testing.T) toolImplementation {
			t.Helper()
			bend := modelsfakes.FakeVcsBackend{}
			bend.ConfigureControlsReturns(errors.New("configure-error"))

			timp := &sourcetoolfakes.FakeToolImplementation{}
			timp.GetVcsBackendReturns(&bend, nil)
			timp.VerifyOptionsForFullOnboardReturns(nil)
			return timp
		}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			impl := tt.getSut(t)
			tool, err := New()
			require.NoError(t, err)
			tool.impl = impl
			err = tool.OnboardRepository(&models.Repository{Path: "example/repo"}, []*models.Branch{{Name: "main"}})
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
