package sourcetool

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/models"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/sourcetoolfakes"
)

func TestGetBranchControls(t *testing.T) {
	t.Parallel()
	t.Run("GetActiveControls-success", func(t *testing.T) {
		t.Parallel()
		i := &sourcetoolfakes.FakeToolImplementation{}
		i.GetBranchControlsReturns(&slsa.Controls{{}}, nil)
		tool := &Tool{
			impl: i,
		}
		res, err := tool.GetBranchControls(&models.Branch{})
		require.NotNil(t, res)
		require.Len(t, *res, 1)
		require.NoError(t, err)
	})
	t.Run("GetActiveControls-fails", func(t *testing.T) {
		t.Parallel()
		i := &sourcetoolfakes.FakeToolImplementation{}
		i.GetBranchControlsReturns(nil, errors.New("failed badly"))
		tool := &Tool{
			impl: i,
		}
		_, err := tool.GetBranchControls(&models.Branch{})
		require.Error(t, err)
	})
}

// func TestOnboardRepository(t *testing.T) {
// 	t.Parallel()
// 	syntErr := errors.New("synthetic error")
// 	for _, tc := range []struct {
// 		name    string
// 		prepare func(t *testing.T) toolImplementation
// 		mustErr bool
// 	}{
// 		{
// 			name: "EnsureDefault-fails", mustErr: true,
// 			prepare: func(t *testing.T) toolImplementation {
// 				t.Helper()
// 				i := &sourcetoolfakes.FakeToolImplementation{}
// 				i.EnsureDefaultsReturns(syntErr)
// 				return i
// 			},
// 		},
// 		{
// 			name: "CheckForks-fails", mustErr: true,
// 			prepare: func(t *testing.T) toolImplementation {
// 				t.Helper()
// 				i := &sourcetoolfakes.FakeToolImplementation{}
// 				i.CheckForksReturns(syntErr)
// 				return i
// 			},
// 		},
// 		{
// 			name: "VerifyOptionsForFullOnboard-fails", mustErr: true,
// 			prepare: func(t *testing.T) toolImplementation {
// 				t.Helper()
// 				i := &sourcetoolfakes.FakeToolImplementation{}
// 				i.VerifyOptionsForFullOnboardReturns(syntErr)
// 				return i
// 			},
// 		},
// 		// {
// 		// 	name: "CreateRepoRuleset-fails", mustErr: true,
// 		// 	prepare: func(t *testing.T) toolImplementation {
// 		// 		t.Helper()
// 		// 		i := &sourcetoolfakes.FakeToolImplementation{}
// 		// 		i.CreateRepoRulesetReturns(syntErr)
// 		// 		return i
// 		// 	},
// 		// },
// 		// {
// 		// 	name: "CheckForksCreateWorkflowPRfails", mustErr: true,
// 		// 	prepare: func(t *testing.T) toolImplementation {
// 		// 		t.Helper()
// 		// 		i := &sourcetoolfakes.FakeToolImplementation{}
// 		// 		i.CreateWorkflowPRReturns(syntErr)
// 		// 		return i
// 		// 	},
// 		// },
// 		{
// 			name: "CreatePolicyPRfails", mustErr: true,
// 			prepare: func(t *testing.T) toolImplementation {
// 				t.Helper()
// 				i := &sourcetoolfakes.FakeToolImplementation{}
// 				i.CreatePolicyPRReturns(syntErr)
// 				return i
// 			},
// 		},
// 		{
// 			name: "all-success", mustErr: false,
// 			prepare: func(t *testing.T) toolImplementation {
// 				t.Helper()
// 				i := &sourcetoolfakes.FakeToolImplementation{}
// 				return i
// 			},
// 		},
// 	} {
// 		t.Run(tc.name, func(t *testing.T) {
// 			t.Parallel()
// 			tool := &Tool{
// 				Options: options.Options{},
// 				impl:    tc.prepare(t),
// 			}
// 			err := tool.OnboardRepository()
// 			if tc.mustErr {
// 				require.Error(t, err)
// 				return
// 			}
// 			require.NoError(t, err)
// 		})
// 	}
// }

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
				i.CreatePolicyPRReturns(syntErr)
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
		expect  *PullRequestDetails
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
				i.SearchPullRequestReturns(0, errors.New("failed"))
				return &i
			},
		},
		{
			"pr-is-zero", false, nil, func(t *testing.T) toolImplementation {
				t.Helper()
				i := sourcetoolfakes.FakeToolImplementation{}
				i.SearchPullRequestReturns(0, nil)
				return &i
			},
		},
		{
			"pr-is-found", false, &PullRequestDetails{
				Owner:  "slsa-framework",
				Repo:   "slsa-source-poc",
				Number: 10,
			}, func(t *testing.T) toolImplementation {
				t.Helper()
				i := sourcetoolfakes.FakeToolImplementation{}
				i.SearchPullRequestReturns(10, nil)
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
			found, err := tool.CheckPolicyRepoFork(&models.Repository{})
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expect, found)
		})
	}
}
