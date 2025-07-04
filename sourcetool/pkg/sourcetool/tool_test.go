package sourcetool

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/options"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/sourcetoolfakes"
)

func TestGetRepoControls(t *testing.T) {
	t.Parallel()
	t.Run("GetActiveControls-success", func(t *testing.T) {
		t.Parallel()
		i := &sourcetoolfakes.FakeToolImplementation{}
		i.GetActiveControlsReturns(slsa.Controls{slsa.Control{
			Name: "hey", Since: time.Now(),
		}}, nil)
		tool := &Tool{
			impl: i,
		}
		res, err := tool.GetRepoControls()
		require.NotNil(t, res)
		require.Len(t, res, 1)
		require.NoError(t, err)
	})
	t.Run("GetActiveControls-fails", func(t *testing.T) {
		t.Parallel()
		i := &sourcetoolfakes.FakeToolImplementation{}
		i.GetActiveControlsReturns(nil, errors.New("failed badly"))
		tool := &Tool{
			impl: i,
		}
		_, err := tool.GetRepoControls()
		require.Error(t, err)
	})
}

func TestOnboardRepository(t *testing.T) {
	t.Parallel()
	syntErr := errors.New("synthetic error")
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T) toolImplementation
		mustErr bool
	}{
		{
			name: "EnsureDefault-fails", mustErr: true,
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.EnsureDefaultsReturns(syntErr)
				return i
			},
		},
		{
			name: "CheckForks-fails", mustErr: true,
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CheckForksReturns(syntErr)
				return i
			},
		},
		{
			name: "VerifyOptionsForFullOnboard-fails", mustErr: true,
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.VerifyOptionsForFullOnboardReturns(syntErr)
				return i
			},
		},
		{
			name: "CreateRepoRuleset-fails", mustErr: true,
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CreateRepoRulesetReturns(syntErr)
				return i
			},
		},
		{
			name: "CheckForksCreateWorkflowPRfails", mustErr: true,
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CreateWorkflowPRReturns(syntErr)
				return i
			},
		},
		{
			name: "CreatePolicyPRfails", mustErr: true,
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CreatePolicyPRReturns(syntErr)
				return i
			},
		},
		{
			name: "all-success", mustErr: false,
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				return i
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tool := &Tool{
				Options: options.Options{},
				impl:    tc.prepare(t),
			}
			err := tool.OnboardRepository()
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestConfigureControls(t *testing.T) {
	t.Parallel()
	syntErr := errors.New("synthetic error")
	for _, tc := range []struct {
		name     string
		mustErr  bool
		controls []ControlConfiguration
		prepare  func(t *testing.T) toolImplementation
	}{
		{
			name: "EnsureDefault-fails", mustErr: true,
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.EnsureDefaultsReturns(syntErr)
				return i
			},
		},
		{
			name: "CreateRepoRuleset-success", mustErr: false,
			controls: []ControlConfiguration{CONFIG_BRANCH_RULES},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CreateRepoRulesetReturns(nil)
				return i
			},
		},
		{
			name: "CreateRepoRuleset-fails", mustErr: true,
			controls: []ControlConfiguration{CONFIG_BRANCH_RULES},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CreateRepoRulesetReturns(syntErr)
				return i
			},
		},
		{
			name: "CheckWorkflowFork-success", mustErr: false,
			controls: []ControlConfiguration{CONFIG_PROVENANCE_WORKFLOW},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CheckWorkflowForkReturns(nil)
				return i
			},
		},
		{
			name: "CheckWorkflowFork-fails", mustErr: true,
			controls: []ControlConfiguration{CONFIG_PROVENANCE_WORKFLOW},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CheckWorkflowForkReturns(syntErr)
				return i
			},
		},
		{
			name: "CreateWorkflowPR-success", mustErr: false,
			controls: []ControlConfiguration{CONFIG_PROVENANCE_WORKFLOW},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CreateWorkflowPRReturns(nil)
				return i
			},
		},
		{
			name: "CreateWorkflowPR-fails", mustErr: true,
			controls: []ControlConfiguration{CONFIG_PROVENANCE_WORKFLOW},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CreateWorkflowPRReturns(syntErr)
				return i
			},
		},
		{
			name: "CheckPolicyFork-success", mustErr: false,
			controls: []ControlConfiguration{CONFIG_POLICY},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CheckPolicyForkReturns(nil)
				return i
			},
		},
		{
			name: "CheckPolicyFork-fails", mustErr: true,
			controls: []ControlConfiguration{CONFIG_POLICY},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CheckPolicyForkReturns(syntErr)
				return i
			},
		},
		{
			name: "CreatePolicyPR-success", mustErr: false,
			controls: []ControlConfiguration{CONFIG_POLICY},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CreatePolicyPRReturns(nil)
				return i
			},
		},
		{
			name: "CreatePolicyPR-fails", mustErr: true,
			controls: []ControlConfiguration{CONFIG_POLICY},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
				i.CreatePolicyPRReturns(syntErr)
				return i
			},
		},
		{
			name: "unknown-config", mustErr: true,
			controls: []ControlConfiguration{"unknown-config"},
			prepare: func(t *testing.T) toolImplementation {
				t.Helper()
				i := &sourcetoolfakes.FakeToolImplementation{}
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
			//
			err := tool.ConfigureControls(tc.controls)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
