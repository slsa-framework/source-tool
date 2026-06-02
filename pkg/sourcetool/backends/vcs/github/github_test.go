// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-github/v69/github"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

func TestAsUnsupportedPlanError(t *testing.T) {
	t.Parallel()

	// This is the shape GitHub returns when reading branch rules on a private
	// repo that is on a free plan (see slsa-framework/source-tool#326). The
	// detection must key off the typed response and status code, not the
	// message text, so the test uses the real go-github error type.
	forbidden := &github.ErrorResponse{
		Response: &http.Response{StatusCode: http.StatusForbidden},
		Message:  "Upgrade to GitHub Pro or make this repository public to enable this feature.",
	}

	for _, tc := range []struct {
		name       string
		err        error
		expectPlan bool
	}{
		{
			name:       "nil",
			err:        nil,
			expectPlan: false,
		},
		{
			name:       "plain-403",
			err:        forbidden,
			expectPlan: true,
		},
		{
			name:       "wrapped-403",
			err:        fmt.Errorf("checking status: %w", forbidden),
			expectPlan: true,
		},
		{
			name: "404-not-plan",
			err: &github.ErrorResponse{
				Response: &http.Response{StatusCode: http.StatusNotFound},
				Message:  "Not Found",
			},
			expectPlan: false,
		},
		{
			name:       "non-github-error",
			err:        errors.New("some other failure"),
			expectPlan: false,
		},
		{
			name: "403-without-response",
			err: &github.ErrorResponse{
				Message: "Forbidden but no response attached",
			},
			expectPlan: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := asUnsupportedPlanError(tc.err)
			if !tc.expectPlan {
				require.Nil(t, got)
				return
			}
			require.Error(t, got)
			// The actionable sentinel must be detectable with errors.Is so the
			// CLI can switch on it...
			require.ErrorIs(t, got, models.ErrUnsupportedRepoPlan)
			// ...and the original API error must still be reachable for debugging.
			require.ErrorIs(t, got, tc.err)
		})
	}
}
