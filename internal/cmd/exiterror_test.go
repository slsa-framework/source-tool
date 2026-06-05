// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"testing"
)

func TestExitErrorErrorAndUnwrap(t *testing.T) {
	wrapped := errors.New("policy target level SLSA_SOURCE_LEVEL_3 not met")
	ee := &exitError{code: 2, err: wrapped}

	if ee.Error() != wrapped.Error() {
		t.Errorf("Error() = %q, want %q", ee.Error(), wrapped.Error())
	}
	if !errors.Is(ee, wrapped) {
		t.Errorf("errors.Is(exitError, wrapped) = false, want true (Unwrap should expose the wrapped error)")
	}
}

func TestExitErrorExtraction(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name      string
		err       error
		wantMatch bool
		wantCode  int
	}{
		{
			name:      "direct exit error",
			err:       &exitError{code: 2, err: errors.New("shortfall")},
			wantMatch: true,
			wantCode:  2,
		},
		{
			name:      "wrapped exit error",
			err:       fmt.Errorf("attesting commit: %w", &exitError{code: 2, err: errors.New("shortfall")}),
			wantMatch: true,
			wantCode:  2,
		},
		{
			name:      "plain error falls through",
			err:       errors.New("boom"),
			wantMatch: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var ee *exitError
			gotMatch := errors.As(tt.err, &ee)
			if gotMatch != tt.wantMatch {
				t.Fatalf("errors.As() = %v, want %v", gotMatch, tt.wantMatch)
			}
			if gotMatch && ee.code != tt.wantCode {
				t.Errorf("exitError.code = %d, want %d", ee.code, tt.wantCode)
			}
		})
	}
}
