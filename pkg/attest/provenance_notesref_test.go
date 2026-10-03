// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-git/go-git/v5"
)

// errorList stands in for vcslocator.ErrorList, which renders its members but
// does not implement Unwrap, so errors.Is cannot see through it.
type errorList struct {
	errs []error
}

func (e *errorList) Error() string {
	return errors.Join(e.errs...).Error()
}

func TestNotesRefMissing(t *testing.T) {
	fetchFailure := fmt.Errorf("fetching ref %q: %w", "refs/notes/commits", git.NoMatchingRefSpecError{})
	// The same failure as it renders once the aggregate has flattened it to
	// text: go-git's NoMatchingRefSpecError prints the ref it could not find.
	rendered := errors.New(`fetching ref "refs/notes/commits": couldn't find remote ref "refs/notes/commits"`)

	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"wrapped go-git error": {
			err:  fmt.Errorf("fetching attestations: %w", fetchFailure),
			want: true,
		},
		"aggregated without an unwrap": {
			err:  fmt.Errorf("error cloning repositories: %w", &errorList{errs: []error{rendered, nil}}),
			want: true,
		},
		"some other failure": {
			err:  fmt.Errorf("fetching attestations: %w", errors.New("connection refused")),
			want: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := notesRefMissing(tc.err); got != tc.want {
				t.Errorf("notesRefMissing(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
