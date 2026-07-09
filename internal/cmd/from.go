// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"slices"

	"github.com/spf13/cobra"
)

// supportedReadSources lists the attestation sources the --from flag accepts.
// They mirror the --push destinations.
var supportedReadSources = []string{pushRepoGithub, pushRepoNote}

// defaultReadSources is the set of attestation sources. Bye default we
// reads git notes only as the GitHub attestations API requires the token
// to have attestations read access, so it must be opted into to avoid failing
// reads in CI where that permission is not granted.
var defaultReadSources = []string{pushRepoNote}

// fromOptions selects the sources to read attestations from.
type fromOptions struct {
	from []string
}

func (fo *fromOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringSliceVar(
		&fo.from, "from", defaultReadSources,
		fmt.Sprintf("sources to read attestations from %v", supportedReadSources),
	)
}

func (fo *fromOptions) Validate() error {
	var errs []error
	for _, s := range fo.from {
		if !slices.Contains(supportedReadSources, s) {
			errs = append(errs, fmt.Errorf("unsupported attestation source: %q", s))
		}
	}
	return errors.Join(errs...)
}

// readGithub returns true when the GitHub attestations API is a selected source.
func (fo *fromOptions) readGithub() bool {
	return slices.Contains(fo.from, pushRepoGithub)
}

// readNotes returns true when git notes are a selected source.
func (fo *fromOptions) readNotes() bool {
	return slices.Contains(fo.from, pushRepoNote)
}
