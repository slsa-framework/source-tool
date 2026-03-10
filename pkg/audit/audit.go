// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"os"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

type Auditor struct {
	attester *attest.Attester
	backend  models.VcsBackend
}

type optFn func(*Auditor) error

func WithAttester(a *attest.Attester) optFn {
	return func(au *Auditor) error {
		au.attester = a
		return nil
	}
}

func WithBackend(b models.VcsBackend) optFn {
	return func(au *Auditor) error {
		au.backend = b
		return nil
	}
}

type AuditCommitResult struct {
	Commit   string
	VsaPred  *vpb.VerificationSummary
	ProvPred *provenance.SourceProvenancePred
	// The previous commit reported by the VCS backend.
	PriorCommit   string
	ControlStatus *slsa.ControlSet
}

func (ar *AuditCommitResult) IsGood() bool {
	// Have to have a VSA
	good := ar.VsaPred != nil

	// Have to have provenance
	if ar.ProvPred == nil {
		good = false
	} else if ar.ProvPred.GetPrevCommit() != ar.PriorCommit {
		// Commits need to be the same.
		good = false
	}

	return good
}

func NewAuditor(fn ...optFn) (*Auditor, error) {
	a := &Auditor{}
	for _, f := range fn {
		if err := f(a); err != nil {
			return nil, err
		}
	}

	errs := []error{}
	if a.attester == nil {
		errs = append(errs, errors.New("auditor has no attester"))
	}
	if a.backend == nil {
		errs = append(errs, errors.New("auditor has no backend"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Auditor) AuditCommit(ctx context.Context, branch *models.Branch, commit *models.Commit) (ar *AuditCommitResult, err error) {
	ar = &AuditCommitResult{Commit: commit.SHA}

	_, vsa, err := a.attester.GetRevisionVSA(ctx, branch, commit)
	if err != nil {
		return nil, fmt.Errorf("getting vsa for revision %s: %w", commit, err)
	}
	ar.VsaPred = vsa

	prov, err := a.attester.GetRevisionProvenance(ctx, branch, commit)
	if err != nil {
		return nil, fmt.Errorf("getting prov for revision %s: %w", commit, err)
	}
	ar.ProvPred = prov

	prior, err := a.backend.GetPreviousCommit(ctx, branch, commit)
	if err != nil {
		return nil, fmt.Errorf("could not get prior commit for revision %s: %w", commit, err)
	}
	ar.PriorCommit = prior.SHA

	if prov == nil {
		// If there's no provenance, check the controls to see how they're looking.
		// It could be that provenance generation failed, but the controls were still
		// in place.
		controlStatus, err := a.backend.GetBranchControlsAtCommit(ctx, branch, commit)
		if err != nil {
			// Still return ar so callers can continue if they want.
			return ar, fmt.Errorf("could not get controls for %s on %s: %w", commit.SHA, branch.FullRef(), err)
		}
		ar.ControlStatus = controlStatus
	}

	return ar, nil
}

func (a *Auditor) AuditBranch(ctx context.Context, branch *models.Branch) iter.Seq2[*AuditCommitResult, error] {
	latestCommit, err := a.backend.GetLatestCommit(ctx, branch.Repository, branch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error fetching latest commit: %v", err)
		return nil
	}

	return func(yield func(*AuditCommitResult, error) bool) {
		if err != nil {
			yield(nil, err)
			return
		}
		nextCommit := latestCommit
		for ok := true; ok; ok = (nextCommit.SHA != "") {
			ar, err := a.AuditCommit(ctx, branch, nextCommit)
			if !yield(ar, err) {
				return
			}
			nextCommit = &models.Commit{SHA: ar.PriorCommit}
		}
	}
}
