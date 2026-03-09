// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"iter"
	"os"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/ghcontrol"
	"github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

type Auditor struct {
	ghc *ghcontrol.GitHubConnection
	// TODO: This should probably be turned into a pointer.
	verifier attest.Verifier
	attester *attest.Attester
	backend  models.VcsBackend
}

type AuditCommitResult struct {
	Commit   string
	VsaPred  *vpb.VerificationSummary
	ProvPred *provenance.SourceProvenancePred
	// The previous commit reported by GH.
	GhPriorCommit   string
	GhControlStatus *ghcontrol.GhControlStatus
}

func (ar *AuditCommitResult) IsGood() bool {
	// Have to have a VSA
	good := ar.VsaPred != nil

	// Have to have provenance
	if ar.ProvPred == nil {
		good = false
	} else if ar.ProvPred.GetPrevCommit() != ar.GhPriorCommit {
		// Commits need to be the same.
		good = false
	}

	return good
}

func NewAuditor(ghc *ghcontrol.GitHubConnection, pa *attest.Attester, verifier attest.Verifier) *Auditor {
	return &Auditor{
		ghc:      ghc,
		verifier: verifier,
		attester: pa,
	}
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

	ghPrior, err := a.ghc.GetPriorCommit(ctx, commit.SHA)
	if err != nil {
		return nil, fmt.Errorf("could not get prior commit for revision %s: %w", commit, err)
	}
	ar.GhPriorCommit = ghPrior

	var controlStatus *ghcontrol.GhControlStatus
	if prov == nil {
		// If there's no provenance, let's check the controls to see how they're looking.
		// It could be that provenance generation failed, but the controls were still
		// in place.
		// TODO: (use backend method here)
		controlStatus, err = a.ghc.GetBranchControlsAtCommit(ctx, commit.SHA, a.ghc.GetFullRef())
		if err != nil {
			// Let's still return ar so they can continue if they want.
			return ar, fmt.Errorf("could not get controls for %s on %s: %w", commit, a.ghc.GetFullRef(), err)
		}
	}
	ar.GhControlStatus = controlStatus

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
			nextCommit = &models.Commit{SHA: ar.GhPriorCommit}
		}
	}
}
