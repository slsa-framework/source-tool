package audit

import (
	"context"
	"fmt"
	"iter"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/ghcontrol"
)

type Auditor struct {
	ghc *ghcontrol.GitHubConnection
	// TODO: This should probably be turned into a pointer.
	verifier attest.Verifier
	pa       *attest.ProvenanceAttestor
}

type AuditCommitResult struct {
	Commit   string
	VsaPred  *vpb.VerificationSummary
	ProvPred *attest.SourceProvenancePred
	// The previous commit reported by GH.
	GhPriorCommit string
}

func NewAuditor(ghc *ghcontrol.GitHubConnection, pa *attest.ProvenanceAttestor, verifier attest.Verifier) *Auditor {
	return &Auditor{
		ghc:      ghc,
		verifier: verifier,
		pa:       pa,
	}
}

func (a *Auditor) AuditCommit(ctx context.Context, commit string) (*AuditCommitResult, error) {
	_, vsa, err := attest.GetVsa(ctx, a.ghc, a.verifier, commit, a.ghc.GetFullRef())
	if err != nil {
		return nil, fmt.Errorf("getting vsa for revision %s: %w", commit, err)
	}

	_, prov, err := a.pa.GetProvenance(ctx, commit, a.ghc.GetFullRef())
	if err != nil {
		return nil, fmt.Errorf("getting prov for revision %s: %w", commit, err)
	}

	ghPrior, err := a.ghc.GetPriorCommit(ctx, commit)
	if err != nil {
		return nil, fmt.Errorf("could not get prior commit for revision %s: %w", commit, err)
	}

	return &AuditCommitResult{
		Commit:        commit,
		VsaPred:       vsa,
		ProvPred:      prov,
		GhPriorCommit: ghPrior,
	}, nil
}

func (a *Auditor) AuditBranch(ctx context.Context, branch string) iter.Seq2[*AuditCommitResult, error] {
	latestCommit, err := a.ghc.GetLatestCommit(ctx, branch)

	return func(yield func(*AuditCommitResult, error) bool) {
		if err != nil {
			yield(nil, err)
			return
		}
		nextCommit := latestCommit
		for ok := true; ok; ok = (nextCommit != "") {
			ar, err := a.AuditCommit(ctx, nextCommit)
			if !yield(ar, err) {
				return
			}
			nextCommit = ar.GhPriorCommit
		}
	}
}
