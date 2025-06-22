package sourcetool

import (
	"context"
	"fmt"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/ghcontrol"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
)

// toolImplementation defines the mockable implementation of source tool
type toolImplementation interface {
	GetActiveControls(*Options) (slsa.Controls, error)
}

type defaultToolImplementation struct{}

// GetActiveControls returns a slsa.Controls with the active controls on a repo
func (impl *defaultToolImplementation) GetActiveControls(opts *Options) (slsa.Controls, error) {
	ctx := context.Background()

	ghc, err := opts.GetGitHubConnection()
	if err != nil {
		return nil, fmt.Errorf("getting GitHub connection: %w", err)
	}

	if err := opts.EnsureBranch(); err != nil {
		return nil, err
	}

	// Get the active controls
	activeControls, err := ghc.GetBranchControls(ctx, ghcontrol.BranchToFullRef(opts.Branch))
	if err != nil {
		return nil, fmt.Errorf("checking status: %w", err)
	}

	// We need to manually check for PROVENANCE_AVAILABLE which is not
	// handled by ghcontrol
	attestor := attest.NewProvenanceAttestor(
		ghc, attest.GetDefaultVerifier(),
	)

	// Fetch the attestation. If found, then add the control:
	attestation, _, err := attestor.GetProvenance(ctx, opts.Commit, ghcontrol.BranchToFullRef(opts.Branch))
	if err != nil {
		return nil, fmt.Errorf("attempting to read provenance from commit: %w", err)
	}
	if attestation != nil {
		activeControls.AddControl(&slsa.Control{
			Name: slsa.ProvenanceAvailable,
		})
	}

	return *activeControls, nil
}
