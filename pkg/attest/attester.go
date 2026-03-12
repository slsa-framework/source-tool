// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slsa-framework/source-tool/pkg/auth"
	"github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

type AttesterOptions struct {
	// Initialize dynamic notes fetcher and storer
	InitNotesCollector bool

	// Initialize attestations store collector and storer
	InitGHCollector bool

	// Additional read repositories
	Repos []string

	// Times to retry fetching attestations
	Retries uint8
}

var defaultAttesterOptions = AttesterOptions{
	InitNotesCollector: true,
	Retries:            3,
}

type Attester struct {
	verifier      Verifier
	backend       models.VcsBackend
	Options       AttesterOptions
	authenticator *auth.Authenticator
}

type optFn func(*Attester) error

func WithRepository(repos ...string) optFn {
	return func(a *Attester) error {
		// TODO(puerco): Validate the repository strings
		for _, s := range repos {
			if !slices.Contains(a.Options.Repos, s) {
				a.Options.Repos = append(a.Options.Repos, s)
			}
		}
		return nil
	}
}

func WithRetries(r uint8) optFn {
	return func(a *Attester) error {
		a.Options.Retries = r
		return nil
	}
}

func WithAuthenticator(athn *auth.Authenticator) optFn {
	return func(a *Attester) error {
		a.authenticator = athn
		return nil
	}
}

func WithBackend(b models.VcsBackend) optFn {
	return func(a *Attester) error {
		a.backend = b
		return nil
	}
}

func WithVerifier(vf Verifier) optFn {
	return func(a *Attester) error {
		a.verifier = vf
		return nil
	}
}

func WithGithubCollector(yesno bool) optFn {
	return func(a *Attester) error {
		a.Options.InitGHCollector = yesno
		return nil
	}
}

func WithNotesCollector(yesno bool) optFn {
	return func(a *Attester) error {
		a.Options.InitNotesCollector = yesno
		return nil
	}
}

// Validate checks that the attester configuration is complete
func (a *Attester) Validate() error {
	errs := []error{}

	// Check a backend is configured
	if a.backend == nil {
		errs = append(errs, errors.New("attester has no backend defined"))
	}

	// Check we have attestation repos to read
	if len(a.Options.Repos) == 0 && !a.Options.InitGHCollector && !a.Options.InitNotesCollector {
		errs = append(errs, errors.New("no attestation repository configured"))
	}

	// Check we have a signature verifier
	if a.verifier == nil {
		errs = append(errs, errors.New("attester has no verifier"))
	}

	return errors.Join(errs...)
}

// NewAttester creates a new attester
func NewAttester(fn ...optFn) (*Attester, error) {
	attester := &Attester{
		Options: defaultAttesterOptions,
	}

	for _, f := range fn {
		if err := f(attester); err != nil {
			return nil, err
		}
	}

	// Check attester configuration
	if err := attester.Validate(); err != nil {
		return nil, err
	}

	return attester, nil
}

// createCurrentProvenance creates the provenance statement for the specified commit
// without any context from the previous provenance (if any).
func (a *Attester) createCurrentProvenance(ctx context.Context, branch *models.Branch, commit, prevCommit *models.Commit) (*intoto.Statement, error) {
	// Get the active controls
	controlStatus, err := a.backend.GetBranchControlsAtCommit(ctx, branch, commit)
	if err != nil {
		return nil, err
	}

	if controlStatus == nil {
		return nil, errors.New("VCS backend returned a nil controlset")
	}

	// Build the provenance predicate
	curProvPred := provenance.SourceProvenancePred{
		PrevCommit:   prevCommit.SHA,
		RepoUri:      branch.Repository.GetHttpURL(),
		ActivityType: controlStatus.ActivityType,
		Actor:        controlStatus.ActorLogin,
		Branch:       branch.FullRef(),
		CreatedOn:    timestamppb.New(time.Now()),
		Controls:     controlStatus.ToProvenanceControls(),
	}

	// At the very least provenance is available starting now. :)
	// ... indeed, but don't set the `since`` date because doing so breaks
	// checking against policies.
	// See https://github.com/slsa-framework/source-tool/issues/272
	if curProvPred.GetControl(slsa.SLSA_SOURCE_SCS_PROVENANCE.String()) == nil {
		curProvPred.AddControl(
			&provenance.Control{
				Name: slsa.SLSA_SOURCE_SCS_PROVENANCE.String(),
			},
		)
	}

	return addPredToStatement(&curProvPred, provenance.SourceProvPredicateType, commit.SHA)
}

// addPredToStatement generates a new statement and adds the provenance predicate
func addPredToStatement(provPred proto.Message, predicateType, commit string) (*intoto.Statement, error) {
	predJson, err := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}.Marshal(provPred)
	if err != nil {
		return nil, fmt.Errorf("marshaling predicate proto: %w", err)
	}

	sub := []*intoto.ResourceDescriptor{{
		Digest: map[string]string{"gitCommit": commit},
	}}

	var predPb structpb.Struct
	err = protojson.Unmarshal(predJson, &predPb)
	if err != nil {
		return nil, err
	}

	statementPb := &intoto.Statement{
		Type:          intoto.StatementTypeUri,
		Subject:       sub,
		PredicateType: predicateType,
		Predicate:     &predPb,
	}

	return statementPb, nil
}
