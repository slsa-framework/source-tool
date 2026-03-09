// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector"
	"github.com/carabiner-dev/collector/filters"
	vsa "github.com/in-toto/attestation/go/predicates/vsa/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

func GetSourceProvPred(statement *intoto.Statement) (*provenance.SourceProvenancePred, error) {
	if statement == nil {
		return nil, errors.New("nil statement")
	}
	if statement.GetPredicateType() != provenance.SourceProvPredicateType {
		return nil, fmt.Errorf("unsupported predicate type: %s", statement.GetPredicateType())
	}
	if statement.GetPredicate() == nil {
		return nil, errors.New("nil predicate in statement")
	}
	predJson, err := protojson.Marshal(statement.GetPredicate())
	if err != nil {
		return nil, fmt.Errorf("cannot marshal predicate to JSON: %w", err)
	}

	var predStruct provenance.SourceProvenancePred
	// Using regular json.Unmarshal because this is just a regular struct.
	err = protojson.Unmarshal(predJson, &predStruct)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling predicate: %w", err)
	}
	// It's valid for Controls to be empty if no controls are reported.
	// The policy evaluation logic will determine if this is acceptable.
	// For example, a policy might only require SLSA Level 1, which has no specific control requirements from this predicate.
	return &predStruct, nil
}

func GetTagProvPred(statement *intoto.Statement) (*provenance.TagProvenancePred, error) {
	if statement == nil {
		return nil, errors.New("nil statement")
	}
	if statement.GetPredicateType() != provenance.TagProvPredicateType {
		return nil, fmt.Errorf("unsupported predicate type: %s", statement.GetPredicateType())
	}
	if statement.GetPredicate() == nil {
		return nil, errors.New("nil predicate in statement")
	}
	predJson, err := protojson.Marshal(statement.GetPredicate())
	if err != nil {
		return nil, fmt.Errorf("cannot marshal predicate to JSON: %w", err)
	}

	var predStruct provenance.TagProvenancePred
	// Using regular json.Unmarshal because this is just a regular struct.
	err = protojson.Unmarshal(predJson, &predStruct)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling predicate: %w", err)
	}
	// It's valid for Controls to be empty if no controls are reported.
	// The policy evaluation logic will determine if this is acceptable.
	// For example, a policy might only require SLSA Level 1, which has no specific control requirements from this predicate.
	return &predStruct, nil
}

func (a *Attester) getCollector(branch *models.Branch) (*collector.Agent, error) {
	if err := collector.LoadDefaultRepositoryTypes(); err != nil {
		return nil, err
	}
	agent, err := collector.New()
	if err != nil {
		return nil, err
	}

	if a.Options.InitNotesCollector {
		if err := agent.AddRepositoryFromString(fmt.Sprintf("dnote:%s", branch.Repository.GetHttpURL())); err != nil {
			return nil, err
		}
	}

	if a.Options.InitGHCollector {
		if err := agent.AddRepositoryFromString(fmt.Sprintf("github:%s", branch.Repository.Path)); err != nil {
			return nil, err
		}
	}

	for _, initString := range a.Options.Repos {
		if err := agent.AddRepositoryFromString(initString); err != nil {
			return nil, err
		}
	}

	return agent, nil
}

// GetVSA returns a revision's VSA attestation
func (a *Attester) GetRevisionVSA(ctx context.Context, branch *models.Branch, commit *models.Commit) (attestation.Envelope, *vsa.VerificationSummary, error) {
	if commit == nil {
		return nil, nil, errors.New("commit is nil")
	}
	c, err := a.getCollector(branch)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get collector: %w", err)
	}

	// Configure the matcher to filter all the predicate types of the provenance
	matcher := &filters.PredicateTypeMatcher{
		PredicateTypes: map[attestation.PredicateType]struct{}{
			attestation.PredicateType("https://slsa.dev/verification_summary/v1"): {},
		},
	}

	var attErr error
	var atts []attestation.Envelope
	for i := 0; i <= int(a.Options.Retries); i++ {
		// Fetch the attestations from the configured repos
		atts, attErr = c.FetchAttestationsBySubject(
			ctx, []attestation.Subject{commit.ToResourceDescriptor()},
			collector.WithQuery(attestation.NewQuery().WithFilter(matcher)),
		)
		if attErr == nil {
			break
		}
		time.Sleep(time.Duration(i*5) * time.Second)
	}
	if attErr != nil {
		return nil, nil, fmt.Errorf("fetching attestations: %w", err)
	}

	if len(atts) == 0 {
		Debugf("no attestations returned from collector")
		return nil, nil, nil
	}

	// Range the attestations and find and validate that it matches our repo
	// and expected resources
	for _, att := range atts {
		predicate := att.GetPredicate().GetParsed()
		vsaPred, ok := predicate.(*vsa.VerificationSummary)
		if !ok {
			// This should not happen
			continue
		}

		// Check the verifier ID matches
		if vsaPred.GetVerifier().GetId() != VsaVerifierId {
			Debugf("VSA verfier ID does not match %s", VsaVerifierId)
			continue
		}

		// Check the VSA resource to ensure it is our repo
		cleanResourceUri := strings.TrimPrefix(vsaPred.GetResourceUri(), "git+")
		if branch.Repository.GetHttpURL() != "" && cleanResourceUri != branch.Repository.GetHttpURL() {
			Debugf("ResourceUri is %s but we want %s", cleanResourceUri, branch.Repository.GetHttpURL())
			continue
		}

		// And the verification is passed
		// 	// Is the result PASSED?
		if vsaPred.GetVerificationResult() != "PASSED" {
			Debugf("verificationResult is %s but must be 'PASSED'", vsaPred.GetVerificationResult())
			continue
		}

		return att, vsaPred, nil
	}

	// None of the collected attestations are valid
	return nil, nil, nil
}

// GetRevisionProvenance returns the provenance attestation for a commit by querying
// the configured collectors.
func (a *Attester) GetRevisionProvenance(ctx context.Context, branch *models.Branch, commit *models.Commit) (*provenance.SourceProvenancePred, error) {
	c, err := a.getCollector(branch)
	if err != nil {
		return nil, fmt.Errorf("unable to get collector: %w", err)
	}

	// Configure the matcher to filter all the predicate types of the provenance
	matcher := &filters.PredicateTypeMatcher{
		PredicateTypes: map[attestation.PredicateType]struct{}{
			attestation.PredicateType(provenance.SourceProvPredicateType): {},
		},
	}

	var attErr error
	var atts []attestation.Envelope
	for i := 0; i <= int(a.Options.Retries); i++ {
		// Fetch the attestations from the configured repos
		atts, attErr = c.FetchAttestationsBySubject(
			ctx, []attestation.Subject{commit.ToResourceDescriptor()},
			collector.WithQuery(attestation.NewQuery().WithFilter(matcher)),
		)
		if attErr == nil {
			break
		}
		time.Sleep(time.Duration(i*5) * time.Second)
	}
	if attErr != nil {
		return nil, fmt.Errorf("fetching attestations: %w", attErr)
	}

	if len(atts) == 0 {
		Debugf("no attestations returned from collector")
		return nil, nil
	}

	// Now extract the provenance
	for _, att := range atts {
		pred := &provenance.SourceProvenancePred{}
		if err = protojson.Unmarshal(att.GetPredicate().GetData(), pred); err == nil {
			return pred, nil
		}
	}
	return nil, fmt.Errorf("unable to parse predicate: %w", err)
}

// prevAttPath string
func (a *Attester) CreateSourceProvenance(ctx context.Context, branch *models.Branch, commit *models.Commit) (*intoto.Statement, error) {
	// Get the previous commit
	prevCommit, err := a.backend.GetPreviousCommit(ctx, branch, commit)
	if err != nil {
		return nil, fmt.Errorf("getting previous commit: %w", err)
	}

	// Source provenance is based on
	// 1. The current control situation (we assume 'commit' has _just_ occurred).
	// 2. How long the properties have been enforced according to the previous provenance.
	curProv, err := a.createCurrentProvenance(ctx, branch, commit, prevCommit)
	if err != nil {
		return nil, fmt.Errorf("creating provenance predicate: %w", err)
	}

	// prevProvStmt, prevProvPred, err := a.GetRevisionProvenance(ctx, branch, prevCommit)
	prevProvPred, err := a.GetRevisionProvenance(ctx, branch, prevCommit)
	if err != nil {
		return nil, err
	}

	// No prior provenance found, so we just go with current.
	// if prevProvStmt == nil || prevProvPred == nil {
	if prevProvPred == nil {
		Debugf("No previous provenance found, have to bootstrap\n")
		return curProv, nil
	}

	curProvPred, err := GetSourceProvPred(curProv)
	if err != nil {
		return nil, err
	}

	// There was prior provenance, so update the Since field for each property
	// to the oldest encountered.
	for i, curControl := range curProvPred.GetControls() {
		prevControl := prevProvPred.GetControl(curControl.GetName())
		// No prior version of this control
		if prevControl == nil {
			continue
		}
		curControl.Since = timestamppb.New(slsa.EarlierTime(curControl.GetSince().AsTime(), prevControl.GetSince().AsTime()))
		// Update the value.
		curProvPred.Controls[i] = curControl
	}

	return addPredToStatement(curProvPred, provenance.SourceProvPredicateType, commit.SHA)
}

// CreateTagProvenance creates a provenance statement for a tag.
func (a Attester) CreateTagProvenance(ctx context.Context, branch *models.Branch, tag *models.Tag, actor string) (*intoto.Statement, error) {
	if tag.Commit == nil {
		return nil, fmt.Errorf("tag does not have its commit set")
	}

	// 1. Check that the tag hygiene control is still enabled and how long it's been enabled, store it in the prov.
	// 2. Get a VSA associated with this commit, if any.
	// 3. Record the levels and branches covered by that VSA in the provenance.
	controls, err := a.backend.GetTagControls(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("getting tag controls: %w", err)
	}

	// Find the most recent VSA for this commit. Any reference is OK.
	// TODO: in the future get all of them.
	// TODO: we should actually verify this vsa: https://github.com/slsa-framework/source-tool/issues/148
	vsaAtt, vsaPred, err := a.GetRevisionVSA(ctx, branch, tag.Commit) // Aqui antes era: ghcontrol.AnyReference
	if err != nil {
		return nil, fmt.Errorf("error fetching VSA when creating tag provenance %w", err)
	}

	if vsaAtt == nil {
		// TODO: If there's not a VSA, should we still issue provenance?
		return nil, nil
	}

	vsaRefs, err := GetSourceRefsForCommit(vsaAtt, tag.Commit)
	if err != nil {
		return nil, fmt.Errorf("error getting source refs from vsa %w", err)
	}

	curProvPred := provenance.TagProvenancePred{
		RepoUri:   branch.Repository.GetHttpURL(),
		Actor:     actor,
		Tag:       tag.Name,
		CreatedOn: timestamppb.Now(),
		Controls:  controls.ToProvenanceControls(),
		VsaSummaries: []*provenance.VsaSummary{
			{
				SourceRefs:     vsaRefs,
				VerifiedLevels: vsaPred.GetVerifiedLevels(),
			},
		},
	}

	return addPredToStatement(&curProvPred, provenance.TagProvPredicateType, tag.Commit.SHA)
}
