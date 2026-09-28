// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package provenance exposes the SLSA source provenance predicate types.
//
// The message definitions live in the shared slsa-framework/protos module;
// this package aliases them so callers keep a descriptive import name and
// adds the predicate type URIs and a few helpers around the generated code.
package provenance

import (
	"slices"

	sourcetoolv1 "github.com/slsa-framework/protos/sourcetool/v1"
)

// Predicate types of the statements source-tool issues. The draft types are
// what source-tool wrote before the predicates were promoted to v1; the
// payload is the same, and attestations already issued under them remain
// valid, so readers accept both while writers only emit the v1 types.
const (
	SourceProvPredicateType      = sourcetoolv1.PredicateTypeSourceProvenance
	TagProvPredicateType         = sourcetoolv1.PredicateTypeTagProvenance
	SourceProvPredicateTypeDraft = sourcetoolv1.PredicateTypeSourceProvenanceDraft
	TagProvPredicateTypeDraft    = sourcetoolv1.PredicateTypeTagProvenanceDraft
)

// IsSourceProvPredicateType returns true when predicateType identifies a
// statement carrying a SourceProvenancePred, in any of its versions.
func IsSourceProvPredicateType(predicateType string) bool {
	return slices.Contains(sourcetoolv1.SourceProvenancePredicateTypes, predicateType)
}

// IsTagProvPredicateType returns true when predicateType identifies a
// statement carrying a TagProvenancePred, in any of its versions.
func IsTagProvPredicateType(predicateType string) bool {
	return slices.Contains(sourcetoolv1.TagProvenancePredicateTypes, predicateType)
}

type (
	// SourceProvenancePred is the source provenance predicate.
	SourceProvenancePred = sourcetoolv1.SourceProvenancePred
	// Control records a control enforced on the source and since when.
	Control = sourcetoolv1.Control
	// TagProvenancePred is the tag provenance predicate.
	TagProvenancePred = sourcetoolv1.TagProvenancePred
	// VsaSummary summarizes a VSA referenced from tag provenance.
	VsaSummary = sourcetoolv1.VsaSummary
)

// GetControl looks for a control by name in the predicate.
func GetControl(pred *SourceProvenancePred, name string) *Control {
	for _, control := range pred.GetControls() {
		if control.GetName() == name {
			return control
		}
	}
	return nil
}

// AddControl adds new controls to the predicate, skipping nil entries.
func AddControl(pred *SourceProvenancePred, newControls ...*Control) {
	for _, c := range newControls {
		if c == nil {
			continue
		}
		pred.Controls = append(pred.Controls, c)
	}
}
