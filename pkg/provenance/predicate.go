// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package provenance exposes the SLSA source provenance predicate types.
//
// The message definitions live in the shared slsa-framework/protos module;
// this package aliases them so callers keep a descriptive import name and
// adds the predicate type URIs and a few helpers around the generated code.
package provenance

import (
	sourcetoolv1 "github.com/slsa-framework/protos/sourcetool/v1"
)

const (
	SourceProvPredicateType = "https://github.com/slsa-framework/slsa-source-poc/source-provenance/v1-draft"
	TagProvPredicateType    = "https://github.com/slsa-framework/slsa-source-poc/tag-provenance/v1-draft"
)

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
