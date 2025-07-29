// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package provenance

import "encoding/json"

const (
	SourceProvPredicateType = "https://github.com/slsa-framework/slsa-source-poc/source-provenance/v1-draft"
	TagProvPredicateType    = "https://github.com/slsa-framework/slsa-source-poc/tag-provenance/v1-draft"
)

// GetControl looks for a control by name in the predicate.
func (pred *SourceProvenancePred) GetControl(name string) *Control {
	for _, control := range pred.GetControls() {
		if control.GetName() == name {
			return control
		}
	}
	return nil
}

// AddControl adds a new control to the predicate.
func (pred *SourceProvenancePred) AddControl(newControls ...*Control) {
	for _, c := range newControls {
		if c == nil {
			continue
		}
		pred.Controls = append(pred.Controls, c)
	}
}

func (pred *SourceProvenancePred) MarshalJSON() ([]byte, error) {
	type Alias SourceProvenancePred
	var con string
	if pred.GetCreatedOn() != nil {
		con = pred.GetCreatedOn().AsTime().Format("2006-01-02T15:04:05.000Z")
	}

	return json.Marshal(
		&struct {
			CreatedOn string `json:"created_on"`
			*Alias
		}{
			CreatedOn: con,
			Alias:     (*Alias)(pred),
		},
	)
}

func (ctl *Control) MarshalJSON() ([]byte, error) {
	type Alias Control
	var since string
	if ctl.GetSince() != nil {
		since = ctl.GetSince().AsTime().Format("2006-01-02T15:04:05.000Z")
	}

	return json.Marshal(
		&struct {
			CreatedOn string `json:"since"`
			*Alias
		}{
			CreatedOn: since,
			Alias:     (*Alias)(ctl),
		},
	)
}
