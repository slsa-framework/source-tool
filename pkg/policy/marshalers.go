// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import "encoding/json"

func (branch *ProtectedBranch) MarshalJSON() ([]byte, error) {
	type Alias ProtectedBranch
	var since string
	if branch.GetSince() != nil {
		since = branch.GetSince().AsTime().Format("2006-01-02T15:04:05.000Z")
	}

	return json.Marshal(
		&struct {
			Since string `json:"since"`
			*Alias
		}{
			Since: since,
			Alias: (*Alias)(branch),
		},
	)
}

func (ctl *OrgStatusCheckControl) MarshalJSON() ([]byte, error) {
	type Alias OrgStatusCheckControl
	var since string
	if ctl.GetSince() != nil {
		since = ctl.GetSince().AsTime().Format("2006-01-02T15:04:05.000Z")
	}

	return json.Marshal(
		&struct {
			Since string `json:"since"`
			*Alias
		}{
			Since: since,
			Alias: (*Alias)(ctl),
		},
	)
}

func (tag *ProtectedTag) MarshalJSON() ([]byte, error) {
	type Alias ProtectedTag
	var since string
	if tag.GetSince() != nil {
		since = tag.GetSince().AsTime().Format("2006-01-02T15:04:05.000Z")
	}

	return json.Marshal(
		&struct {
			Since string `json:"since"`
			*Alias
		}{
			Since: since,
			Alias: (*Alias)(tag),
		},
	)
}
