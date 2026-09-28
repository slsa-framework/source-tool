// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/source-tool/pkg/provenance"
)

// The predicate getters must read statements issued under the current v1
// predicate types as well as under the draft types source-tool used before
// the promotion, since attestations already stored under them remain valid.
func TestGetSourceProvPredPredicateTypes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		predicateType string
		wantErr       bool
	}{
		{"v1", provenance.SourceProvPredicateType, false},
		{"draft", provenance.SourceProvPredicateTypeDraft, false},
		{"tag type", provenance.TagProvPredicateType, true},
		{"unknown", "https://example.com/other/v1", true},
		{"empty", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pred := &provenance.SourceProvenancePred{
				PrevCommit: "abc",
				RepoUri:    "https://github.com/example/repo",
				Controls:   []*provenance.Control{{Name: "TEST_CONTROL"}},
			}
			stmt, err := addPredToStatement(pred, tc.predicateType, "deadbeef")
			require.NoError(t, err)

			got, err := GetSourceProvPred(stmt)
			if tc.wantErr {
				require.Error(t, err)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, pred.GetPrevCommit(), got.GetPrevCommit())
			require.Equal(t, pred.GetRepoUri(), got.GetRepoUri())
			require.Len(t, got.GetControls(), 1)
			require.Equal(t, "TEST_CONTROL", got.GetControls()[0].GetName())
		})
	}
}

func TestGetTagProvPredPredicateTypes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		predicateType string
		wantErr       bool
	}{
		{"v1", provenance.TagProvPredicateType, false},
		{"draft", provenance.TagProvPredicateTypeDraft, false},
		{"source type", provenance.SourceProvPredicateType, true},
		{"unknown", "https://example.com/other/v1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pred := &provenance.TagProvenancePred{
				RepoUri: "https://github.com/example/repo",
				Tag:     "refs/tags/v1.0.0",
			}
			stmt, err := addPredToStatement(pred, tc.predicateType, "deadbeef")
			require.NoError(t, err)

			got, err := GetTagProvPred(stmt)
			if tc.wantErr {
				require.Error(t, err)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, pred.GetTag(), got.GetTag())
			require.Equal(t, pred.GetRepoUri(), got.GetRepoUri())
		})
	}
}

// New statements are always issued under the v1 predicate types.
func TestWritersEmitV1PredicateTypes(t *testing.T) {
	t.Parallel()
	require.Equal(t, "https://github.com/slsa-framework/source-tool/source-provenance/v1", provenance.SourceProvPredicateType)
	require.Equal(t, "https://github.com/slsa-framework/source-tool/tag-provenance/v1", provenance.TagProvPredicateType)
	require.True(t, provenance.IsSourceProvPredicateType(provenance.SourceProvPredicateTypeDraft))
	require.True(t, provenance.IsTagProvPredicateType(provenance.TagProvPredicateTypeDraft))
	require.False(t, provenance.IsSourceProvPredicateType(provenance.TagProvPredicateType))
}
