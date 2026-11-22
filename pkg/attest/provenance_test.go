// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

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

func TestEarliestSince(t *testing.T) {
	t.Parallel()
	older := timestamppb.New(time.Date(2025, 1, 26, 2, 23, 18, 0, time.UTC))
	newer := timestamppb.New(time.Date(2026, 11, 22, 16, 25, 6, 0, time.UTC))
	epoch := timestamppb.New(time.Unix(0, 0))

	for _, tc := range []struct {
		name      string
		cur, prev *timestamppb.Timestamp
		expect    *timestamppb.Timestamp
	}{
		{name: "previous-is-older", cur: newer, prev: older, expect: older},
		{name: "current-is-older", cur: older, prev: newer, expect: older},
		{name: "no-current-date", cur: nil, prev: older, expect: older},
		{name: "no-previous-date", cur: newer, prev: nil, expect: newer},
		{name: "no-dates", cur: nil, prev: nil, expect: nil},
		// Provenance issued by earlier versions has the epoch where a
		// date was missing. It must not be carried over.
		{name: "epoch-in-previous", cur: newer, prev: epoch, expect: newer},
		{name: "epoch-in-current", cur: epoch, prev: older, expect: older},
		{name: "epoch-in-both", cur: epoch, prev: epoch, expect: nil},
		{name: "epoch-and-no-date", cur: nil, prev: epoch, expect: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := earliestSince(tc.cur, tc.prev)
			if tc.expect == nil {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.True(t, tc.expect.AsTime().Equal(got.AsTime()), "got %v", got.AsTime())
		})
	}
}
