// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"reflect"
	"testing"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"

	"github.com/slsa-framework/source-tool/pkg/audit"
	"github.com/slsa-framework/source-tool/pkg/ghcontrol"
	"github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/slsa-framework/source-tool/pkg/slsa"
)

// assertJSONEqual compares two JSON values semantically (ignoring field order and formatting)
func assertJSONEqual(t *testing.T, got, want interface{}) {
	t.Helper()

	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("failed to marshal got: %v", err)
	}

	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("failed to marshal want: %v", err)
	}

	var gotData, wantData interface{}
	if err := json.Unmarshal(gotJSON, &gotData); err != nil {
		t.Fatalf("failed to unmarshal got JSON: %v", err)
	}
	if err := json.Unmarshal(wantJSON, &wantData); err != nil {
		t.Fatalf("failed to unmarshal want JSON: %v", err)
	}

	if !reflect.DeepEqual(gotData, wantData) {
		t.Errorf("JSON mismatch:\ngot:  %s\nwant: %s", string(gotJSON), string(wantJSON))
	}
}

func TestAuditResultJSON_JSONMarshaling(t *testing.T) {
	tests := []struct {
		name   string
		result AuditResultJSON
		want   AuditResultJSON
	}{
		{
			name: "complete audit result",
			result: AuditResultJSON{
				Owner:        "test-owner",
				Repository:   "test-repo",
				Branch:       "main",
				LatestCommit: "abc123",
				CommitResults: []AuditCommitResultJSON{
					{
						Commit:         "abc123",
						Status:         "passed",
						VerifiedLevels: []string{"SLSA_SOURCE_LEVEL_3"},
						Link:           "https://github.com/test-owner/test-repo/commit/abc123",
					},
				},
				Summary: &AuditSummary{
					TotalCommits:  1,
					PassedCommits: 1,
					FailedCommits: 0,
				},
			},
			want: AuditResultJSON{
				Owner:        "test-owner",
				Repository:   "test-repo",
				Branch:       "main",
				LatestCommit: "abc123",
				CommitResults: []AuditCommitResultJSON{
					{
						Commit:         "abc123",
						Status:         "passed",
						VerifiedLevels: []string{"SLSA_SOURCE_LEVEL_3"},
						Link:           "https://github.com/test-owner/test-repo/commit/abc123",
					},
				},
				Summary: &AuditSummary{
					TotalCommits:  1,
					PassedCommits: 1,
					FailedCommits: 0,
				},
			},
		},
		{
			name: "audit with failed commit",
			result: AuditResultJSON{
				Owner:        "test-owner",
				Repository:   "test-repo",
				Branch:       "main",
				LatestCommit: "def456",
				CommitResults: []AuditCommitResultJSON{
					{
						Commit: "def456",
						Status: "failed",
						Link:   "https://github.com/test-owner/test-repo/commit/def456",
					},
				},
				Summary: &AuditSummary{
					TotalCommits:  1,
					PassedCommits: 0,
					FailedCommits: 1,
				},
			},
			want: AuditResultJSON{
				Owner:        "test-owner",
				Repository:   "test-repo",
				Branch:       "main",
				LatestCommit: "def456",
				CommitResults: []AuditCommitResultJSON{
					{
						Commit: "def456",
						Status: "failed",
						Link:   "https://github.com/test-owner/test-repo/commit/def456",
					},
				},
				Summary: &AuditSummary{
					TotalCommits:  1,
					PassedCommits: 0,
					FailedCommits: 1,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use semantic JSON comparison instead of string comparison
			assertJSONEqual(t, tt.result, tt.want)
		})
	}
}

func TestConvertAuditResultToJSON(t *testing.T) {
	ghc := ghcontrol.NewGhConnection("test-owner", "test-repo", "refs/heads/main")

	tests := []struct {
		name   string
		result *audit.AuditCommitResult
		mode   AuditMode
		want   AuditCommitResultJSON
	}{
		{
			name: "passed audit in basic mode",
			result: &audit.AuditCommitResult{
				Commit: "abc123",
				VsaPred: &vpb.VerificationSummary{
					VerifiedLevels: []string{"SLSA_SOURCE_LEVEL_3"},
				},
				ProvPred: &provenance.SourceProvenancePred{
					PrevCommit: "def456",
				},
				GhPriorCommit: "def456",
			},
			mode: AuditModeBasic,
			want: AuditCommitResultJSON{
				Commit: "abc123",
				Status: "passed",
				Link:   "https://github.com/test-owner/test-repo/commit/def456",
			},
		},
		{
			name: "passed audit in full mode",
			result: &audit.AuditCommitResult{
				Commit: "abc123",
				VsaPred: &vpb.VerificationSummary{
					VerifiedLevels: []string{"SLSA_SOURCE_LEVEL_3"},
				},
				ProvPred: &provenance.SourceProvenancePred{
					PrevCommit: "def456",
					Controls:   []*provenance.Control{{Name: "test_control"}},
				},
				GhPriorCommit: "def456",
				GhControlStatus: &ghcontrol.GhControlStatus{
					Controls: slsa.Controls{},
				},
			},
			mode: AuditModeFull,
			want: func() AuditCommitResultJSON {
				matches := true
				return AuditCommitResultJSON{
					Commit:            "abc123",
					Status:            "passed",
					VerifiedLevels:    []string{"SLSA_SOURCE_LEVEL_3"},
					PrevCommitMatches: &matches,
					ProvControls:      []*provenance.Control{{Name: "test_control"}},
					GhControls:        slsa.Controls{},
					PrevCommit:        "def456",
					GhPriorCommit:     "def456",
					Link:              "https://github.com/test-owner/test-repo/commit/def456",
				}
			}(),
		},
		{
			name: "failed audit shows details even in basic mode",
			result: &audit.AuditCommitResult{
				Commit:        "abc123",
				VsaPred:       nil,
				ProvPred:      nil,
				GhPriorCommit: "def456",
			},
			mode: AuditModeBasic,
			want: AuditCommitResultJSON{
				Commit: "abc123",
				Status: "failed",
				Link:   "https://github.com/test-owner/test-repo/commit/def456",
			},
		},
		{
			name: "failed audit with mismatched commits",
			result: &audit.AuditCommitResult{
				Commit: "abc123",
				VsaPred: &vpb.VerificationSummary{
					VerifiedLevels: []string{"SLSA_SOURCE_LEVEL_3"},
				},
				ProvPred: &provenance.SourceProvenancePred{
					PrevCommit: "wrong123",
					Controls:   []*provenance.Control{{Name: "test_control"}},
				},
				GhPriorCommit: "def456",
			},
			mode: AuditModeFull,
			want: func() AuditCommitResultJSON {
				matches := false
				return AuditCommitResultJSON{
					Commit:            "abc123",
					Status:            "failed",
					VerifiedLevels:    []string{"SLSA_SOURCE_LEVEL_3"},
					PrevCommitMatches: &matches,
					ProvControls:      []*provenance.Control{{Name: "test_control"}},
					PrevCommit:        "wrong123",
					GhPriorCommit:     "def456",
					Link:              "https://github.com/test-owner/test-repo/commit/def456",
				}
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertAuditResultToJSON(ghc, tt.result, tt.mode)

			if got.Commit != tt.want.Commit {
				t.Errorf("Commit = %v, want %v", got.Commit, tt.want.Commit)
			}
			if got.Status != tt.want.Status {
				t.Errorf("Status = %v, want %v", got.Status, tt.want.Status)
			}
			if got.Link != tt.want.Link {
				t.Errorf("Link = %v, want %v", got.Link, tt.want.Link)
			}

			// Check verified levels
			if len(got.VerifiedLevels) != len(tt.want.VerifiedLevels) {
				t.Errorf("VerifiedLevels length = %v, want %v", len(got.VerifiedLevels), len(tt.want.VerifiedLevels))
			}

			// Check PrevCommitMatches pointer
			if (got.PrevCommitMatches == nil) != (tt.want.PrevCommitMatches == nil) {
				t.Errorf("PrevCommitMatches nil mismatch: got nil=%v, want nil=%v",
					got.PrevCommitMatches == nil, tt.want.PrevCommitMatches == nil)
			} else if got.PrevCommitMatches != nil && *got.PrevCommitMatches != *tt.want.PrevCommitMatches {
				t.Errorf("PrevCommitMatches = %v, want %v", *got.PrevCommitMatches, *tt.want.PrevCommitMatches)
			}
		})
	}
}

func TestAuditMode_String(t *testing.T) {
	tests := []struct {
		name string
		mode AuditMode
		want string
	}{
		{
			name: "basic mode",
			mode: AuditModeBasic,
			want: "basic",
		},
		{
			name: "full mode",
			mode: AuditModeFull,
			want: "full",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mode.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuditMode_Set(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    AuditMode
		wantErr bool
	}{
		{
			name:    "set to basic",
			value:   "basic",
			want:    AuditModeBasic,
			wantErr: false,
		},
		{
			name:    "set to full",
			value:   "full",
			want:    AuditModeFull,
			wantErr: false,
		},
		{
			name:    "invalid value",
			value:   "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mode AuditMode
			err := mode.Set(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && mode != tt.want {
				t.Errorf("Set() got = %v, want %v", mode, tt.want)
			}
		})
	}
}
