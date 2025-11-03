// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestVerifyCommitResult_JSONMarshaling(t *testing.T) {
	tests := []struct {
		name   string
		result VerifyCommitResult
		want   VerifyCommitResult
	}{
		{
			name: "successful verification",
			result: VerifyCommitResult{
				Success:        true,
				Commit:         "abc123",
				Ref:            "main",
				RefType:        "branch",
				Owner:          "test-owner",
				Repository:     "test-repo",
				VerifiedLevels: []string{"SLSA_SOURCE_LEVEL_3"},
			},
			want: VerifyCommitResult{
				Success:        true,
				Commit:         "abc123",
				Ref:            "main",
				RefType:        "branch",
				Owner:          "test-owner",
				Repository:     "test-repo",
				VerifiedLevels: []string{"SLSA_SOURCE_LEVEL_3"},
			},
		},
		{
			name: "failed verification",
			result: VerifyCommitResult{
				Success:    false,
				Commit:     "def456",
				Ref:        "develop",
				RefType:    "branch",
				Owner:      "test-owner",
				Repository: "test-repo",
				Message:    "no VSA matching commit 'def456' on branch 'develop' found in github.com/test-owner/test-repo",
			},
			want: VerifyCommitResult{
				Success:    false,
				Commit:     "def456",
				Ref:        "develop",
				RefType:    "branch",
				Owner:      "test-owner",
				Repository: "test-repo",
				Message:    "no VSA matching commit 'def456' on branch 'develop' found in github.com/test-owner/test-repo",
			},
		},
		{
			name: "tag verification",
			result: VerifyCommitResult{
				Success:        true,
				Commit:         "ghi789",
				Ref:            "v1.0.0",
				RefType:        "tag",
				Owner:          "test-owner",
				Repository:     "test-repo",
				VerifiedLevels: []string{"SLSA_SOURCE_LEVEL_2", "SLSA_SOURCE_LEVEL_3"},
			},
			want: VerifyCommitResult{
				Success:        true,
				Commit:         "ghi789",
				Ref:            "v1.0.0",
				RefType:        "tag",
				Owner:          "test-owner",
				Repository:     "test-repo",
				VerifiedLevels: []string{"SLSA_SOURCE_LEVEL_2", "SLSA_SOURCE_LEVEL_3"},
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

func TestOutputOptions_WriteJSON(t *testing.T) {
	result := VerifyCommitResult{
		Success:        true,
		Commit:         "abc123",
		Ref:            "main",
		RefType:        "branch",
		Owner:          "test-owner",
		Repository:     "test-repo",
		VerifiedLevels: []string{"SLSA_SOURCE_LEVEL_3"},
	}

	var buf bytes.Buffer
	opts := outputOptions{
		format: OutputFormatJSON,
		writer: &buf,
	}

	if err := opts.writeJSON(result); err != nil {
		t.Fatalf("writeJSON failed: %v", err)
	}

	// Verify it's valid JSON
	var decoded VerifyCommitResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if decoded.Commit != result.Commit {
		t.Errorf("commit mismatch: got %s, want %s", decoded.Commit, result.Commit)
	}
	if decoded.Success != result.Success {
		t.Errorf("success mismatch: got %v, want %v", decoded.Success, result.Success)
	}
}

func TestOutputOptions_IsJSON(t *testing.T) {
	tests := []struct {
		name   string
		format string
		want   bool
	}{
		{
			name:   "JSON format",
			format: OutputFormatJSON,
			want:   true,
		},
		{
			name:   "text format",
			format: OutputFormatText,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := outputOptions{format: tt.format}
			if got := opts.isJSON(); got != tt.want {
				t.Errorf("isJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}
