// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

// TODO: This test package uses some functions that live in provenance_test.go
// that seems ugly and maybe we should fix it.

import (
	"slices"
	"testing"

	"github.com/google/go-github/v69/github"

	"github.com/slsa-framework/slsa-source-poc/pkg/slsa"
	"github.com/slsa-framework/slsa-source-poc/pkg/testsupport"
)

func createTestVsa(t *testing.T, repoUri, ref, commit string, verifiedLevels slsa.SourceVerifiedLevels) string {
	vsa, err := CreateUnsignedSourceVsa(repoUri, ref, commit, verifiedLevels, "test-policy")
	if err != nil {
		t.Fatalf("failure creating test vsa: %v", err)
	}
	return vsa
}

func createTestVsaWithIdAndResult(t *testing.T, repoUri, ref, commit, id, result string, verifiedLevels slsa.SourceVerifiedLevels) string {
	vsa, err := createUnsignedSourceVsaAllParams(repoUri, ref, commit, verifiedLevels, "test-policy", id, result)
	if err != nil {
		t.Fatalf("failure creating test vsa: %v", err)
	}
	return vsa
}

func TestReadVsaSuccess(t *testing.T) {
	testVsa := createTestVsa(t, "https://github.com/owner/repo", "refs/some/ref", "de9395302d14b24c0a42685cf27315d93c88ff79", slsa.SourceVerifiedLevels{"TEST_LEVEL"})
	ghc := newTestGhConnection("owner", "repo", "branch",
		// We just need _some_ rulesets response, we don't care what.
		newTagHygieneRulesetsResponse(123, github.RulesetTargetTag,
			github.RulesetEnforcementActive, rulesetOldTime),
		newNotesContent(testVsa))
	verifier := testsupport.NewMockVerifier()

	readStmt, readPred, err := GetVsa(t.Context(), ghc, verifier, "de9395302d14b24c0a42685cf27315d93c88ff79", "refs/some/ref")
	if err != nil {
		t.Fatalf("error finding vsa: %v", err)
	}
	if readStmt == nil || readPred == nil {
		t.Errorf("could not find vsa")
	}

	if !slices.Contains(readPred.GetVerifiedLevels(), "TEST_LEVEL") {
		t.Errorf("expected VSA to contain TEST_LEVEL, but it just contains %v", readPred.GetVerifiedLevels())
	}
}

func TestReadVsaInvalidVsas(t *testing.T) {
	goodRepo := "https://github.com/org/foo"
	goodRef := "refs/heads/main"
	goodCommit := "73f0a864c2c9af12e03dae433a6ff5f5e719d7aa"

	// We want to make sure invalid VSAs aren't returned.
	tests := []struct {
		name string
		vsa  string
	}{
		{
			name: "wrong commit",
			vsa:  createTestVsa(t, goodRepo, goodRef, "def456", slsa.SourceVerifiedLevels{}),
		},
		{
			name: "wrong repo uri",
			vsa:  createTestVsa(t, "https://github.com/foo/bar", goodRef, goodCommit, slsa.SourceVerifiedLevels{}),
		},
		{
			name: "wrong ref",
			vsa:  createTestVsa(t, goodRepo, "refs/heads/bad", goodCommit, slsa.SourceVerifiedLevels{}),
		},
		{
			name: "wrong verifier ID",
			vsa:  createTestVsaWithIdAndResult(t, goodRepo, goodRef, goodCommit, "bad id", "PASSED", slsa.SourceVerifiedLevels{}),
		},
		{
			name: "bad result",
			vsa:  createTestVsaWithIdAndResult(t, goodRepo, goodRef, goodCommit, VsaVerifierId, "FAILED", slsa.SourceVerifiedLevels{}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ghc := newTestGhConnection("org", "foo", "main",
				// We just need _some_ rulesets response, we don't care what.
				newTagHygieneRulesetsResponse(123, github.RulesetTargetTag,
					github.RulesetEnforcementActive, rulesetOldTime),
				newNotesContent(tt.vsa))
			verifier := testsupport.NewMockVerifier()

			_, readPred, err := GetVsa(t.Context(), ghc, verifier, "73f0a864c2c9af12e03dae433a6ff5f5e719d7aa", "refs/heads/main")
			if err != nil {
				t.Fatalf("error finding vsa: %v", err)
			}
			if readPred != nil {
				t.Errorf("should not have gotten vsa: %+v", readPred)
			}
		})
	}
}
