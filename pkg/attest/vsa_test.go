// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"testing"

	spb "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

func newTestBranch(hostname, path, branchName string) *models.Branch {
	return &models.Branch{
		Name: branchName,
		Repository: &models.Repository{
			Hostname: hostname,
			Path:     path,
		},
	}
}

func newTestCommit(sha string) *models.Commit {
	return &models.Commit{SHA: sha}
}

func TestCreateUnsignedSourceVsa(t *testing.T) {
	branch := newTestBranch("github.com", "owner/repo", "main")
	commit := newTestCommit("de9395302d14b24c0a42685cf27315d93c88ff79")

	vsaJSON, err := CreateUnsignedSourceVsa(branch, commit, slsa.SourceVerifiedLevels{"TEST_LEVEL"}, "test-policy")
	require.NoError(t, err)
	require.NotEmpty(t, vsaJSON)

	// Parse the statement back
	var stmt spb.Statement
	err = protojson.Unmarshal([]byte(vsaJSON), &stmt)
	require.NoError(t, err)

	require.Equal(t, VsaPredicateType, stmt.GetPredicateType())
	require.Len(t, stmt.GetSubject(), 1)
	require.Equal(t, commit.SHA, stmt.GetSubject()[0].GetDigest()["gitCommit"])

	// Verify the predicate contains the verifier ID and result
	predFields := stmt.GetPredicate().GetFields()
	require.Equal(t, VsaVerifierId, predFields["verifier"].GetStructValue().GetFields()["id"].GetStringValue())
	require.Equal(t, "PASSED", predFields["verificationResult"].GetStringValue())
	require.Equal(t, "test-policy", predFields["policy"].GetStructValue().GetFields()["uri"].GetStringValue())

	// Check verified levels
	levels := predFields["verifiedLevels"].GetListValue().GetValues()
	require.Len(t, levels, 1)
	require.Equal(t, "TEST_LEVEL", levels[0].GetStringValue())

	// Check resource URI includes the repo URL
	require.Contains(t, predFields["resourceUri"].GetStringValue(), branch.Repository.GetHttpURL())
}

func TestCreateUnsignedSourceVsaMultipleLevels(t *testing.T) {
	branch := newTestBranch("github.com", "owner/repo", "main")
	commit := newTestCommit("73f0a864c2c9af12e03dae433a6ff5f5e719d7aa")

	vsaJSON, err := CreateUnsignedSourceVsa(branch, commit, slsa.SourceVerifiedLevels{"LEVEL_1", "LEVEL_2", "LEVEL_3"}, "test-policy")
	require.NoError(t, err)

	var stmt spb.Statement
	err = protojson.Unmarshal([]byte(vsaJSON), &stmt)
	require.NoError(t, err)

	levels := stmt.GetPredicate().GetFields()["verifiedLevels"].GetListValue().GetValues()
	require.Len(t, levels, 3)
}

func TestCreateUnsignedSourceVsaAllParams(t *testing.T) {
	branch := newTestBranch("github.com", "owner/repo", "main")
	commit := newTestCommit("73f0a864c2c9af12e03dae433a6ff5f5e719d7aa")

	tests := []struct {
		name       string
		verifierID string
		result     string
	}{
		{
			name:       "custom verifier and PASSED",
			verifierID: "custom-verifier",
			result:     "PASSED",
		},
		{
			name:       "default verifier and FAILED",
			verifierID: VsaVerifierId,
			result:     "FAILED",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vsaJSON, err := createUnsignedSourceVsaAllParams(branch, commit, slsa.SourceVerifiedLevels{}, "test-policy", tt.verifierID, tt.result)
			require.NoError(t, err)

			var stmt spb.Statement
			err = protojson.Unmarshal([]byte(vsaJSON), &stmt)
			require.NoError(t, err)

			predFields := stmt.GetPredicate().GetFields()
			require.Equal(t, tt.verifierID, predFields["verifier"].GetStructValue().GetFields()["id"].GetStringValue())
			require.Equal(t, tt.result, predFields["verificationResult"].GetStringValue())
		})
	}
}

func TestCreateUnsignedSourceVsaSubjectAnnotation(t *testing.T) {
	branch := newTestBranch("github.com", "owner/repo", "main")
	commit := newTestCommit("abc123")

	vsaJSON, err := CreateUnsignedSourceVsa(branch, commit, slsa.SourceVerifiedLevels{}, "test-policy")
	require.NoError(t, err)

	var stmt spb.Statement
	err = protojson.Unmarshal([]byte(vsaJSON), &stmt)
	require.NoError(t, err)

	// The subject should have a source_refs annotation with the branch ref
	annotations := stmt.GetSubject()[0].GetAnnotations()
	require.NotNil(t, annotations)
	refs := annotations.GetFields()[slsa.SourceRefsAnnotation].GetListValue().GetValues()
	require.Len(t, refs, 1)
	require.Equal(t, branch.FullRef(), refs[0].GetStringValue())
}
