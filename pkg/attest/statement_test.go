// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"fmt"
	"slices"
	"testing"

	"github.com/carabiner-dev/attestation"
	spb "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

// mockEnvelope implements attestation.Envelope for testing.
type mockEnvelope struct {
	statement *mockStatement
	predicate *mockPredicate
}

func (m *mockEnvelope) GetStatement() attestation.Statement       { return m.statement }
func (m *mockEnvelope) GetPredicate() attestation.Predicate       { return m.predicate }
func (m *mockEnvelope) GetSignatures() []attestation.Signature    { return nil }
func (m *mockEnvelope) GetCertificate() attestation.Certificate   { return nil }
func (m *mockEnvelope) GetVerification() attestation.Verification { return nil }
func (m *mockEnvelope) Verify(...any) error                       { return nil }

type mockStatement struct {
	subjects []attestation.Subject
}

func (m *mockStatement) GetSubjects() []attestation.Subject          { return m.subjects }
func (m *mockStatement) GetPredicate() attestation.Predicate         { return nil }
func (m *mockStatement) GetPredicateType() attestation.PredicateType { return "" }
func (m *mockStatement) GetType() string                             { return "" }
func (m *mockStatement) GetVerification() attestation.Verification   { return nil }

type mockPredicate struct {
	data []byte
}

func (m *mockPredicate) GetType() attestation.PredicateType        { return "" }
func (m *mockPredicate) SetType(attestation.PredicateType) error   { return nil }
func (m *mockPredicate) GetParsed() any                            { return nil }
func (m *mockPredicate) GetData() []byte                           { return m.data }
func (m *mockPredicate) GetVerification() attestation.Verification { return nil }
func (m *mockPredicate) GetOrigin() attestation.Subject            { return nil }
func (m *mockPredicate) SetOrigin(attestation.Subject)             {}
func (m *mockPredicate) SetVerification(attestation.Verification)  {}

func newMockEnvelope(commit string, annotation map[string]any) (attestation.Envelope, error) {
	var subjects []attestation.Subject
	if annotation != nil {
		annotationStruct, err := structpb.NewStruct(annotation)
		if err != nil {
			return nil, fmt.Errorf("creating struct from map: %w", err)
		}
		subjects = []attestation.Subject{&spb.ResourceDescriptor{
			Digest:      map[string]string{"gitCommit": commit},
			Annotations: annotationStruct,
		}}
	}

	return &mockEnvelope{
		statement: &mockStatement{subjects: subjects},
		predicate: &mockPredicate{data: []byte("{}")},
	}, nil
}

func newMockEnvelopeWithSubjects(subjects []attestation.Subject) attestation.Envelope {
	return &mockEnvelope{
		statement: &mockStatement{subjects: subjects},
		predicate: &mockPredicate{data: []byte("{}")},
	}
}

func TestGetSubjectForCommit(t *testing.T) {
	commitSHA := "abc123"
	commit := &models.Commit{SHA: commitSHA}

	tests := []struct {
		name     string
		subjects []attestation.Subject
		wantNil  bool
	}{
		{
			name: "match by gitCommit",
			subjects: []attestation.Subject{
				&spb.ResourceDescriptor{
					Digest: map[string]string{"gitCommit": commitSHA},
				},
			},
		},
		{
			name: "match by sha1 fallback",
			subjects: []attestation.Subject{
				&spb.ResourceDescriptor{
					Digest: map[string]string{"sha1": commitSHA},
				},
			},
		},
		{
			name: "gitCommit preferred over sha1",
			subjects: []attestation.Subject{
				&spb.ResourceDescriptor{
					Digest: map[string]string{"sha1": commitSHA},
					Name:   "sha1-subject",
				},
				&spb.ResourceDescriptor{
					Digest: map[string]string{"gitCommit": commitSHA},
					Name:   "gitCommit-subject",
				},
			},
		},
		{
			name: "no match",
			subjects: []attestation.Subject{
				&spb.ResourceDescriptor{
					Digest: map[string]string{"gitCommit": "other"},
				},
			},
			wantNil: true,
		},
		{
			name:     "empty subjects",
			subjects: nil,
			wantNil:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newMockEnvelopeWithSubjects(tt.subjects)
			got := GetSubjectForCommit(env, commit)

			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil subject")
			}

			// For the "preferred" test, verify we got the gitCommit subject
			if tt.name == "gitCommit preferred over sha1" {
				if got.GetName() != "gitCommit-subject" {
					t.Errorf("expected gitCommit-subject, got %s", got.GetName())
				}
			}
		})
	}
}

func stringToAnyArray(valArray []string) []any {
	aa := make([]any, len(valArray))
	for i := range valArray {
		aa[i] = valArray[i]
	}
	return aa
}

func TestGetSourceRefsForCommit(t *testing.T) {
	tests := []struct {
		name           string
		annotationName string
		refs           []string
		expectedRefs   []string
		expectErr      bool
	}{
		{
			name:           "source_refs with list",
			annotationName: "source_refs",
			refs:           []string{"foo"},
			expectedRefs:   []string{"foo"},
			expectErr:      false,
		},
		{
			name:           "source_branches with list",
			annotationName: "source_branches",
			refs:           []string{"foo"},
			expectedRefs:   []string{"foo"},
			expectErr:      false,
		},
		{
			name:           "empty refs",
			annotationName: "source_refs",
			refs:           []string{},
			expectedRefs:   []string{},
			expectErr:      false,
		},
		{
			name:           "many refs",
			annotationName: "source_refs",
			refs:           []string{"foo", "bar", "baz"},
			expectedRefs:   []string{"foo", "bar", "baz"},
			expectErr:      false,
		},
		{
			name:           "unknown annotation",
			annotationName: "foo_refs",
			refs:           []string{"foo", "bar", "baz"},
			expectedRefs:   []string{},
			expectErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, err := newMockEnvelope("abc123", map[string]any{tt.annotationName: stringToAnyArray(tt.refs)})
			if err != nil {
				t.Fatalf("error creating envelope: %v", err)
			}

			commit := &models.Commit{SHA: "abc123"}
			gotRefs, err := GetSourceRefsForCommit(env, commit)

			if err != nil && !tt.expectErr {
				t.Errorf("did not expect error, got %v", err)
			}

			if !slices.Equal(gotRefs, tt.expectedRefs) {
				t.Errorf("expected %v, got %v", tt.expectedRefs, gotRefs)
			}
		})
	}
}
