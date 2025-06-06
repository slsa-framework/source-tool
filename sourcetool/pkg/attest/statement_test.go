package attest

import (
	"fmt"
	"slices"
	"testing"

	spb "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func newStatement(commit string, annotation map[string]any) (*spb.Statement, error) {
	var sub []*spb.ResourceDescriptor
	if annotation != nil {
		annotationStruct, err := structpb.NewStruct(annotation)
		if err != nil {
			return nil, fmt.Errorf("creating struct from map: %w", err)
		}
		sub = []*spb.ResourceDescriptor{{
			Digest:      map[string]string{"gitCommit": commit},
			Annotations: annotationStruct,
		}}
	}

	statementPb := spb.Statement{
		Type:          spb.StatementTypeUri,
		Subject:       sub,
		PredicateType: "test",
		Predicate:     &structpb.Struct{},
	}
	return &statementPb, nil
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
		stmt           *spb.Statement
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
			stmt, err := newStatement("abc123", map[string]any{tt.annotationName: stringToAnyArray(tt.refs)})
			if err != nil {
				t.Fatalf("error creating statement: %v", err)
			}

			gotRefs, err := GetSourceRefsForCommit(stmt, "abc123")

			if err != nil && !tt.expectErr {
				t.Errorf("did not expect error, got %v", err)
			}

			if !slices.Equal(gotRefs, tt.expectedRefs) {
				t.Errorf("expected %v, got %v", tt.expectedRefs, gotRefs)
			}
		})
	}
}
