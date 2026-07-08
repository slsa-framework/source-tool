// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"fmt"

	"github.com/carabiner-dev/attestation"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

// GetSourceRefsForCommit returns the source branch annotations from the subject
func GetSourceRefsForCommit(att attestation.Envelope, commit *models.Commit) ([]string, error) {
	subject := GetSubjectForCommit(att, commit)
	if subject == nil {
		return []string{}, fmt.Errorf("statement \n%v\n does not match commit %s", string(att.GetPredicate().GetData()), commit)
	}
	annotations := subject.GetAnnotations()
	sourceRefs, ok := annotations.GetFields()[slsa.SourceRefsAnnotation]
	if !ok {
		// This used to be called 'source_branches', maybe this is an old VSA.
		// TODO: remove once we're not worried about backward compatibility.
		sourceRefs, ok = annotations.GetFields()[slsa.SourceBranchesAnnotation]
		if !ok {
			return []string{}, fmt.Errorf("no source_refs or source_branches annotation in VSA subject")
		}
	}

	protoRefs := sourceRefs.GetListValue()
	stringRefs := []string{}
	for _, ref := range protoRefs.GetValues() {
		stringRefs = append(stringRefs, ref.GetStringValue())
	}
	return stringRefs, nil
}

// Returns the _first_ subject that includes the commit.
// TODO: add support for multiple subjects...
func GetSubjectForCommit(att attestation.Envelope, commit *models.Commit) *intoto.ResourceDescriptor {
	var fromSha *intoto.ResourceDescriptor
	for _, subject := range att.GetStatement().GetSubjects() {
		rd, ok := subject.(*intoto.ResourceDescriptor)
		if !ok {
			continue
		}
		val, ok := rd.GetDigest()["gitCommit"]
		if ok && val == commit.SHA {
			return rd
		}

		if val, ok = rd.GetDigest()["sha1"]; ok && val == commit.SHA {
			fromSha = rd
		}
	}

	// Prefer the gitCommit version, but if we saw a sha1 of the commit
	// sha return the backup resource descriptor.
	return fromSha
}

// Just make this easy for logging...
func StatementToString(stmt *intoto.Statement) string {
	if stmt == nil {
		return "<nil>"
	}

	options := protojson.MarshalOptions{
		Multiline:     true,
		Indent:        " ",
		AllowPartial:  true,
		UseProtoNames: false,
	}

	jsonBytes, err := options.Marshal(stmt)
	if err != nil {
		return fmt.Sprintf("%v", err)
	}
	return string(jsonBytes)
}
