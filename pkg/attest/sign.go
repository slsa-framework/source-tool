// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bytes"

	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/options"
)

func Sign(data string) (string, error) {
	artifact, err := signer.NewSigner().SignStatement(
		[]byte(data), options.WithPayloadType("application/vnd.in-toto+json"),
	)
	if err != nil {
		return "", err
	}

	// SignStatement returns a polymorphic SignedArtifact; WriteTo emits its
	// canonical JSON serialization (a sigstore bundle for the default backend).
	var buf bytes.Buffer
	if _, err := artifact.WriteTo(&buf); err != nil {
		return "", err
	}

	return buf.String(), nil
}
