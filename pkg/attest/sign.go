// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/options"
	"google.golang.org/protobuf/encoding/protojson"
)

func Sign(data string) (string, error) {
	bundle, err := signer.NewSigner().SignStatement(
		[]byte(data), options.WithPayloadType("application/vnd.in-toto+json"),
	)
	if err != nil {
		return "", err
	}

	json, err := protojson.Marshal(bundle)
	if err != nil {
		return "", err
	}

	return string(json), nil
}
