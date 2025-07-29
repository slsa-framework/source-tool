// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"github.com/carabiner-dev/bnd/pkg/bnd"
	"google.golang.org/protobuf/encoding/protojson"
)

func Sign(data string) (string, error) {
	signer := bnd.NewSigner()
	bundle, err := signer.SignStatement([]byte(data))
	if err != nil {
		return "", err
	}

	json, err := protojson.Marshal(bundle)
	if err != nil {
		return "", err
	}

	return string(json), nil
}
