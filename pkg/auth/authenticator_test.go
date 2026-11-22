// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// tokenReader is an authenticator implementation that only reads a token
type tokenReader struct {
	authenticatorImplementation
	token string
	err   error
}

func (tr *tokenReader) readToken() (string, error) {
	return tr.token, tr.err
}

func TestUsesEnvironmentToken(t *testing.T) {
	for _, tc := range []struct {
		name     string
		envToken string
		token    string
		err      error
		expect   bool
	}{
		{name: "environment-token", envToken: "env-token", token: "env-token", expect: true},
		{name: "app-token", envToken: "env-token", token: "app-token", expect: false},
		{name: "app-token-no-env", envToken: "", token: "app-token", expect: false},
		{name: "no-token", envToken: "", token: "", expect: false},
		{name: "read-error", envToken: "env-token", token: "env-token", err: errors.New("read error"), expect: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITHUB_TOKEN", tc.envToken)
			a := &Authenticator{impl: &tokenReader{token: tc.token, err: tc.err}}
			require.Equal(t, tc.expect, a.UsesEnvironmentToken())
		})
	}
}
