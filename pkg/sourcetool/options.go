// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package sourcetool

import (
	"errors"

	"github.com/slsa-framework/slsa-source-poc/pkg/auth"
)

type ConfigFn func(*Tool) error

func WithAuthenticator(a *auth.Authenticator) ConfigFn {
	return func(t *Tool) error {
		if a == nil {
			return errors.New("authenticator is nil")
		}
		t.Authenticator = a
		return nil
	}
}

func WithEnforce(enforce bool) ConfigFn {
	return func(t *Tool) error {
		t.Options.Enforce = enforce
		return nil
	}
}

func WithCreatePolicyPR(yesno bool) ConfigFn {
	return func(t *Tool) error {
		t.Options.CreatePolicyPR = yesno
		return nil
	}
}

func WithUserForkOrg(org string) ConfigFn {
	return func(t *Tool) error {
		t.Options.UserForkOrg = org
		return nil
	}
}

func WithPolicyRepo(slug string) ConfigFn {
	return func(t *Tool) error {
		t.Options.PolicyRepo = slug
		return nil
	}
}
