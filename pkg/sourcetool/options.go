// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package sourcetool

import (
	"errors"

	"github.com/slsa-framework/source-tool/pkg/auth"
)

type ConfigFn func(*Tool) error

func WithGithubCollector(yesno bool) ConfigFn {
	return func(t *Tool) error {
		t.Options.InitGHCollector = yesno
		return nil
	}
}

func WithGithubStorer(yesno bool) ConfigFn {
	return func(t *Tool) error {
		t.Options.InitGHStorer = yesno
		return nil
	}
}

func WithNotesCollector(yesno bool) ConfigFn {
	return func(t *Tool) error {
		t.Options.InitNotesCollector = yesno
		return nil
	}
}

func WithNotesStorer(yesno bool) ConfigFn {
	return func(t *Tool) error {
		t.Options.InitNotesStorer = yesno
		return nil
	}
}

func WithStorageLocation(l ...string) ConfigFn {
	return func(t *Tool) error {
		t.Options.StorageLocations = l
		return nil
	}
}

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

func WithAllowMergeCommits(allow bool) ConfigFn {
	return func(t *Tool) error {
		t.Options.AllowMergeCommits = allow
		return nil
	}
}
