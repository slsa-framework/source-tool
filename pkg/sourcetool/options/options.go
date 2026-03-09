// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"fmt"

	"github.com/slsa-framework/source-tool/pkg/policy"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

type Options struct {
	// Organization to look for slsa and user forks
	UserForkOrg string
	Enforce     bool
	UseSSH      bool
	UpdateRepo  bool

	CreatePolicyPR bool

	// PolicyRepo is the repository where the policies are stored
	PolicyRepo string

	// Initialize GitHub attestations store collector
	InitGHCollector bool

	// Initialize Dynamic notes collector
	InitNotesCollector bool

	models.BackendOptions
}

// DefaultOptions holds the default options the tool initializes with
var Default = Options{
	PolicyRepo:         fmt.Sprintf("%s/%s", policy.SourcePolicyRepoOwner, policy.SourcePolicyRepo),
	UseSSH:             true,
	CreatePolicyPR:     true,
	InitNotesCollector: true,
}
