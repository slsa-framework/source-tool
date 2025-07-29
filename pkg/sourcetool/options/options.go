package options

import (
	"fmt"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/policy"
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
}

// DefaultOptions holds the default options the tool initializes with
var Default = Options{
	PolicyRepo:     fmt.Sprintf("%s/%s", policy.SourcePolicyRepoOwner, policy.SourcePolicyRepo),
	UseSSH:         true,
	CreatePolicyPR: true,
}
