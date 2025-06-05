package ghcontrol

import (
	"fmt"
	"strings"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
)

// Matches any reference type.
const AnyReference = "*"
const GitHubActionsIntegrationId = int64(15368)

func BranchToFullRef(branch string) string {
	return fmt.Sprintf("refs/heads/%s", branch)
}

func TagToFullRef(tag string) string {
	return fmt.Sprintf("refs/tags/%s", tag)
}

// Returns "" if the ref isn't a branch
func GetBranchFromRef(ref string) string {
	return strings.TrimPrefix(ref, "refs/heads/")
}

func GetTagFromRef(ref string) string {
	return strings.TrimPrefix(ref, "refs/tags/")
}

func CheckNameToControlName(checkName string) slsa.ControlName {
	return slsa.ControlName(fmt.Sprintf("GH_REQUIRED_CHECK_%s", checkName))
}
