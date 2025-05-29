package gh_control

import (
	"fmt"
	"strings"
)

// Matches any reference type.
const AnyReference = "*"

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
