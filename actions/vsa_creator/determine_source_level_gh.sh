#!/bin/sh
set -e

# Determine's the source level of a GitHub repository/commit/branch.
# Usage:
# ./determine_source_level_gh.sh <COMMIT> <REPO> <BRANCH>

# TODO: Commit is currently ignored, do we really need it
COMMIT=$1
REPO=$2
BRANCH=$3

# TODO: Add GitHub token for non-public repos?
GITHUB_RULESET=$(curl -L \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    https://api.github.com/repos/${REPO}/rules/branches/${BRANCH})

echo $GITHUB_RULESET