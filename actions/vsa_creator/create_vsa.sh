#!/bin/sh
set -e

# Usage:
# ./create_vsa.sh <COMMIT> <REPO> <BRANCH> <LEVEL>

COMMIT=$1
REPO=$2
BRANCH=$3
LEVEL=$4
TIME_VERIFIED=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Create an unsigned in-toto statement of a source VSA according to
# https://slsa.dev/spec/draft/source-requirements#summary-attestation
UNSIGNED_VSA=$(jq -n --arg subjectCommit ${COMMIT} --arg subjectRepo ${REPO} --arg subjectBranch ${BRANCH} --arg timeVerified $TIME_VERIFIED --arg sourceLevel $LEVEL -f vsa_template.jq)

echo $UNSIGNED_VSA

# TODO: sign it
