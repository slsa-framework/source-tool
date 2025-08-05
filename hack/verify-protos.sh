#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

set -o xtrace

source hack/common.sh

make proto

# Check if the proto definitions need updating
git diff --exit-code || exit_with_msg "Code from protocol definitions is not up to date. Please run 'make proto' and commit the result"

# Check the format of the proto files
buf lint || exit_with_msg "The proto files have linting errors. Please run 'buf lint' and fix them before committing"
