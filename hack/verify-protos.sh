#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

set -o xtrace

source hack/common.sh

make proto
git diff --exit-code || exit_with_msg "Code from protocol definitions is not up to date. Please run 'make proto' and commit the result"
