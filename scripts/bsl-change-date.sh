#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# Print the effective Business Source License Change Date for this checkout.
#
# The Change Date is two years after the author date of the commit you are
# holding, so every commit restarts the two-year clock for the version it
# produces. Older copies keep the Change Date they were published with and
# convert to MIT on schedule regardless of later commits.
set -euo pipefail

ref="${1:-HEAD}"

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "error: not inside a Git repository (the Change Date is derived from commit history)" >&2
    exit 1
fi

commit_date="$(git show -s --format=%as "$ref")"
commit_sha="$(git rev-parse --short "$ref")"
# Two years on; 29 February maps to 28 February (GNU date would roll over
# to 1 March, so the leap day is handled explicitly).
year=${commit_date:0:4} rest=${commit_date:4}
if [[ $rest == "-02-29" ]]; then
    change_date="$((10#$year + 2))-02-28"
else
    change_date="$((10#$year + 2))$rest"
fi

echo "commit:        $commit_sha ($commit_date)"
echo "Change Date:   $change_date"
echo "Change License: MIT"
