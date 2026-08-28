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
change_date="$(python3 -c "
import datetime, sys
d = datetime.date.fromisoformat(sys.argv[1])
try:
    print(d.replace(year=d.year + 2))
except ValueError:            # 29 Feb -> 28 Feb
    print(d.replace(year=d.year + 2, day=28))
" "$commit_date")"

echo "commit:        $commit_sha ($commit_date)"
echo "Change Date:   $change_date"
echo "Change License: MIT"
