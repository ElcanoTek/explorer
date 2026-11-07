#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# scripts/version.sh — Explorer's release identity, derived from git. The ONE
# place that knows how an Explorer release number is shaped.
#
# Explorer ships from a rolling release train: every PR squash-merges into
# `main`, and every push to `main` that passes CI is a release. There is no
# VERSION file, no semver bump to argue about, and NOBODY EVER TYPES A VERSION
# NUMBER — the release workflow (.github/workflows/release.yml) derives the
# next date-based tag from the clock and the tags already on the repo, and
# builds derive theirs from `git describe`.
#
# The release number is CalVer with a per-day ordinal:
#
#     YYYY.MM.DD.N        e.g. 2026.09.04.1, 2026.09.04.2, 2026.12.25.1
#
# tagged as `v<version>`. The date is UTC and N counts that day's releases
# from 1.
#
# Subcommands (all read-only; none of them writes a tag — release.yml does that):
#
#   current   the newest release REACHABLE FROM HEAD, or the `dev` sentinel when
#             none is. Reachability, not "newest tag anywhere": an old checkout
#             in a clone that has fetched newer tags must not claim them.
#   describe  what a build stamps or reports: the version if HEAD is exactly a
#             release, else <version>+<n>.g<sha> ("n commits past that release"),
#             with a `.dirty` suffix for a modified tree. Falls back to
#             dev+g<sha> before the first release.
#   next      the next unused tag for today, e.g. v2026.09.04.3. Used by
#             release.yml; safe to run locally to see what the next push would
#             be tagged.
#   released-at [rev]
#             the release tag ON that commit (default HEAD), or nothing. The
#             idempotence check release.yml uses.
#   semver    the same identity re-rendered as a strict 3-field SemVer,
#             YYYY.<MM*100+DD>.<N> (2026.09.04.1 -> 2026.904.1).
#   filter    read names on stdin, print the release tags among them, oldest
#             first (numeric per field, so .10 sorts after .9). Used by
#             release.yml to decide which superseded release objects to prune.
#
# Kept in POSIX-ish bash with no dependency beyond git so bootstrap.sh,
# update.sh, the Makefile and CI can all call it.

set -euo pipefail

# Release tags only. Git's glob is the PRE-filter, not the check: in git's
# fnmatch syntax `[0-9]*` is "one digit then anything at all", so this alone
# also matches `v2026.09.04.1oops`. It narrows what git walks; TAG_RE below is
# what actually decides whether a name is a release tag.
readonly TAG_GLOB='v[0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9].[0-9]*'

# The real format. Anchored and fully numeric, with ordinal >= 1.
readonly TAG_RE='^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$'

# The sentinel an unreleased/unstamped build reports.
readonly DEV_SENTINEL='dev'

die() {
	printf 'version.sh: %s\n' "$1" >&2
	exit 1
}

# is_release_tag is the single yes/no for "is this name one of ours?".
is_release_tag() {
	printf '%s' "${1:-}" | grep -Eq "$TAG_RE"
}

# in_explorer_git_repo is true only when git discovery lands on THIS checkout.
in_explorer_git_repo() {
	local toplevel script_root
	toplevel="$(git rev-parse --show-toplevel 2>/dev/null)" || return 1
	script_root="$(CDPATH='' cd -- "$(dirname -- "$(script_path)")/.." && pwd -P)" || return 1
	[ "$(CDPATH='' cd -- "$toplevel" && pwd -P)" = "$script_root" ]
}

script_path() {
	local src="${BASH_SOURCE[0]}" dir
	while [ -L "$src" ]; do
		dir="$(CDPATH='' cd -- "$(dirname -- "$src")" && pwd -P)"
		src="$(readlink -- "$src")"
		case "$src" in
		/*) ;;
		*) src="$dir/$src" ;;
		esac
	done
	printf '%s' "$src"
}

short_sha() {
	git rev-parse --short=12 HEAD 2>/dev/null || echo unknown
}

tree_is_dirty() {
	[ -n "$(git status --porcelain --untracked-files=normal 2>/dev/null)" ]
}

newest_tag() {
	local tag
	tag="$(git describe --tags --abbrev=0 --match "$TAG_GLOB" 2>/dev/null)" || return 0
	is_release_tag "$tag" || return 0
	printf '%s' "$tag"
}

cmd_current() {
	local tag=''
	if in_explorer_git_repo; then
		tag="$(newest_tag)"
	fi
	if [ -z "$tag" ]; then
		echo "$DEV_SENTINEL"
		return 0
	fi
	echo "${tag#v}"
}

cmd_released_at() {
	local rev="${1:-HEAD}" tag
	in_explorer_git_repo || return 0
	tag="$(git describe --tags --exact-match --match "$TAG_GLOB" "$rev" 2>/dev/null)" || return 0
	is_release_tag "$tag" || return 0
	printf '%s\n' "$tag"
}

cmd_describe() {
	if ! in_explorer_git_repo; then
		echo "$DEV_SENTINEL"
		return 0
	fi

	local -a meta=()
	local version

	local described
	if described="$(git describe --tags --long --abbrev=12 --match "$TAG_GLOB" 2>/dev/null)"; then
		local sha without_sha distance
		sha="${described##*-g}"
		without_sha="${described%-g*}"
		distance="${without_sha##*-}"
		version="${without_sha%-*}"
		if is_release_tag "$version"; then
			version="${version#v}"
			if [ "$distance" != "0" ]; then
				meta+=("$distance" "g${sha}")
			fi
		else
			version="$DEV_SENTINEL"
			meta=("g$(short_sha)")
		fi
	else
		version="$DEV_SENTINEL"
		meta+=("g$(short_sha)")
	fi

	if tree_is_dirty; then
		meta+=('dirty')
	fi

	if [ "${#meta[@]}" -eq 0 ]; then
		echo "$version"
		return 0
	fi
	local joined
	joined="$(
		IFS='.'
		echo "${meta[*]}"
	)"
	echo "${version}+${joined}"
}

cmd_next() {
	local date="${1:-}"
	if [ -z "$date" ]; then
		date="$(date -u +%Y.%m.%d)"
	fi
	case "$date" in
	[0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9]) ;;
	*) die "next: date must be YYYY.MM.DD (got '$date')" ;;
	esac

	local highest=0 tag ordinal
	while read -r tag; do
		[ -n "$tag" ] || continue
		ordinal="${tag##*.}"
		case "$ordinal" in
		'' | *[!0-9]*) continue ;;
		esac
		if [ "$ordinal" -gt "$highest" ]; then
			highest="$ordinal"
		fi
	done <<<"$(git tag --list "v${date}.[0-9]*" 2>/dev/null)"

	echo "v${date}.$((highest + 1))"
}

cmd_semver() {
	local version
	version="$(cmd_current)"
	if [ "$version" = "$DEV_SENTINEL" ]; then
		echo '0.0.0'
		return 0
	fi

	local year month day ordinal
	IFS='.' read -r year month day ordinal <<<"$version"
	printf '%d.%d.%d\n' "$((10#$year))" "$((10#$month * 100 + 10#$day))" "$((10#$ordinal))"
}

cmd_filter() {
	local name
	while IFS= read -r name; do
		if is_release_tag "$name"; then
			printf '%s\n' "$name"
		fi
	done | sort -t. -k1.2,1n -k2,2n -k3,3n -k4,4n
}

main() {
	local cmd="${1:-describe}"
	shift || true
	case "$cmd" in
	current) cmd_current "$@" ;;
	describe) cmd_describe "$@" ;;
	next) cmd_next "$@" ;;
	semver) cmd_semver "$@" ;;
	released-at) cmd_released_at "$@" ;;
	filter) cmd_filter "$@" ;;
	-h | --help | help)
		sed -n '6,45p' "$0" | sed 's/^# \{0,1\}//'
		;;
	*) die "unknown subcommand '$cmd' (want: current | describe | next | semver | released-at | filter)" ;;
	esac
}

main "$@"
