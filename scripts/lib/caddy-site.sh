#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# Sourceable Caddy site planning helpers. The primary Caddyfile's import paths
# are relative to that file, not to bootstrap's working directory.
# Compatibility identifier for already-installed site blocks. Do not change:
# bootstrap must recognize and clean up copies written by older releases.
EXPLORER_CADDY_MARKER='# Caddy site block for Explorer, imported by /etc/caddy/Caddyfile via'

explorer_caddy_is_ours() {
  local path=$1 first
  [[ -f $path && ! -L $path ]] || return 1
  IFS= read -r first < "$path" || true
  [[ $first == "$EXPLORER_CADDY_MARKER" ]]
}

explorer_caddy_imports() {
  local file=$1 line rest pattern tail quote
  [[ -f $file ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line =~ ^[[:space:]]*import[[:space:]]+(.+)$ ]] || continue
    rest=${BASH_REMATCH[1]}
    if [[ ${rest:0:1} == '"' || ${rest:0:1} == "'" ]]; then
      quote=${rest:0:1}
      rest=${rest:1}
      [[ $rest == *"$quote"* ]] || continue
      pattern=${rest%%"$quote"*}
      tail=${rest#*"$quote"}
      [[ $tail =~ ^[[:space:]]*(#.*)?$ ]] || continue
    else
      pattern=${rest%%[[:space:]]*}
    fi
    [[ -n $pattern ]] && printf '%s\n' "$pattern"
  done < "$file"
}

explorer_caddy_candidate() {
  local file=$1 pattern=$2 directory glob name
  directory=$(dirname -- "$pattern")
  glob=$(basename -- "$pattern")
  # We only synthesize names for globs in concrete directories. Unsupported
  # import forms get a separate, explicit import rather than a guessed path.
  case $directory in *'*'*|*'?'*|*'['*) return 1 ;; esac
  case $glob in *'*'*|*'?'*|*'['*) ;; *) return 1 ;; esac
  if [[ $directory != /* ]]; then
    directory=$(dirname -- "$file")/$directory
  fi
  directory=$(realpath -m -- "$directory") || return 1
  name=${glob//\*/explorer}
  name=${name//\?/x}
  # A broad '*' can load the conventional .caddy name; a suffix glob such
  # as '*.caddyfile' naturally yields explorer.caddyfile instead.
  [[ $glob == '*' ]] && name=explorer.caddy
  # This is intentionally a shell glob match, not string equality.
  # shellcheck disable=SC2053
  [[ $name == $glob ]] || return 1
  printf '%s/%s\n' "$directory" "$name"
}

explorer_caddy_plan() {
  local file=$1 host=$2 pattern candidate
  EXPLORER_CADDY_TARGET=''
  EXPLORER_CADDY_ADD_IMPORT=0
  EXPLORER_CADDY_CANDIDATES=()
  while IFS= read -r pattern; do
    candidate=$(explorer_caddy_candidate "$file" "$pattern") || continue
    EXPLORER_CADDY_CANDIDATES+=("$candidate")
  done < <(explorer_caddy_imports "$file")
  # Keep the already-loaded hand-installed block in preference to creating a
  # second one. An occupied, unmarked candidate is never overwritten.
  for candidate in "${EXPLORER_CADDY_CANDIDATES[@]}"; do
    if explorer_caddy_is_ours "$candidate" "$host"; then
      EXPLORER_CADDY_TARGET=$candidate
      return 0
    fi
  done
  for candidate in "${EXPLORER_CADDY_CANDIDATES[@]}"; do
    if [[ ! -e $candidate && ! -L $candidate ]]; then
      EXPLORER_CADDY_TARGET=$candidate
      return 0
    fi
  done
  EXPLORER_CADDY_TARGET=$(realpath -m -- "$(dirname -- "$file")/conf.d/explorer.caddy") || return 1
  # Read by the sourcing installer (and fixture tests).
  # shellcheck disable=SC2034
  EXPLORER_CADDY_ADD_IMPORT=1
  [[ ! -e $EXPLORER_CADDY_TARGET && ! -L $EXPLORER_CADDY_TARGET ]] ||
    explorer_caddy_is_ours "$EXPLORER_CADDY_TARGET" "$host"
}

explorer_caddy_remove_stale() {
  local file=$1 host=$2 target=$3 candidate dir path
  local -A directories=()
  for candidate in "${EXPLORER_CADDY_CANDIDATES[@]}" \
    "$(dirname -- "$file")/conf.d/explorer.caddy" \
    "$(dirname -- "$file")/Caddyfile.d/explorer.caddyfile"; do
    dir=$(dirname -- "$candidate")
    [[ -d $dir && ! -L $dir ]] && directories["$dir"]=1
  done
  for dir in "${!directories[@]}"; do
    while IFS= read -r -d '' path; do
      [[ $path == "$target" ]] && continue
      if explorer_caddy_is_ours "$path" "$host"; then
        rm -- "$path" || return 1
        printf '%s\n' "$path"
      fi
    done < <(find "$dir" -maxdepth 1 -type f -print0)
  done
}

explorer_caddy_adapted_has_site() {
  local json=$1 host=$2 upstream=$3
  jq -e --arg host "$host" --arg upstream "$upstream" '
    any(.apps.http.servers[]?.routes[]?;
      any(.match[]?.host[]?; . == $host) and
      ([.. | objects | select(.handler? == "reverse_proxy") |
        .upstreams[]?.dial] | index($upstream) != null))
  ' "$json" >/dev/null
}
