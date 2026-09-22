#!/usr/bin/env bash

# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

# Ownership and trust boundary for an installed Explorer tree. Root owns all
# source and executable content; the service account owns only its venv,
# configuration, attachment scratch space and database directory. Root never
# executes or installs a file from a service-writable path.

: "${APP_DIR:?layout.sh needs APP_DIR}"
: "${APP_USER:?layout.sh needs APP_USER}"
BUILD_CACHE="${BUILD_CACHE:-/var/cache/explorer-build}"
UV_BIN="${EXPLORER_UV_BIN:-uv}"

LAYOUT_SYNC_EXCLUDES=(
  --exclude='/.git'
  --exclude='/.venv'
  --exclude='/.venv.old'
  --exclude='/.tmp'
  --exclude='/.env'
  --exclude='/.env.shared'
)

layout_die() { printf 'layout: %s\n' "$*" >&2; return 1; }

layout_require_real() {
  local path
  for path in "$@"; do
    [[ ! -L $path ]] || { layout_die "$path is a symlink; a real path is required"; return 1; }
  done
}

layout_require_trusted_path() {
  local path owner mode
  path=$(readlink -f -- "$1") || { layout_die "$1 does not resolve"; return 1; }
  while :; do
    owner=$(stat -c %U "$path") || return 1
    mode=$(stat -c %a "$path") || return 1
    [[ $owner == root ]] || { layout_die "$path is owned by $owner; root must own it and every ancestor"; return 1; }
    (( (8#$mode & 8#022) == 0 )) || { layout_die "$path is writable by group or others"; return 1; }
    [[ $path == / ]] && break
    path=$(dirname -- "$path")
  done
}

layout_require_trusted() {
  local dir=$1 stray
  layout_require_trusted_path "$dir" || return 1
  stray=$(find "$(readlink -f -- "$dir")" \
    \( ! -user root -o -perm -g+w -o -perm -o+w -o -type l \) \
    -print -quit 2>/dev/null)
  [[ -z $stray ]] || {
    layout_die "$stray is not exclusively root-controlled; fix ownership/mode and remove symlinks"
    return 1
  }
}

layout_build_cache() {
  layout_require_real "$BUILD_CACHE" || return 1
  layout_require_trusted_path "$(dirname -- "$BUILD_CACHE")" || return 1
  install -d -o "$APP_USER" -g "$APP_USER" -m 0700 "$BUILD_CACHE"
}

layout_build() {
  local src=$1 staging=$2 uv_bin
  layout_require_trusted "$src" || return 1
  layout_require_real "$staging" || return 1
  uv_bin=$(command -v -- "$UV_BIN") || { layout_die "uv executable not found: $UV_BIN"; return 1; }
  [[ -f $uv_bin && ! -L $uv_bin ]] || { layout_die "$uv_bin is not a real file"; return 1; }
  layout_require_trusted_path "$uv_bin" || return 1
  install -d -o root -g root -m 0755 "$staging" || return 1
  rsync -a --delete "${LAYOUT_SYNC_EXCLUDES[@]}" "$src/" "$staging/" || return 1
  install -d -o "$APP_USER" -g "$APP_USER" -m 0755 "$staging/.venv" || return 1
  layout_build_cache || return 1
  runuser -u "$APP_USER" -- env -i -C "$staging" \
    PATH=/usr/local/bin:/usr/bin:/bin \
    HOME="$BUILD_CACHE" UV_CACHE_DIR="$BUILD_CACHE/uv" UV_NO_CONFIG=1 \
    "$uv_bin" venv "$staging/.venv" >/dev/null || return 1
  runuser -u "$APP_USER" -- env -i -C "$staging" \
    PATH=/usr/local/bin:/usr/bin:/bin \
    HOME="$BUILD_CACHE" UV_CACHE_DIR="$BUILD_CACHE/uv" UV_NO_CONFIG=1 \
    "$uv_bin" pip install --python "$staging/.venv/bin/python" \
      --reinstall -r "$staging/requirements.txt" || return 1
  [[ -d $staging/.venv && ! -L $staging/.venv ]] || {
    layout_die "$staging/.venv is not a real directory"
    return 1
  }
}

layout_install_source() {
  local src=$1
  layout_require_trusted "$src" || return 1
  layout_require_real "$APP_DIR" || return 1
  layout_require_trusted_path "$(dirname -- "$(readlink -m -- "$APP_DIR")")" || return 1
  install -d -o root -g root -m 0755 "$APP_DIR" || return 1
  # Do not trust rsync's size+mtime quick check when replacing a legacy tree:
  # a compromised service can preserve both while changing file contents.
  rsync -a --delete --checksum --no-owner --no-group --chown=root:root --chmod=go-w \
    "${LAYOUT_SYNC_EXCLUDES[@]}" "$src/" "$APP_DIR/"
}

layout_write_revision() {
  local revision=$1 marker="$APP_DIR/.explorer-revision"
  [[ $revision =~ ^[0-9a-f]{40,64}$ ]] || { layout_die "invalid source revision: $revision"; return 1; }
  [[ ! -e $marker && ! -L $marker ]] || rm -f -- "$marker" || return 1
  printf '%s\n' "$revision" > "$marker" || return 1
  chown root:root "$marker" || return 1
  chmod 0644 "$marker" || return 1
}

layout_revision_matches() {
  local expected=$1 marker="$APP_DIR/.explorer-revision" actual
  [[ -f $marker && ! -L $marker && $(stat -c '%U:%G %a %h' "$marker") == 'root:root 644 1' ]] || return 1
  IFS= read -r actual < "$marker" || return 1
  [[ $actual == "$expected" ]]
}

layout_secure_runtime() {
  local file
  layout_require_real "$APP_DIR" "$APP_DIR/.venv" "$APP_DIR/.tmp" || return 1
  install -d -o root -g root -m 0755 "$APP_DIR" || return 1
  install -d -o "$APP_USER" -g "$APP_USER" -m 0750 \
    "$APP_DIR/.tmp" "$APP_DIR/.tmp/email_attachments" || return 1
  for file in "$APP_DIR/.env" "$APP_DIR/.env.shared"; do
    [[ -e $file || -L $file ]] || continue
    [[ -f $file && ! -L $file && $(stat -c %h "$file") -eq 1 ]] || {
      layout_die "$file must be a single-link regular file"
      return 1
    }
    chown "$APP_USER:$APP_USER" "$file" || return 1
    chmod 0600 "$file" || return 1
  done
  layout_build_cache || return 1
}

layout_check() {
  local stray file
  [[ -d $APP_DIR && ! -L $APP_DIR ]] || { layout_die "$APP_DIR is not a real directory"; return 1; }
  [[ $(stat -c '%U:%G %a' "$APP_DIR") == 'root:root 755' ]] || {
    layout_die "$APP_DIR must be root:root 0755"
    return 1
  }
  stray=$(find "$APP_DIR" \
    \( -path "$APP_DIR/.venv" -o -path "$APP_DIR/.tmp" -o -path "$APP_DIR/.env" -o -path "$APP_DIR/.env.shared" \) -prune -o \
    \( ! -user root -o -perm -g+w -o -perm -o+w -o -type l \) -print -quit)
  [[ -z $stray ]] || { layout_die "$stray violates the root-owned application layout"; return 1; }
  [[ -d $APP_DIR/.venv && ! -L $APP_DIR/.venv ]] || { layout_die "$APP_DIR/.venv is not a real directory"; return 1; }
  [[ $(stat -c %U "$APP_DIR/.venv") == "$APP_USER" ]] || {
    layout_die "$APP_DIR/.venv is not owned by $APP_USER"
    return 1
  }
  [[ -d $APP_DIR/.tmp && ! -L $APP_DIR/.tmp && $(stat -c %U "$APP_DIR/.tmp") == "$APP_USER" ]] || {
    layout_die "$APP_DIR/.tmp is not owned by $APP_USER"
    return 1
  }
  for file in "$APP_DIR/.env" "$APP_DIR/.env.shared"; do
    [[ -e $file || -L $file ]] || continue
    [[ -f $file && ! -L $file && $(stat -c '%U:%G %a %h' "$file") == "$APP_USER:$APP_USER 600 1" ]] || {
      layout_die "$file must be $APP_USER:$APP_USER 0600 with one link"
      return 1
    }
  done
  layout_require_trusted "$SRC_DIR" || return 1
}

env_unquote() {
  local value=$1 out='' i char next bs=$'\\'
  value=${value#"${value%%[![:space:]]*}"}
  value=${value%"${value##*[![:space:]]}"}
  case $value in
    \"*)
      i=1
      while (( i < ${#value} )); do
        char=${value:i:1}
        if [[ $char == "$bs" ]]; then
          next=${value:i+1:1}
          if [[ $next == '"' || $next == "$bs" ]]; then out+=$next; (( i += 2 )); continue; fi
        fi
        [[ $char == '"' ]] && break
        out+=$char
        (( i++ ))
      done
      printf '%s' "$out"
      ;;
    \'*) value=${value:1}; printf '%s' "${value%%\'*}" ;;
    *) value=${value%%#*}; printf '%s' "${value%"${value##*[![:space:]]}"}" ;;
  esac
}

layout_read_env() {
  local file=$1 line key value
  [[ -f $file && ! -L $file ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line#"${line%%[![:space:]]*}"}
    [[ $line =~ ^([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]] || continue
    key=${BASH_REMATCH[1]}; value=${BASH_REMATCH[2]}
    case $key in
      EXPLORER_SESSION_SECRET|EXPLORER_AUTH_MODE|EXPLORER_ACCESS_DB|EXPLORER_AUTH_COOKIE_SECURE|EXPLORER_SESSION_IDLE_SECONDS|EXPLORER_SESSION_ABSOLUTE_SECONDS|EXPLORER_PUBLIC_URL|AUTH_SIGNING_PUBKEY|AUTH_SIGNING_PREVIOUS_PUBKEYS|AUTH_LOGIN_URL|AUTH_COOKIE_NAME|AUTH_ISSUER_URL|AUTH_CLIENT_ID|AUTH_CLIENT_SECRET|AUTH_HTTP_TIMEOUT_SECONDS|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AWS_REGION|EMAIL_S3_BUCKET|EMAIL_S3_PREFIX|EMAIL_S3_DATE_PREFIX_FORMAT|EMAIL_S3_MAX_DATE_PREFIX_DAYS|EMAIL_S3_MAX_BODY_SEARCH_DAYS|EMAIL_HEADER_FETCH_BYTES|EMAIL_SEARCH_JOB_MAX_SECONDS)
        printf -v "$key" '%s' "$(env_unquote "$value")"
        ;;
    esac
  done < "$file"
}
