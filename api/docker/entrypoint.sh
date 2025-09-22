#!/bin/sh
set -e

# Ensure uploads directory exists and is writable even when bind-mounted from host
ensure_writable_dir() {
  dir="$1"
  perms="$2"
  if [ ! -d "$dir" ]; then
    mkdir -p "$dir"
  fi

  if chown -R appuser:appuser "$dir" 2>/dev/null; then
    chmod -R "$perms" "$dir" 2>/dev/null || true
  else
    chmod -R "$perms" "$dir" 2>/dev/null || true
  fi
}

ensure_writable_dir /data/uploads 0777

# Ensure plugins directory exists and is readable by appuser
PLUGIN_DIR="${PLUGINS_DIR:-/app/plugins}"
ensure_writable_dir "$PLUGIN_DIR" 0755

exec gosu appuser:appuser "$@"
