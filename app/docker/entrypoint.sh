#!/usr/bin/env sh
set -eu

: "${VITE_API_BASE_URL:?VITE_API_BASE_URL must be set}"
export VITE_API_BASE_URL="${VITE_API_BASE_URL%/}"

envsubst '${VITE_API_BASE_URL}' \
  < /etc/nginx/conf.d/default.conf.template \
  > /etc/nginx/conf.d/default.conf

printf 'window.__ENV__ = {\n  VITE_API_BASE_URL: "%s"\n};\n' "$VITE_API_BASE_URL" \
  > /usr/share/nginx/html/env.js

exec "$@"
