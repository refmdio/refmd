#!/usr/bin/env sh
set -eu

# Generate /env.js for runtime configuration
cat > /usr/share/nginx/html/env.js <<EOF
window.__ENV__ = {
  VITE_API_BASE_URL: "${VITE_API_BASE_URL:-}"
};
EOF

exec "$@"

