#!/usr/bin/env bash
# Run ON THE EDGE host (or any host inside the tunnel allowlist) against the core directly.
# Needs M4A_EDGE_SECRET and CORE_URL=http://<core-wg-ip>:8741 in the environment. Prints no secret.
set -euo pipefail
: "${CORE_URL:?}"; : "${M4A_EDGE_SECRET:?}"
code=$(curl -s -o /dev/null -w '%{http_code}' "$CORE_URL/client/versions"); [ "$code" = 401 ] && echo "PASS core refuses requests without the secret"
curl -fsS -H "x-m4a-edge-secret: $M4A_EDGE_SECRET" "$CORE_URL/client/versions" | grep -q versions && echo "PASS core versions with secret"
