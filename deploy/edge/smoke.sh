#!/usr/bin/env bash
# Smoke through the edge: the same end-to-end script as the single-host kit, pointed at the PUBLIC (or loopback) edge URL.
# SMOKE_BASE_URL=https://<entry-host> deploy/edge/smoke.sh     (add SMOKE_INSECURE=1 for staging certs)
# Extra: loopback health of the edge->core link.
set -euo pipefail
cd "$(dirname "$0")"
curl -fsS http://127.0.0.1:18741/edge/healthz 2>/dev/null | grep -q '"core":true' && echo "PASS edge healthz (core reachable)" || echo "INFO edge healthz not available from here (run on the edge host)"
exec ../hub/smoke.sh
