#!/bin/bash
# Prints GET /runs/<run_id> (the RunView JSON) from the Control API on the team host.
# Run on the host as the devsecops user. scripts/run_ts_08_01.py calls it over SSH:
#   --view-cmd 'ssh <host> ... bash <checkout>/scripts/host_run_view.sh {run_id}'
# The token is read from the checkout's .env and never printed.
set -euo pipefail
[[ "${1:-}" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]] || { echo "usage: $0 <run_id>" >&2; exit 2; }
CHECKOUT="${CHECKOUT:-/home/devsecops/multi-agent-devsecops-pipeline}"
TOKEN=$(grep -E '^CONTROL_API_TOKEN=' "${CHECKOUT}/.env" | cut -d= -f2-)
curl -sf -m 10 -H "Authorization: Bearer ${TOKEN}" "http://127.0.0.1:8000/runs/$1"
