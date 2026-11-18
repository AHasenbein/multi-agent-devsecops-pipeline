#!/bin/bash
# Puts the Control API on the team host into a test mode for one system test, and back.
# Run as root inside the distro (it writes a systemd drop-in and restarts the service):
#
#   wsl -d devsecops -u root -- bash <checkout>/scripts/host_test_mode.sh review-120s
#   wsl -d devsecops -u root -- bash <checkout>/scripts/host_test_mode.sh claude-off
#   wsl -d devsecops -u root -- bash <checkout>/scripts/host_test_mode.sh off
#
#   review-120s  TS-06-01: a copy of the pinned policy.yaml with review_timeout_s: 120,
#                passed through DEVSECOPS_POLICY_PATH. Nothing else in the policy changes.
#   claude-off   QA-AV-01: CLAUDE_BASE_URL points at a closed local port, so every call to
#                Claude fails and the template reason is used.
#   off          removes the drop-in: the pinned policy and the real Claude URL again.
#
# It refuses while a run is in progress, because a restart closes that run as ERROR
# (CLAUDE.md §11 item 12). Runs paused for review carry on. The .env is never edited.
set -euo pipefail

MODE="${1:-}"
SERVICE="devsecops-control-api"
CHECKOUT="${CHECKOUT:-/home/devsecops/multi-agent-devsecops-pipeline}"
STATE_DIR="/home/devsecops/.devsecops"
DROPIN_DIR="/etc/systemd/system/${SERVICE}.service.d"
DROPIN="${DROPIN_DIR}/test-mode.conf"
TEST_POLICY="${STATE_DIR}/policy-review-120s.yaml"

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
case "${MODE}" in review-120s | claude-off | off) ;; *) echo "usage: $0 review-120s|claude-off|off" >&2; exit 2 ;; esac
for name in DEVSECOPS_POLICY_PATH CLAUDE_BASE_URL; do
    if grep -qE "^${name}=" "${CHECKOUT}/.env"; then
        echo "${name} is set in .env, which would override the drop-in; remove it there first" >&2
        exit 1
    fi
done

api() {
    local token
    token=$(grep -E '^CONTROL_API_TOKEN=' "${CHECKOUT}/.env" | cut -d= -f2-)
    curl -sf -m 10 -H "Authorization: Bearer ${token}" "http://127.0.0.1:8000$1"
}

busy=$(api /runs | python3 -c '
import json, sys
final = {"DENIED", "DEPLOYED", "ROLLED_BACK", "ROLLBACK_FAILED", "ERROR", "ALLOWED", "AWAITING_REVIEW"}
print(" ".join(r["run_id"][:8] + ":" + r["status"] for r in json.load(sys.stdin) if r["status"] not in final))')
if [ -n "${busy}" ]; then
    echo "a run is in progress, not restarting: ${busy}" >&2
    exit 3
fi

mkdir -p "${DROPIN_DIR}"
case "${MODE}" in
review-120s)
    sed -E 's/^(  review_timeout_s:) *[0-9]+/\1 120/' "${CHECKOUT}/policy.yaml" > "${TEST_POLICY}"
    grep -qE '^  review_timeout_s: 120( |$)' "${TEST_POLICY}" || { echo "could not set the timeout" >&2; exit 1; }
    chown devsecops:devsecops "${TEST_POLICY}"
    chmod 600 "${TEST_POLICY}"
    printf '[Service]\n# TS-06-01 test mode. Remove with: host_test_mode.sh off\nEnvironment=DEVSECOPS_POLICY_PATH=%s\n' \
        "${TEST_POLICY}" > "${DROPIN}"
    ;;
claude-off)
    printf '[Service]\n# QA-AV-01 test mode. Remove with: host_test_mode.sh off\nEnvironment=CLAUDE_BASE_URL=http://127.0.0.1:9\n' \
        > "${DROPIN}"
    ;;
off)
    rm -f "${DROPIN}" "${TEST_POLICY}"
    ;;
esac

systemctl daemon-reload
systemctl restart "${SERVICE}"
code=000
for _ in $(seq 1 60); do
    code=$(curl -s -m 2 -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/health || true)
    [ "${code}" = "200" ] && break
    sleep 1
done
[ "${code}" = "200" ] || { echo "Control API did not come back (GET /health: ${code})" >&2; exit 1; }
echo "mode: ${MODE}"
echo "drop-in: $(cat "${DROPIN}" 2>/dev/null | grep -E '^Environment' || echo none)"
api /policies | python3 -c 'import json, sys; print("review_timeout_s:", json.load(sys.stdin)["timers"]["review_timeout_s"])'
echo TEST_MODE_OK
