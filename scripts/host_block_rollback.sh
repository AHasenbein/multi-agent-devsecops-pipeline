#!/bin/bash
# TS-08-01 step 3: block the rollback. Waits until the sandbox runs the image built from
# <commit_sha>, then removes the kept old version, so the coming rollback has nothing to
# go back to and must report ROLLBACK_FAILED (FR18).
# Run on the host as the devsecops user. scripts/run_ts_08_01.py starts it over SSH:
#   --block-cmd 'ssh <host> ... bash <checkout>/scripts/host_block_rollback.sh {sha}'
# Afterwards the sandbox holds a broken app and no rollback target: deploy a good change.
set -euo pipefail
[[ "${1:-}" =~ ^[0-9a-f]{40}$ ]] || { echo "usage: $0 <40-hex commit_sha>" >&2; exit 2; }
IMAGE="${DEVSECOPS_APP_IMAGE:-sample_app}:${1:0:12}"
NAME="${SANDBOX_NAME:-sandbox-app}"
for _ in $(seq 1 900); do  # up to 15 minutes: the build, tests and scans come first
    if [ "$(docker inspect -f '{{.Config.Image}}' "${NAME}" 2>/dev/null || true)" = "${IMAGE}" ]; then
        docker rm -f "${NAME}-previous" >/dev/null
        echo "BLOCKED: ${NAME}-previous removed while ${IMAGE} is live"
        exit 0
    fi
    sleep 1
done
echo "timed out waiting for ${IMAGE} in ${NAME}" >&2
exit 1
