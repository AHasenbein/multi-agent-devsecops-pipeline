#!/bin/bash
# Installs the self-hosted GitHub Actions runner on the team host and registers it to the
# PRIVATE app repo (CLAUDE.md §2). Never register it to the public pipeline repo: a
# stranger's pull request there would then run code on our machine.
#
# Run it twice on the host, inside the "devsecops" distro:
#
#   1. As the devsecops user, to download, verify and register the runner:
#        RUNNER_REPO=<owner>/<private-app-repo> RUNNER_TOKEN=<registration token> \
#            bash scripts/install_runner.sh
#      Get the token (valid for one hour) on a laptop with:
#        gh api -X POST repos/<owner>/<private-app-repo>/actions/runners/registration-token -q .token
#
#   2. As root, to install and start the systemd service that keeps it running:
#        wsl -d devsecops -u root -- bash /home/devsecops/multi-agent-devsecops-pipeline/scripts/install_runner.sh
#
# The runner lives in /home/devsecops/actions-runner and runs as the devsecops user. Its
# only job is to call the Control API on localhost (pipeline.yml), so it needs no secrets
# of its own beyond the ones GitHub passes to the job.
set -euo pipefail

RUNNER_VERSION="${RUNNER_VERSION:-2.338.2}"
RUNNER_SHA256="${RUNNER_SHA256:-baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40}"
RUNNER_USER="devsecops"
RUNNER_DIR="/home/${RUNNER_USER}/actions-runner"
RUNNER_NAME="${RUNNER_NAME:-team-host}"
RUNNER_LABELS="${RUNNER_LABELS:-devsecops-host}"

if [ "$(id -u)" -eq 0 ]; then
    # Step 2: the service. Needs root; config.sh (step 1) refuses to run as root.
    [ -f "${RUNNER_DIR}/.runner" ] || { echo "run step 1 as ${RUNNER_USER} first" >&2; exit 1; }
    cd "${RUNNER_DIR}"
    ./bin/installdependencies.sh >/dev/null
    [ -f .service ] || ./svc.sh install "${RUNNER_USER}" >/dev/null
    ./svc.sh start >/dev/null
    systemctl is-active "$(cat .service)"
    echo RUNNER_SERVICE_OK
    exit 0
fi

# Step 1: download, verify, register.
: "${RUNNER_REPO:?set RUNNER_REPO to owner/name of the private app repo}"
: "${RUNNER_TOKEN:?set RUNNER_TOKEN to a fresh registration token}"
[ "$(whoami)" = "${RUNNER_USER}" ] || { echo "run as ${RUNNER_USER}" >&2; exit 1; }
if [ -f "${RUNNER_DIR}/.runner" ]; then
    echo "already registered; remove it with ./config.sh remove before registering again" >&2
    exit 1
fi
mkdir -p "${RUNNER_DIR}"
cd "${RUNNER_DIR}"
tarball="actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
curl -fsSL -o "${tarball}" \
    "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${tarball}"
echo "${RUNNER_SHA256}  ${tarball}" | sha256sum -c - >/dev/null
tar xzf "${tarball}"
rm "${tarball}"
./config.sh --unattended \
    --url "https://github.com/${RUNNER_REPO}" \
    --token "${RUNNER_TOKEN}" \
    --name "${RUNNER_NAME}" \
    --labels "${RUNNER_LABELS}" \
    --work _work >/dev/null
echo RUNNER_REGISTERED
