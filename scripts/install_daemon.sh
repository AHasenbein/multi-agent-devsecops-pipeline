#!/bin/bash
# Installs the Control API as a systemd service on the team host (CLAUDE.md §2), so that it
# starts with the "devsecops" distro and comes back after a crash or a restart.
#
# Run it as root inside the distro, from the host's pinned checkout:
#
#   wsl -d devsecops -u root -- bash /home/devsecops/multi-agent-devsecops-pipeline/scripts/install_daemon.sh
#
# The service runs as the devsecops user, from the pinned checkout, with the settings and
# secrets in that checkout's .env (mode 600). It listens on 127.0.0.1:8000 only. State
# stays in ~/.devsecops and the log is appended to ~/.devsecops/control-api.log.
#
# Before the first install, stop the old tmux session (as devsecops):
#   tmux kill-session -t control-api
# A run in progress at that moment is closed as ERROR when the service starts (CLAUDE.md
# §11 item 12); runs paused for review carry on. The script refuses to start while
# something else holds port 8000.
#
# Running it again rewrites the unit and restarts the service: do that after moving the pin.
set -euo pipefail

SERVICE="devsecops-control-api"
APP_USER="devsecops"
APP_HOME="/home/${APP_USER}"
CHECKOUT="${CHECKOUT:-${APP_HOME}/multi-agent-devsecops-pipeline}"
STATE_DIR="${APP_HOME}/.devsecops"
LOG="${STATE_DIR}/control-api.log"
UV="${APP_HOME}/.local/bin/uv"
PORT=8000
UNIT="/etc/systemd/system/${SERVICE}.service"

[ "$(id -u)" -eq 0 ] || { echo "run as root (wsl -d devsecops -u root -- ...)" >&2; exit 1; }
[ -x "${UV}" ] || { echo "uv not found at ${UV}" >&2; exit 1; }
[ -f "${CHECKOUT}/.env" ] || { echo "${CHECKOUT}/.env is missing" >&2; exit 1; }
[ "$(stat -c %a "${CHECKOUT}/.env")" = "600" ] || {
    echo "${CHECKOUT}/.env must be mode 600" >&2
    exit 1
}
for name in CONTROL_API_TOKEN DEVSECOPS_APP_REPO GITHUB_TOKEN; do
    grep -qE "^${name}=." "${CHECKOUT}/.env" || { echo "${name} is not set in .env" >&2; exit 1; }
done

if ! systemctl is-active --quiet "${SERVICE}" && ss -ltn | grep -q ":${PORT} "; then
    echo "port ${PORT} is in use by something else (the old tmux session?)." >&2
    echo "stop it first, as ${APP_USER}: tmux kill-session -t control-api" >&2
    exit 1
fi

install -d -m 700 -o "${APP_USER}" -g "${APP_USER}" "${STATE_DIR}"

cat > "${UNIT}" <<EOF
[Unit]
Description=DevSecOps pipeline Control API (127.0.0.1:${PORT})
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${CHECKOUT}
ExecStart=${UV} run --frozen --env-file ${CHECKOUT}/.env uvicorn devsecops.api.main:create_app_from_env --factory --host 127.0.0.1 --port ${PORT}
Restart=on-failure
RestartSec=5
# A run cut off by a stop is closed as ERROR at the next start; give uvicorn time to finish
# answering requests first.
TimeoutStopSec=20
UMask=0077
NoNewPrivileges=true
StandardOutput=append:${LOG}
StandardError=append:${LOG}

[Install]
WantedBy=multi-user.target
EOF
chmod 644 "${UNIT}"

systemctl daemon-reload
systemctl enable --quiet "${SERVICE}"
systemctl restart "${SERVICE}"

code=000
for _ in $(seq 1 60); do
    code=$(curl -s -m 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/health" || true)
    [ "${code}" = "200" ] && break
    sleep 1
done
echo "GET /health: ${code}"
echo "GET /runs without token: $(curl -s -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/runs")"
echo "listening: $(ss -ltn | awk -v p=":${PORT}" '$4 ~ p {print $4}')"
# As the checkout's owner: git refuses to read another user's repository as root.
echo "pin: $(runuser -u "${APP_USER}" -- git -C "${CHECKOUT}" log -1 --format='%h %s')"
systemctl is-active "${SERVICE}"
[ "${code}" = "200" ] || { echo "--- log tail"; tail -20 "${LOG}"; exit 1; }
echo DAEMON_SERVICE_OK
