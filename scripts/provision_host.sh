#!/bin/bash
# Provisions the team host: Docker Engine, git, uv and a non-root "devsecops" user.
#
# Run once as root on a fresh Ubuntu 24.04. The team host is an Ubuntu 24.04 WSL2 distro
# on the always-on server (CLAUDE.md §2), where this was run as:
#     wsl -d devsecops -u root -- bash provision_host.sh
# The /etc/wsl.conf lines turn on systemd (so Docker starts with the distro) and make
# "devsecops" the default user. On a plain Linux host that file is ignored.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq docker.io docker-buildx git curl ca-certificates python3 python3-venv >/dev/null
id devsecops >/dev/null 2>&1 || useradd -m -s /bin/bash devsecops
usermod -aG docker devsecops
printf '[boot]\nsystemd=true\n\n[user]\ndefault=devsecops\n' > /etc/wsl.conf
systemctl enable --now docker >/dev/null 2>&1
su - devsecops -c 'command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1'
echo "docker: $(docker version --format '{{.Server.Version}}')"
echo "buildx: $(docker buildx version | cut -d' ' -f2)"
echo "git: $(git --version)"
echo "python: $(python3 --version)"
echo "uv: $(su - devsecops -c '~/.local/bin/uv --version')"
docker run --rm hello-world | grep -m1 "Hello from Docker"
docker image rm hello-world >/dev/null
echo PROVISION_OK
