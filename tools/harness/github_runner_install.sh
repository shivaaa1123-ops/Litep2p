#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Install and register a GitHub self-hosted runner as a systemd service.
#
# Usage (on VPS):
#   sudo bash tools/harness/github_runner_install.sh <repo_url> <label>
#
# Examples:
#   sudo bash tools/harness/github_runner_install.sh https://github.com/you/Litep2p litep2p-sg
#   sudo bash tools/harness/github_runner_install.sh https://github.com/you/Litep2p litep2p-us
#
# You will be prompted for the GitHub runner registration token (or provide RUNNER_TOKEN env var).
#
# Requirements:
# - Ubuntu/Debian with systemd

REPO_URL="${1:-}"
LABEL="${2:-}"
RUNNER_TOKEN="${RUNNER_TOKEN:-}"

if [[ -z "${REPO_URL}" || -z "${LABEL}" ]]; then
  echo "usage: sudo bash $0 <repo_url> <label>" >&2
  exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo bash $0 ..." >&2
  exit 1
fi

echo "==> Installing dependencies"
apt-get update
apt-get install -y --no-install-recommends curl ca-certificates tar git build-essential cmake ninja-build pkg-config \
  python3 python3-venv \
  libsodium-dev uuid-dev \
  libssl-dev

RUNNER_DIR="/opt/actions-runner"
mkdir -p "${RUNNER_DIR}"
cd "${RUNNER_DIR}"

if [[ ! -f ./config.sh ]]; then
  echo "==> Downloading GitHub runner"
  # Keep this reasonably up-to-date; you can bump versions later.
  RUNNER_VER="2.317.0"
  ARCH="x64"
  curl -fsSL -o actions-runner.tar.gz "https://github.com/actions/runner/releases/download/v${RUNNER_VER}/actions-runner-linux-${ARCH}-${RUNNER_VER}.tar.gz"
  tar xzf actions-runner.tar.gz
  rm -f actions-runner.tar.gz
fi

if [[ -z "${RUNNER_TOKEN}" ]]; then
  echo
  echo "Paste the GitHub runner registration token for ${REPO_URL} (Settings -> Actions -> Runners -> New self-hosted runner):"
  read -r RUNNER_TOKEN
fi

echo "==> Configuring runner (label=${LABEL})"
./config.sh remove --unattended --token "${RUNNER_TOKEN}" >/dev/null 2>&1 || true
./config.sh --unattended \
  --url "${REPO_URL}" \
  --token "${RUNNER_TOKEN}" \
  --labels "${LABEL}" \
  --name "$(hostname)-${LABEL}" \
  --work "_work"

echo "==> Installing and starting systemd service"
./svc.sh install
./svc.sh start

echo "==> Preparing /etc/litep2p/config.json (runner-local, not committed)"
mkdir -p /etc/litep2p
if [[ ! -f /etc/litep2p/config.json ]]; then
  cat > /etc/litep2p/config.json <<'JSON'
{
  "signaling": { "enabled": true, "url": "ws://SIGNALING_HOST:8765", "reconnect_interval_ms": 5000 },
  "nat_traversal": {
    "enabled": true,
    "turn_enabled": true,
    "turn_config": { "server_ip": "TURN_SERVER_IP", "server_port": 3478, "username": "TURN_USERNAME", "password": "TURN_PASSWORD", "realm": "TURN_REALM" }
  }
}
JSON
  echo "Wrote placeholder /etc/litep2p/config.json - you must fill in real signaling/TURN settings."
fi

echo "==> Runner installed. Check status:"
echo "  systemctl status actions.runner.* --no-pager"


