#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Run the LiteP2P stress suite on one or more remote Linux hosts over SSH, and pull artifacts locally.
#
# Usage:
#   tools/harness/run_remote_suite.sh hosts.txt
#
# hosts.txt format (one per line):
#   user@1.2.3.4
#   ubuntu@my-hostname
#   # comments allowed
#
# Requirements (local): ssh, scp (rsync optional)
# Requirements (remote): git, bash, python3, build deps if SKIP_BUILD!=1

HOSTS_FILE="${1:-}"
if [[ -z "${HOSTS_FILE}" || ! -f "${HOSTS_FILE}" ]]; then
  echo "usage: $0 <hosts_file>" >&2
  exit 2
fi

DRY_RUN="${DRY_RUN:-0}"            # 1 => print ssh/scp actions only
# SSH options as an array to avoid word-splitting issues
SSH_OPTS_ARR=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=30)
REMOTE_REPO_DIR="${REMOTE_REPO_DIR:-~/Litep2p}"
REMOTE_BRANCH="${REMOTE_BRANCH:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)}"
REMOTE_OUT_BASE="${REMOTE_OUT_BASE:-/tmp}"
LOCAL_ARTIFACTS_DIR="${LOCAL_ARTIFACTS_DIR:-./remote_artifacts}"

# Stress suite env (override as needed)
QUICK="${QUICK:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
CHAOS_ENABLED="${CHAOS_ENABLED:-1}"
CHAOS_MODE="${CHAOS_MODE:-tc,iptables}"
ALLOW_CHAOS_FAILURES="${ALLOW_CHAOS_FAILURES:-1}"
TC_SAFE_MODE="${TC_SAFE_MODE:-1}"
RESOURCE_CHAOS_ENABLED="${RESOURCE_CHAOS_ENABLED:-0}"
RESOURCE_CHAOS_PROFILE="${RESOURCE_CHAOS_PROFILE:-cpu,vm,io}"
RESOURCE_CHAOS_DURATION_SEC="${RESOURCE_CHAOS_DURATION_SEC:-30}"
LOSS_PROB="${LOSS_PROB:-0.10}"
LOSS_DURATION_SEC="${LOSS_DURATION_SEC:-30}"
RECONNECT_CYCLES="${RECONNECT_CYCLES:-8}"

have_cmd() { command -v "$1" >/dev/null 2>&1; }

if ! have_cmd ssh || ! have_cmd scp; then
  echo "ERROR: ssh and scp are required locally" >&2
  exit 2
fi

mkdir -p "${LOCAL_ARTIFACTS_DIR}"

run_ssh() {
  local host="$1"; shift
  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "[dry-run] ssh ${SSH_OPTS_ARR[*]} ${host} $*"
    return 0
  fi
  ssh "${SSH_OPTS_ARR[@]}" "${host}" "$@"
}

run_scp() {
  local src="$1"
  local dst="$2"
  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "[dry-run] scp ${SSH_OPTS_ARR[*]} ${src} ${dst}"
    return 0
  fi
  scp "${SSH_OPTS_ARR[@]}" "${src}" "${dst}"
}

ts="$(date +%Y%m%d_%H%M%S)"

while IFS= read -r line; do
  line="${line%%#*}"
  line="$(echo "${line}" | xargs)" || true
  [[ -z "${line}" ]] && continue

  host="${line}"
  safe_host="${host//[^a-zA-Z0-9_.-]/_}"
  local_host_dir="${LOCAL_ARTIFACTS_DIR}/${safe_host}/${ts}"
  mkdir -p "${local_host_dir}"

  remote_out="${REMOTE_OUT_BASE}/litep2p_stress_${safe_host}_${ts}"
  remote_out_base="$(basename "${remote_out}")"

  echo "[remote] ${host}: updating repo (requested=${REMOTE_REPO_DIR}, branch=${REMOTE_BRANCH})"
  run_ssh "${host}" "set -euo pipefail; \
    repo_dir=\"${REMOTE_REPO_DIR}\"; \
    if [[ \"\$repo_dir\" == ~/* ]]; then repo_dir=\"\$HOME/\${repo_dir:2}\"; fi; \
    if [[ -d \"\$repo_dir\" && ! -d \"\$repo_dir\"/.git ]]; then \
      repo_dir=\"\$HOME/Litep2p_git\"; \
      echo \"WARN: ${REMOTE_REPO_DIR} exists but is not a git repo; using \$repo_dir\" >&2; \
    fi; \
    if [[ ! -d \"\$repo_dir\"/.git ]]; then \
      echo \"Cloning repo into \$repo_dir (branch=${REMOTE_BRANCH})\"; \
      git clone --depth 1 --branch \"${REMOTE_BRANCH}\" https://github.com/shivaaa1123-ops/Litep2p.git \"\$repo_dir\"; \
    fi; \
    cd \"\$repo_dir\"; \
    git fetch --depth 1 origin \"${REMOTE_BRANCH}\" || git fetch --all; \
    git checkout \"${REMOTE_BRANCH}\" || git checkout -b \"${REMOTE_BRANCH}\" origin/\"${REMOTE_BRANCH}\"; \
    git pull --ff-only || true;"

  echo "[remote] ${host}: running stress suite (OUT_DIR=${remote_out})"
  run_ssh "${host}" "set -euo pipefail; \
    repo_dir=\"${REMOTE_REPO_DIR}\"; \
    if [[ \"\$repo_dir\" == ~/* ]]; then repo_dir=\"\$HOME/\${repo_dir:2}\"; fi; \
    if [[ -d \"\$repo_dir\" && ! -d \"\$repo_dir\"/.git ]]; then \
      repo_dir=\"\$HOME/Litep2p_git\"; \
    fi; \
    cd \"\$repo_dir\"; \
    OUT_DIR=\"${remote_out}\" \
    QUICK=\"${QUICK}\" \
    SKIP_BUILD=\"${SKIP_BUILD}\" \
    CHAOS_ENABLED=\"${CHAOS_ENABLED}\" \
    CHAOS_MODE=\"${CHAOS_MODE}\" \
    ALLOW_CHAOS_FAILURES=\"${ALLOW_CHAOS_FAILURES}\" \
    TC_SAFE_MODE=\"${TC_SAFE_MODE}\" \
    RESOURCE_CHAOS_ENABLED=\"${RESOURCE_CHAOS_ENABLED}\" \
    RESOURCE_CHAOS_PROFILE=\"${RESOURCE_CHAOS_PROFILE}\" \
    RESOURCE_CHAOS_DURATION_SEC=\"${RESOURCE_CHAOS_DURATION_SEC}\" \
    LOSS_PROB=\"${LOSS_PROB}\" \
    LOSS_DURATION_SEC=\"${LOSS_DURATION_SEC}\" \
    RECONNECT_CYCLES=\"${RECONNECT_CYCLES}\" \
    bash tools/harness/stress_suite.sh; \
    echo \"REMOTE_OUT_DIR=${remote_out}\""

  echo "[remote] ${host}: packing artifacts"
  run_ssh "${host}" "set -euo pipefail; \
    tar -C \"${REMOTE_OUT_BASE}\" -czf \"${remote_out}.tgz\" \"${remote_out_base}\"; \
    ls -lh \"${remote_out}.tgz\""

  echo "[local] pulling ${host} artifacts -> ${local_host_dir}"
  run_scp "${host}:${remote_out}.tgz" "${local_host_dir}/"

  if [[ "${DRY_RUN}" != "1" ]]; then
    tar -C "${local_host_dir}" -xzf "${local_host_dir}/$(basename "${remote_out}").tgz" || true
  fi

done < "${HOSTS_FILE}"

echo "[local] done. Artifacts under: ${LOCAL_ARTIFACTS_DIR} (timestamp=${ts})"