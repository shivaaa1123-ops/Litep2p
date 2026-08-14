#!/usr/bin/env bash
set -euo pipefail

# Convenience wrapper: run a production-style connectivity stress matrix against the
# multi-thread Android build with multiple desktop peers.
#
# This calls tools/harness/android_wifi_handoff_repro.sh with a recommended scenario
# set and more conservative stabilization timings.
#
# Environment variables (override as needed):
# - LOOPS (default: 3)
# - DESKTOP_COUNT (default: 15)
# - SCENARIOS (default: wifi,data,no_network)
# - FORCE_TRANSPORT_BREAK (default: 1)
# - ENFORCE_SLA (default: 1)
# - SLA_SECONDS (default: 8; auto-bumped for large DESKTOP_COUNT unless explicitly set)
# - SLA_REQUIRE_READY (default: 0) also enforce READY <= SLA ("ready for messaging")
# - WATCHDOG_ENABLE (default: 1)
# - STABILIZE_SECS (default: 3)
# - WIFI_DISABLE_SECS / WIFI_ENABLE_SECS / DATA_DISABLE_SECS / DATA_ENABLE_SECS / AIRPLANE_* (optional)
#
# Note: To ensure the multi-thread engine is used, set ENGINE_COMMS_MODE appropriately
# (your app maps this to the comms mode spinner).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

LOOPS="${LOOPS:-3}"

# Default to 15 peers for scale testing.
if [[ -z "${DESKTOP_COUNT+x}" ]]; then
	DESKTOP_COUNT="15"
fi

SCENARIOS="${SCENARIOS:-wifi,data,no_network}"

# FORCE_TRANSPORT_BREAK briefly disables mobile data while Wi‑Fi is OFF to force a hard transport break.
# At higher peer counts this can be overly disruptive (it creates a true no-network window), so default
# it OFF unless explicitly requested.
if [[ -z "${FORCE_TRANSPORT_BREAK+x}" ]]; then
	if [[ "${DESKTOP_COUNT}" =~ ^[0-9]+$ ]] && (( DESKTOP_COUNT >= 10 )); then
		FORCE_TRANSPORT_BREAK="0"
	else
		FORCE_TRANSPORT_BREAK="1"
	fi
fi
ENFORCE_SLA="${ENFORCE_SLA:-1}"

# At larger peer counts, public-network (LTE) routing + NAT punching can take longer.
# If the caller did not explicitly set SLA_SECONDS, bump the default to reduce false failures.
if [[ -z "${SLA_SECONDS+x}" ]]; then
	if [[ "${DESKTOP_COUNT}" =~ ^[0-9]+$ ]] && (( DESKTOP_COUNT >= 10 )); then
		# With LTE-only windows and many peers, signaling/register + reconnect can exceed 20s.
		# Default to a more realistic threshold for scale runs.
		SLA_SECONDS="35"
	else
		SLA_SECONDS="8"
	fi
fi

SLA_REQUIRE_READY="${SLA_REQUIRE_READY:-0}"
WATCHDOG_ENABLE="${WATCHDOG_ENABLE:-1}"
STABILIZE_SECS="${STABILIZE_SECS:-3}"

export LOOPS DESKTOP_COUNT SCENARIOS FORCE_TRANSPORT_BREAK ENFORCE_SLA SLA_SECONDS SLA_REQUIRE_READY WATCHDOG_ENABLE STABILIZE_SECS

# More conservative defaults for real devices. Adjust per environment.
#
# For high DESKTOP_COUNT, give extra time in the LTE-only window (wifi_disable) for the
# routing/transport switch + reconnect to complete across all peers.
if [[ "${DESKTOP_COUNT}" =~ ^[0-9]+$ ]] && (( DESKTOP_COUNT >= 10 )); then
	# Give the public-network transition plenty of room.
	export WIFI_DISABLE_SECS="${WIFI_DISABLE_SECS:-40}"
	export WIFI_ENABLE_SECS="${WIFI_ENABLE_SECS:-45}"
	export WIFI_TOGGLE_VERIFY_SECS="${WIFI_TOGGLE_VERIFY_SECS:-30}"
	export WIFI_IP_VERIFY_SECS="${WIFI_IP_VERIFY_SECS:-40}"
	export WATCHDOG_NO_LOG_SECS="${WATCHDOG_NO_LOG_SECS:-35}"
	export WATCHDOG_NO_PROGRESS_SECS="${WATCHDOG_NO_PROGRESS_SECS:-120}"
	export STABILIZE_SECS="${STABILIZE_SECS:-4}"
else
	export WIFI_DISABLE_SECS="${WIFI_DISABLE_SECS:-8}"
	export WIFI_ENABLE_SECS="${WIFI_ENABLE_SECS:-15}"
	export WIFI_TOGGLE_VERIFY_SECS="${WIFI_TOGGLE_VERIFY_SECS:-18}"
	export WIFI_IP_VERIFY_SECS="${WIFI_IP_VERIFY_SECS:-25}"
fi

if [[ "${DESKTOP_COUNT}" =~ ^[0-9]+$ ]] && (( DESKTOP_COUNT >= 10 )); then
	export DATA_ENABLE_SECS="${DATA_ENABLE_SECS:-8}"
	export DATA_DISABLE_SECS="${DATA_DISABLE_SECS:-6}"
else
	export DATA_DISABLE_SECS="${DATA_DISABLE_SECS:-4}"
	export DATA_ENABLE_SECS="${DATA_ENABLE_SECS:-4}"
fi
export AIRPLANE_ENABLE_SECS="${AIRPLANE_ENABLE_SECS:-8}"
export AIRPLANE_DISABLE_SECS="${AIRPLANE_DISABLE_SECS:-12}"

exec "${ROOT_DIR}/tools/harness/android_wifi_handoff_repro.sh"
