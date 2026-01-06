#!/usr/bin/env bash
set -euo pipefail

# Apply a netem profile inside the `litep2p_netem` container.
#
# Example:
#   ./tools/harness/scenarios/netem_profile.sh loss5
#
# Profiles are intentionally simple at first; we can add more as we learn which conditions reproduce issues.

PROFILE="${1:-}"
if [[ -z "${PROFILE}" ]]; then
  echo "usage: $0 <profile>"
  echo "profiles: clean, loss1, loss5, jitter50, jitter200, blackout3"
  exit 2
fi

case "${PROFILE}" in
  clean)
    echo "clean: remove netem qdisc"
    docker exec litep2p_netem sh -c "tc qdisc del dev eth0 root 2>/dev/null || true"
    ;;
  loss1)
    docker exec litep2p_netem sh -c "tc qdisc replace dev eth0 root netem loss 1%"
    ;;
  loss5)
    docker exec litep2p_netem sh -c "tc qdisc replace dev eth0 root netem loss 5%"
    ;;
  jitter50)
    docker exec litep2p_netem sh -c "tc qdisc replace dev eth0 root netem delay 50ms 10ms distribution normal"
    ;;
  jitter200)
    docker exec litep2p_netem sh -c "tc qdisc replace dev eth0 root netem delay 200ms 50ms distribution normal"
    ;;
  blackout3)
    echo "blackout3: drop all traffic for 3 seconds, then restore"
    docker exec litep2p_netem sh -c "iptables -I OUTPUT -j DROP; iptables -I INPUT -j DROP; sleep 3; iptables -D OUTPUT -j DROP; iptables -D INPUT -j DROP"
    ;;
  *)
    echo "unknown profile: ${PROFILE}"
    exit 2
    ;;
esac

echo "applied profile: ${PROFILE}"


