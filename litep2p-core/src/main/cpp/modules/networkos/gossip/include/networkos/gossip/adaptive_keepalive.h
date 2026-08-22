#pragma once

// Adaptive keep-alive policy (signalling.md §3 Phase-2 idle heartbeats).
//
// Mobile CGNATs drop idle mappings rapidly, but fixed short timers burn radio
// tail-time. The strategy: start probing at 45 s and ramp the interval up as
// the path proves stable (45 -> 90 -> 120 -> 180 s cap), resetting on any
// failure or network change. Heartbeats are request/response pairs, so both
// peers' radios wake once per cycle (bidirectional sync is inherent to the
// ping->pong exchange).
//
// Pure policy: no timers, no sockets — the connection manager consults it
// whenever it is about to schedule the next keepalive.

#include <cstdint>

namespace networkos {
namespace gossip {

class AdaptiveKeepalive {
public:
    static constexpr int64_t kInitialMs = 45'000;
    static constexpr int64_t kMaxMs = 180'000;

    // Interval to use for the NEXT keepalive given current stability state.
    int64_t intervalMs() const { return m_current_ms; }

    // Called after a successful keepalive round-trip. Ramps the interval one
    // step per confirmed cycle: 45s -> 90s -> 120s -> 180s (capped).
    void onSuccess() {
        m_failures = 0;
        if (m_current_ms < kMaxMs) {
            if (m_current_ms < 90'000) m_current_ms = 90'000;
            else if (m_current_ms < 120'000) m_current_ms = 120'000;
            else m_current_ms = kMaxMs;
        }
    }

    // Called on timeout / ICMP-unreachable / socket error. Two consecutive
    // failures drop back toward the fast probe cadence so liveness recovers
    // quickly instead of waiting out a 180 s silence.
    void onFailure() {
        if (++m_failures >= 2) {
            m_current_ms = kInitialMs;
            m_failures = 0;
        }
    }

    // Network switch / wake-from-Doze: path identity changed, stability is
    // unknown again. Probe fast until the new path proves itself.
    void onNetworkChange() {
        m_current_ms = kInitialMs;
        m_failures = 0;
    }

private:
    int64_t m_current_ms{kInitialMs};
    int m_failures{0};
};

}  // namespace gossip
}  // namespace networkos