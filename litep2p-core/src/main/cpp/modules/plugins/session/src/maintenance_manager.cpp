#include "maintenance_manager.h"
#include "session_manager_p.h"
#include "config_manager.h"
#include "telemetry.h"
#include "anomaly_reporter.h"
#include "wire_codec.h"
#include "rugged_recovery_manager.h"
#include "../../discovery/include/discovery.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <sstream>
#include <unordered_map>

#if defined(__linux__) || defined(__ANDROID__)
#include <unistd.h>
#include <fstream>
#endif

namespace {
int64_t steady_now_ms_local() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// ---------------------------------------------------------------------------
// Resource sampling (api-spec.md §6.1): answer "how much RAM/CPU/threads is the
// engine consuming" directly from the OS, no external profiling required.
// Best-effort: every read failure leaves the previous gauge value untouched.
// ---------------------------------------------------------------------------
#if defined(__linux__) || defined(__ANDROID__)

// VmRSS (kB) and Threads from /proc/self/status.
bool read_proc_status(int64_t& rss_bytes, int64_t& thread_count) {
    std::ifstream f("/proc/self/status");
    if (!f.good()) return false;
    bool got_rss = false, got_threads = false;
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
            // Format: "VmRSS:\t   12345 kB"
            long kb = 0;
            if (std::sscanf(line.c_str(), "VmRSS: %ld", &kb) == 1) {
                rss_bytes = static_cast<int64_t>(kb) * 1024;
                got_rss = true;
            }
        } else if (line.rfind("Threads:", 0) == 0) {
            long n = 0;
            if (std::sscanf(line.c_str(), "Threads: %ld", &n) == 1) {
                thread_count = n;
                got_threads = true;
            }
        }
        if (got_rss && got_threads) break;
    }
    return got_rss || got_threads;
}

// CPU usage estimate from /proc/self/stat jiffies deltas between samples.
// Returns percent of one core (0..100+), or -1 when unavailable.
double sample_cpu_pct() {
    static std::mutex cpu_mu;
    static int64_t last_total_jiffies = -1;
    static int64_t last_sample_ms = 0;

    std::ifstream f("/proc/self/stat");
    if (!f.good()) return -1.0;

    // Fields: pid comm state ppid ... field14=utime field15=stime (1-based).
    // comm may contain spaces/parens, so skip past the closing ')' first.
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    const size_t close_paren = content.rfind(')');
    if (close_paren == std::string::npos) return -1.0;

    unsigned long utime = 0, stime = 0;
    // After ')' the next token is field 3 (state); utime is field 14, so it is
    // the 12th token after the paren.
    std::istringstream iss(content.substr(close_paren + 1));
    std::string tok;
    for (int i = 3; i <= 15; ++i) {
        if (!(iss >> tok)) return -1.0;
        if (i == 14) utime = std::strtoul(tok.c_str(), nullptr, 10);
        if (i == 15) stime = std::strtoul(tok.c_str(), nullptr, 10);
    }

    const long ticks_per_sec = ::sysconf(_SC_CLK_TCK);
    if (ticks_per_sec <= 0) return -1.0;

    const int64_t total = static_cast<int64_t>(utime + stime);
    const int64_t now = steady_now_ms_local();

    std::lock_guard<std::mutex> lock(cpu_mu);
    double pct = -1.0;
    if (last_total_jiffies >= 0 && now > last_sample_ms) {
        const int64_t dj = total - last_total_jiffies;
        const double elapsed_s = (now - last_sample_ms) / 1000.0;
        if (elapsed_s > 0.0 && dj >= 0) {
            pct = (static_cast<double>(dj) / ticks_per_sec) / elapsed_s * 100.0;
        }
    }
    last_total_jiffies = total;
    last_sample_ms = now;
    return pct;
}
#endif

int effective_keepalive_interval_sec() {
    // Prefer policy-driven interval (battery/network aware). Fall back to config.
    const uint32_t policy_sec = PeerReconnectPolicy::getInstance().get_keepalive_interval_seconds();
    int sec = static_cast<int>(policy_sec);
    if (sec <= 0) {
        sec = ConfigManager::getInstance().getHeartbeatIntervalSec();
    }
    return std::max(1, sec);
}
} // namespace

namespace detail {
    MaintenanceManager::MaintenanceManager(SessionManager::Impl* sm) 
        : m_sm(sm), 
          m_last_heartbeat(std::chrono::steady_clock::now() - std::chrono::seconds(effective_keepalive_interval_sec())),
                    m_last_discovery_broadcast(std::chrono::steady_clock::now()),
                                        m_last_signaling_reconnect_kick(std::chrono::steady_clock::now() - std::chrono::seconds(2)),
                                        m_last_peer_retry_scan(std::chrono::steady_clock::now() - std::chrono::seconds(1)),
                                        m_last_lan_discovery_scan(std::chrono::steady_clock::now()),
                                        m_last_endpoint_fallback_check(std::chrono::steady_clock::now()) {}

    void MaintenanceManager::handleTimerTick(const TimerTickEvent& event) {
        (void)event;
        LOG_DEBUG("MM: handleTimerTick called");
        // Shutdown guard
        if (m_sm->m_shutting_down.load(std::memory_order_acquire)) {
            return;
        }

        // AnomalyReporter housekeeping: upload pending incident files (rate-limited
        // to the configured interval). Best-effort; failures leave files pending.
        AnomalyReporter::getInstance().tick();

        // --- STALL DETECTION (field diagnostics) ---
        // A peer stuck in CONNECTING/HANDSHAKING beyond the threshold never
        // recovered. Report it to the AnomalyReporter once per episode (until the
        // peer's FSM state changes), so long-lived stalls are captured without
        // spamming one incident per maintenance tick.
        detectStalledPeers();

        // RUGGED RECOVERY: Process pending message retries and recovery queue
        if (m_sm->m_recovery_manager) {
            m_sm->m_recovery_manager->tick();
        }

        // Snapshot peer counts for this tick (also used to decide whether signaling should be kept alive).
        int64_t peers_total_for_tick = 0;

        // Telemetry tick + basic gauges (cheap, best-effort).
        {
            Telemetry& t = Telemetry::getInstance();
            t.tick();

            // Signaling/network state (best-effort; helps diagnose recovery after network changes).
            const int64_t signaling_connected = (m_sm->m_signaling_client && m_sm->m_signaling_client->isConnected()) ? 1 : 0;
            const int64_t signaling_registered = m_sm->m_signaling_registered.load(std::memory_order_acquire) ? 1 : 0;
            t.set_gauge("signaling_connected", signaling_connected);
            t.set_gauge("signaling_registered", signaling_registered);
            t.set_gauge("network_available", m_sm->m_network_available.load(std::memory_order_acquire) ? 1 : 0);
            t.set_gauge("network_is_wifi", m_sm->m_is_wifi.load(std::memory_order_acquire) ? 1 : 0);

            int64_t peers_total = 0;
            int64_t peers_connected = 0;
            {
                std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                peers_total = static_cast<int64_t>(m_sm->m_peers.size());
                for (const auto& kv : m_sm->m_peers) {
                    if (kv.second.connected) peers_connected++;
                }
            }
            peers_total_for_tick = peers_total;
            t.set_gauge("peers_total", peers_total);
            t.set_gauge("peers_connected", peers_connected);

            int64_t st_connecting = 0, st_handshaking = 0, st_ready = 0;
            int64_t pending_msgs = 0;
            {
                std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                for (const auto& kv : m_sm->m_peer_contexts) {
                    const PeerContext& ctx = kv.second;
                    if (ctx.state == PeerState::CONNECTING) st_connecting++;
                    else if (ctx.state == PeerState::HANDSHAKING) st_handshaking++;
                    else if (ctx.state == PeerState::READY) st_ready++;
                    pending_msgs += static_cast<int64_t>(ctx.pending_messages.size());
                }
            }
            t.set_gauge("peers_state_connecting", st_connecting);
            t.set_gauge("peers_state_handshaking", st_handshaking);
            t.set_gauge("peers_state_ready", st_ready);
            t.set_gauge("pending_messages_total", pending_msgs);

            // Resource gauges (api-spec.md §6.1): RAM, threads, CPU estimate.
            // These let the harness (and integrators) answer "how lightweight is
            // the engine" without external profiling. Best-effort on Linux/Android.
#if defined(__linux__) || defined(__ANDROID__)
            int64_t rss_bytes = 0, thread_count = 0;
            if (read_proc_status(rss_bytes, thread_count)) {
                if (rss_bytes > 0) t.set_gauge("rss_bytes", rss_bytes);
                if (thread_count > 0) t.set_gauge("thread_count", thread_count);
            }
            const double cpu_pct = sample_cpu_pct();
            if (cpu_pct >= 0.0) {
                // Best-effort integer percent of one core (spec §6.1 name).
                t.set_gauge("cpu_pct_estimate", static_cast<int64_t>(cpu_pct + 0.5));
            }
#endif
        }

        // --- SIGNALING FRESHNESS WATCHDOG (P0.4) ---
        // SignalingClient is a simple WebSocket client without automatic ping/pong.
        // It's possible to end up "connected" but stalled (no frames flowing). When signaling
        // is stale, force a cheap re-register to recover deterministically.
        if (m_sm->m_signaling_enabled && m_sm->m_signaling_client &&
            m_sm->m_signaling_client->isConnected() &&
            m_sm->m_signaling_registered.load(std::memory_order_acquire)) {
            const int64_t now_ms = steady_now_ms_local();
            const int64_t last_rx_ms = m_sm->m_last_signaling_rx_ms.load(std::memory_order_acquire);
            if (last_rx_ms > 0) {
                const int64_t keepalive_sec = static_cast<int64_t>(effective_keepalive_interval_sec());
                // Be conservative: signaling doesn't need to be as chatty as peer heartbeats.
                const int64_t stale_window_ms = std::max<int64_t>(45000, keepalive_sec * 4 * 1000);
                if (now_ms - last_rx_ms > stale_window_ms) {
                    const int64_t last_force_ms = m_sm->m_last_signaling_forced_reregister_ms.load(std::memory_order_acquire);
                    const int64_t min_force_gap_ms = std::max<int64_t>(10000, stale_window_ms / 2);
                    if (last_force_ms == 0 || now_ms - last_force_ms > min_force_gap_ms) {
                        m_sm->m_last_signaling_forced_reregister_ms.store(now_ms, std::memory_order_release);
                        LOG_WARN("MM: Signaling appears stale (" + std::to_string(now_ms - last_rx_ms) + "ms since last frame); forcing re-register");
                        m_sm->ensure_signaling_connected_async(true);
                    }
                }
            }
        }

        // --- SIGNALING RECONNECT/REGISTER KICK ---
        // During Wi-Fi <-> cellular handoffs, a reconnect attempt can fail transiently with
        // ENETUNREACH while the new interface is still coming up. If no further network
        // callbacks fire (common when "available" remains true), we still need to retry.
        if (m_sm->m_signaling_enabled &&
            m_sm->m_network_available.load(std::memory_order_acquire)) {
            const bool connected = (m_sm->m_signaling_client && m_sm->m_signaling_client->isConnected());
            const bool registered = m_sm->m_signaling_registered.load(std::memory_order_acquire);

            const int64_t now_ms = steady_now_ms_local();
            const int64_t change_ms = m_sm->m_last_network_change_ms.load(std::memory_order_acquire);
            // If we have not observed a network transition, use a large sentinel age.
            const int64_t age_ms = (change_ms > 0) ? (now_ms - change_ms) : 999999999;
            const bool in_post_handoff_grace = (age_ms >= 0 && age_ms < 15000);
            const bool force_reconnect_pending = m_sm->m_force_signaling_reconnect_requested.load(std::memory_order_acquire);

            // Only keep signaling alive if it's actually useful right now:
            // - DB-first bootstrap requested, OR
            // - we've entered a mode where signaling should stay persistent, OR
            // - we already know at least one peer (so endpoint updates / CONNECT_REQUESTs matter).
            const bool want_signaling =
                m_sm->m_signaling_bootstrap_requested.load(std::memory_order_acquire) ||
                m_sm->m_signaling_persistent_after_db_exhausted.load(std::memory_order_acquire) ||
                peers_total_for_tick > 0;

            if (want_signaling && (!connected || !registered || (in_post_handoff_grace && force_reconnect_pending))) {
                const auto now_tp = std::chrono::steady_clock::now();
                const auto kick_interval = in_post_handoff_grace ? std::chrono::seconds(1) : std::chrono::seconds(2);
                if (now_tp - m_last_signaling_reconnect_kick >= kick_interval) {
                    m_last_signaling_reconnect_kick = now_tp;

                    // If we're inside the post-handoff grace window, force signaling recovery so
                    // transient ENETUNREACH doesn't cause a single long gap with no REGISTER_ACK.
                    // Otherwise, only force when TCP is connected but not registered.
                    const bool force = in_post_handoff_grace || force_reconnect_pending || (connected && !registered);
                    m_sm->ensure_signaling_connected_async(force);
                }
            }
        }
        
        // In single-thread mode, we need to periodically send discovery broadcasts
        // since there's no dedicated broadcast thread
        auto now = std::chrono::steady_clock::now();
        auto discovery_elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_last_discovery_broadcast).count();
        if (discovery_elapsed >= 3) {  // Broadcast every 3 seconds
            m_last_discovery_broadcast = now;
            Discovery* discovery = getGlobalDiscoveryInstance();
            if (discovery && discovery->getSocketFd() >= 0) {
                discovery->sendBroadcast();
                LOG_DEBUG("MM: Sent discovery broadcast (single-thread mode)");
            }
        }

        // Get configurable values
        const int heartbeat_interval_sec = effective_keepalive_interval_sec();
        const int peer_expiration_ms = ConfigManager::getInstance().getPeerExpirationTimeoutMs();

        // Heartbeat-based liveness timeout for CONNECTED peers.
        // If we mark a peer as connected, we also send periodic PINGs. If PONGs stop,
        // we should not keep the UI in a "connected" state for the full peer_expiration_ms
        // (which may be configured large). Bound the connected-liveness window by heartbeat cadence.
        const int heartbeat_liveness_ms = std::max(5000, heartbeat_interval_sec * 3 * 1000);

        // If we keep receiving discovery from a peer but we do NOT receive authenticated/control traffic
        // (e.g., PONG/app data) for a while, it strongly suggests the encrypted session is stale
        // (common after peer restarts with new Noise keys). Discovery must not keep the peer "connected".
        const int restart_suspected_ms = std::max(8000, heartbeat_interval_sec * 2 * 1000);
        const int discovery_recent_ms = 5000;

        // Check if it's time to send heartbeat (every heartbeat_interval_sec seconds)
        // (now is already defined above)
        
        // --- PEER TIMEOUT / EXPIRATION CHECK ---
        // For UDP, peers may disappear without an explicit disconnect callback.
        // If we keep them marked as connected, we can retain stale Noise sessions and
        // stale ephemeral-port routing state. We treat long silence as DISCONNECT_DETECTED.
        std::vector<std::pair<std::string, std::string>> peers_to_disconnect; // (peer_id, network_id)
        std::vector<std::string> peers_to_remove;
        {
            std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
            for (const auto& pair : m_sm->m_peers) {
                const Peer& peer = pair.second;
                auto last_seen_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - peer.last_seen).count();
                auto last_discovery_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - peer.last_discovery_seen).count();

                // Grace: a connection that just completed its Noise handshake must not be
                // torn down by the inactivity detector. A spurious DISCONNECT_DETECTED right
                // after READY triggers a *one-sided* re-handshake (new ephemeral/keys on one
                // peer only) whose counterpart keeps the old session. That desyncs the two
                // peers' transport/Noise keys and every subsequent application message fails
                // with "auth tag mismatch" (this is a very likely cause of "I connected but
                // messages never arrive"). Give freshly-established sessions a short window so
                // heartbeats/PONGs have a chance to refresh last_seen before we renegotiate.
                static constexpr int kReadyGraceMs = 4000;
                bool recently_ready = false;
                {
                    auto ctx_it = m_sm->m_peer_contexts.find(peer.id);
                    if (ctx_it != m_sm->m_peer_contexts.end() &&
                        ctx_it->second.last_handshake_completed != std::chrono::steady_clock::time_point{}) {
                        const auto since_ready_ms =
                            std::chrono::duration_cast<std::chrono::milliseconds>(
                                now - ctx_it->second.last_handshake_completed).count();
                        recently_ready = (since_ready_ms >= 0 && since_ready_ms < kReadyGraceMs);
                    }
                }

                if (peer.connected && !recently_ready) {
                    // Primary inactivity timeout.
                    const int effective_expiration_ms = std::min(peer_expiration_ms, heartbeat_liveness_ms);
                    if (last_seen_ms > effective_expiration_ms) {
                        peers_to_disconnect.emplace_back(peer.id, peer.network_id);
                    } else if (last_discovery_ms >= 0 && last_discovery_ms < discovery_recent_ms && last_seen_ms > restart_suspected_ms) {
                        // Discovery is fresh (peer is alive), but authenticated traffic is stale.
                        // Treat as disconnect so we can renegotiate keys.
                        peers_to_disconnect.emplace_back(peer.id, peer.network_id);
                    }
                } else {
                    if (last_seen_ms > peer_expiration_ms) {
                        // IMPORTANT:
                        // Do not aggressively remove peers that still have a valid endpoint.
                        // For signaling-discovered peers, we may have long idle periods with no
                        // incoming traffic; removing them makes later outbound connects (e.g.
                        // proxy gateway auto-connect) fail with "Cannot connect to unknown peer".
                        const bool has_routable_endpoint = !peer.network_id.empty() && !peer.ip.empty() && peer.port > 0;
                        if (!has_routable_endpoint) {
                            peers_to_remove.push_back(peer.id);
                        }
                    }
                }
            }
        }

        if (!peers_to_disconnect.empty()) {
            LOG_INFO("MM: Marking " + std::to_string(peers_to_disconnect.size()) + " connected peers as DISCONNECTED due to inactivity");
            for (const auto& item : peers_to_disconnect) {
                const std::string& peer_id = item.first;
                const std::string& network_id = item.second;
                LOG_INFO("MM: Peer timed out: " + peer_id + " (last_seen>" + std::to_string(peer_expiration_ms) + "ms)");

                // Get current epoch for this peer
                uint64_t current_epoch = 0;
                {
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    auto ctx_it = m_sm->m_peer_contexts.find(peer_id);
                    if (ctx_it != m_sm->m_peer_contexts.end()) {
                        current_epoch = ctx_it->second.connect_epoch;
                    }
                }

                // Drive FSM cleanup (removes READY Noise session, etc.).
                m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::DISCONNECT_DETECTED, current_epoch});

                // Update connected flag so UI/state is consistent.
                {
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    Peer* p = m_sm->find_peer_by_id(peer_id);
                    if (p) {
                        p->connected = false;
                        p->last_seen = now;
                    }
                }

                // Best-effort: clear any ephemeral mappings referencing this peer's last known network_id.
                // This prevents future sends from routing to stale sockets.
                {
                    std::lock_guard<std::mutex> index_lock(m_sm->m_network_index_mutex);
                    for (auto it = m_sm->m_ephemeral_to_advertised_port_map.begin();
                         it != m_sm->m_ephemeral_to_advertised_port_map.end();) {
                        if (it->first == network_id || it->second == network_id) {
                            it = m_sm->m_ephemeral_to_advertised_port_map.erase(it);
                        } else {
                            ++it;
                        }
                    }
                }
            }
            m_sm->notifyPeerUpdate();

            // After we detect a peer went silent (UDP has no reliable disconnect), refresh signaling.
            // This helps recover quickly when the remote peer restarts and advertises a new endpoint.
            if (m_sm->m_signaling_enabled) {
                constexpr auto kPeerListCooldown = std::chrono::seconds(5);
                const auto now_local = std::chrono::steady_clock::now();
                if (m_sm->m_last_signaling_peer_list_request == std::chrono::steady_clock::time_point{} ||
                    (now_local - m_sm->m_last_signaling_peer_list_request) >= kPeerListCooldown) {
                    m_sm->m_last_signaling_peer_list_request = now_local;
                    LOG_INFO("MM: Requesting signaling peer list after inactivity disconnect");

                    m_sm->m_signaling_bootstrap_requested.store(true, std::memory_order_release);
                    m_sm->m_signaling_persistent_after_db_exhausted.store(true, std::memory_order_release);

                    if (m_sm->m_signaling_client && m_sm->m_signaling_client->isConnected() &&
                        m_sm->m_signaling_registered.load(std::memory_order_acquire)) {
                        m_sm->m_signaling_client->sendListPeers();
                    } else {
                        m_sm->ensure_signaling_connected_async(true);
                    }
                }
            }
        }

        // --- CHECK FOR PEERS STUCK IN CONNECTING STATE ---
        // If a peer has been in CONNECTING state for too long without receiving any response,
        // mark the connection as failed and trigger a retry. This handles cases where:
        // - The remote peer has restarted with new NAT mappings
        // - The cached IP:port from the local DB is stale
        // - NAT traversal failed silently
        //
        // SELF-HEALING OPTIMIZATION: Reduced from 15s to 8s for faster failure detection
        // during network transitions. This allows the engine to try alternative paths
        // (e.g., signaling relay, different transport) more quickly.
        constexpr auto kConnectingTimeoutMs = 8000; // 8 seconds (reduced from 15s)
        // HANDSHAKING can also hang (e.g., stale Noise session, packet loss, asymmetric reachability).
        // Never allow an unbounded handshake: fail and let reconnect policy retry.
        //
        // SELF-HEALING OPTIMIZATION: Reduced from 10s to 5s for faster handshake failure
        // detection. This is critical during WiFi<->LTE handoffs where stale sessions
        // need to be discarded quickly to allow fresh handshakes. The relay fallback
        // typically completes in <100ms once the failed handshake triggers retry.
        constexpr auto kHandshakingTimeoutMs = 5000; // 5 seconds (reduced from 10s)
        // PROACTIVE RELAY ESCALATION: If handshake hasn't completed in 2 seconds, proactively
        // re-send via signaling relay. This handles cases where UDP handshake gets lost.
        constexpr auto kHandshakeRelayEscalationMs = 2000; // 2 seconds
        std::vector<std::string> stuck_connecting_peers;
        std::vector<std::string> stuck_handshaking_peers;
        std::vector<std::string> handshake_escalation_peers;
        {
            std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
            for (const auto& ctx_pair : m_sm->m_peer_contexts) {
                const PeerContext& ctx = ctx_pair.second;
                if (ctx.state == PeerState::CONNECTING) {
                    auto stuck_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - ctx.last_state_change).count();
                    if (stuck_ms > kConnectingTimeoutMs) {
                        stuck_connecting_peers.push_back(ctx_pair.first);
                    }
                } else if (ctx.state == PeerState::HANDSHAKING) {
                    auto stuck_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - ctx.last_state_change).count();
                    if (stuck_ms > kHandshakingTimeoutMs) {
                        stuck_handshaking_peers.push_back(ctx_pair.first);
                    } else if (stuck_ms > kHandshakeRelayEscalationMs) {
                        // Proactive relay escalation: handshake stuck for >2s but <5s
                        // Only escalate once per handshake attempt (check last_relay_escalation)
                        // If last escalation was before current state change, we haven't escalated this attempt
                        bool not_escalated_yet = (ctx.last_relay_escalation < ctx.last_state_change);
                        if (not_escalated_yet) {
                            handshake_escalation_peers.push_back(ctx_pair.first);
                        }
                    }
                }
            }
        }
        
        // PROACTIVE RELAY ESCALATION: Re-send handshake via relay for stuck peers
        // This helps when UDP path is blocked but signaling relay works
        if (!handshake_escalation_peers.empty()) {
            LOG_INFO("MM: Escalating " + std::to_string(handshake_escalation_peers.size()) +
                     " handshakes to relay after " + std::to_string(kHandshakeRelayEscalationMs) + "ms");
            for (const auto& peer_id : handshake_escalation_peers) {
                LOG_INFO("MM: Proactively re-sending handshake via relay to " + peer_id);
                // Update last_relay_escalation timestamp before escalating
                {
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    auto it = m_sm->m_peer_contexts.find(peer_id);
                    if (it != m_sm->m_peer_contexts.end()) {
                        it->second.last_relay_escalation = now;
                    }
                }
#if HAVE_NOISE_PROTOCOL
                m_sm->proactiveHandshakeRelay(peer_id);
#endif
            }
        }
        
        if (!stuck_connecting_peers.empty()) {
            LOG_INFO("MM: Found " + std::to_string(stuck_connecting_peers.size()) + 
                     " peers stuck in CONNECTING state for >" + std::to_string(kConnectingTimeoutMs) + "ms");
            for (const auto& peer_id : stuck_connecting_peers) {
                LOG_WARN("MM: Peer " + peer_id + " stuck in CONNECTING - marking as CONNECT_FAILED");
                
                // Get current epoch for this peer
                uint64_t current_epoch = 0;
                {
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    auto ctx_it = m_sm->m_peer_contexts.find(peer_id);
                    if (ctx_it != m_sm->m_peer_contexts.end()) {
                        current_epoch = ctx_it->second.connect_epoch;
                    }
                }
                m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::CONNECT_FAILED, current_epoch});
            }
        }

        if (!stuck_handshaking_peers.empty()) {
            LOG_INFO("MM: Found " + std::to_string(stuck_handshaking_peers.size()) +
                     " peers stuck in HANDSHAKING state for >" + std::to_string(kHandshakingTimeoutMs) + "ms");
            for (const auto& peer_id : stuck_handshaking_peers) {
                LOG_WARN("MM: Peer " + peer_id + " stuck in HANDSHAKING - marking as HANDSHAKE_FAILED");
                
                // Get current epoch for this peer
                uint64_t current_epoch = 0;
                {
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    auto ctx_it = m_sm->m_peer_contexts.find(peer_id);
                    if (ctx_it != m_sm->m_peer_contexts.end()) {
                        current_epoch = ctx_it->second.connect_epoch;
                    }
                }
                m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_FAILED, current_epoch});
            }
        }
        
        if (!peers_to_remove.empty()) {
            LOG_INFO("MM: Removing " + std::to_string(peers_to_remove.size()) + " expired peers");
            for (const auto& peer_id : peers_to_remove) {
                m_sm->remove_peer_by_id(peer_id);
            }
            m_sm->notifyPeerUpdate();
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_last_heartbeat).count();
        
        if (elapsed >= heartbeat_interval_sec) {
            m_last_heartbeat = now;
            
            std::vector<Peer> peers_snapshot;
            {
                std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                for (const auto& pair : m_sm->m_peers) {
                    peers_snapshot.push_back(pair.second);
                }
            }

            int connected_count = 0;
            for (const auto& peer : peers_snapshot) {
                if (peer.connected) {
                    connected_count++;
                    // HEARTBEAT: Send ping to keep the connection alive and measure latency
                    // The heartbeat ensures connections stay active indefinitely
                    // Actual disconnection only happens when TCP reports peer is down
                    if (peer.network_id.empty()) {
                        continue;
                    }

                    // Send a lightweight token and compute RTT locally when we receive the PONG.
                    // Do NOT send steady_clock timestamps over the wire.
                    const uint64_t token = m_sm->m_ping_seq.fetch_add(1, std::memory_order_relaxed) + 1;
                    const auto sent_time = std::chrono::steady_clock::now();
                    {
                        std::lock_guard<std::mutex> lk(m_sm->m_ping_mutex);
                        m_sm->m_last_ping_by_peer[peer.id] = {token, sent_time};
                    }

                    const std::string ping_payload = std::to_string(token);
                    std::string ping_message = wire::encode_message(MessageType::CONTROL_PING, ping_payload);
                    LOG_INFO("MM: Sending PING heartbeat to peer " + peer.id + " (connected: " + std::to_string(connected_count) + ")");
                    m_sm->send_message_to_peer(peer.network_id, ping_message);
                }
            }
            
            if (connected_count == 0) {
                LOG_DEBUG("MM: No connected peers to send heartbeat to (total peers: " + std::to_string(peers_snapshot.size()) + ")");
            }
        }

        if (m_sm->m_message_batcher) {
            auto messages_to_send = m_sm->m_message_batcher->get_ready_batch();
            if (!messages_to_send.empty()) {
                LOG_INFO("MM: Retrieved " + std::to_string(messages_to_send.size()) + " messages from batcher");
            }
            for (const auto& msg : messages_to_send) {
                const Peer* peer = m_sm->find_peer_by_id(msg.peer_id);
                if (peer) {
                    m_sm->handleSendMessageWithRetry(msg.peer_id, peer->network_id, msg.message);
                }
            }
        }

        // Cleanup expired sessions from cache
        if (m_sm->m_session_cache) {
            m_sm->m_session_cache->cleanup_expired();
        }

        // --- PERIODIC PEER RECONNECT SCAN ---
        // DB-first reconnect only runs while zero peers are connected. In real deployments it's
        // common to have partial connectivity (one peer READY while another is DEGRADED/DISCONNECTED).
        // Without an independent retry scan, the non-connected peer can starve indefinitely.
        {
            PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
            const int64_t scan_interval_ms = std::max<int64_t>(250, policy.get_reconnect_attempt_interval_ms());
            const auto since_last_scan_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_last_peer_retry_scan).count();
            if (m_last_peer_retry_scan == std::chrono::steady_clock::time_point{} || since_last_scan_ms >= scan_interval_ms) {
                m_last_peer_retry_scan = now;

                struct Candidate {
                    std::string peer_id;
                    int priority = 0;
                    // True for peers we had a session with before this process's most recent
                    // restart (i.e. their Noise static public key is persisted in our keystore).
                    // After a restart these peers must be re-established, but the remote side
                    // keeps the stale encrypted session from the previous incarnation and never
                    // re-initiates on its own.
                    bool known_prior = false;
                };
                std::vector<Candidate> candidates;
                candidates.reserve(8);

                const bool signaling_enabled = m_sm->m_signaling_enabled;

                {
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    for (const auto& kv : m_sm->m_peers) {
                        const Peer& peer = kv.second;
                        if (peer.connected) continue;

                        // Respect explicit user disconnects: never auto-reconnect
                        // a peer the user disconnected until they connect again.
                        if (m_sm->m_user_disconnected_peers.count(peer.id)) continue;

                        PeerState st = PeerState::UNKNOWN;
                        auto ctx_it = m_sm->m_peer_contexts.find(peer.id);
                        if (ctx_it != m_sm->m_peer_contexts.end()) {
                            st = ctx_it->second.state;
                        }

                        // Only retry peers that have already failed/disconnected.
                        // Do NOT proactively auto-connect newly discovered peers here; that can
                        // disrupt endpoint-upgrade logic and can create connect storms.
                        // Exception: peers we had a persisted Noise session with before a restart.
                        // When a peer is kill -9'd and restarted (same workdir/keystore), its remote
                        // peers still hold the encrypted session from the killed process and keep
                        // sending encrypted data the restarted peer cannot decrypt. They never
                        // re-initiate because from their perspective the session is still READY, and
                        // WE are not the deterministic Noise initiator either. The peers thus sit in
                        // DISCOVERED forever. Restoring a *previously-established* (keystore-known)
                        // peer via an outbound CONTROL_CONNECT lets the remote side clear its stale
                        // session and re-handshake. This only applies to known peers, so brand-new
                        // broadcast discoveries are still skipped (no connect storms).
                        bool known_prior = false;
#if HAVE_NOISE_PROTOCOL
                        if ((st == PeerState::DISCOVERED || st == PeerState::CONNECTED) &&
                            m_sm->m_noise_key_store && m_sm->m_noise_key_store->has_peer_key(peer.id)) {
                            known_prior = true;
                        }
#endif
                        if (st != PeerState::DEGRADED && st != PeerState::DISCONNECTED &&
                            st != PeerState::FAILED && !known_prior) {
                            continue;
                        }

                        // Require an endpoint when signaling is disabled.
                        const bool has_endpoint = (!peer.advertised_network_id.empty() || !peer.network_id.empty()) &&
                                                  !peer.ip.empty() && peer.port > 0;
                        if (!has_endpoint && !signaling_enabled) {
                            continue;
                        }

                        int pri = 0;
                        if (st == PeerState::DEGRADED) pri = 3;
                        else if (st == PeerState::DISCONNECTED) pri = 2;
                        else if (known_prior) pri = 2;   // restore known peers like a disconnect
                        else if (st == PeerState::FAILED) pri = 1;

                        candidates.push_back(Candidate{peer.id, pri, known_prior});
                    }
                }

                if (!candidates.empty()) {
                    std::sort(candidates.begin(), candidates.end(),
                              [](const Candidate& a, const Candidate& b) {
                                  if (a.priority != b.priority) return a.priority > b.priority;
                                  return a.peer_id < b.peer_id;
                              });

                    // SELF-HEALING OPTIMIZATION: Parallel reconnection for multiple degraded peers.
                    // Previously we only retried one peer per scan to avoid storming. However, during
                    // network transitions (WiFi<->LTE), multiple peers may disconnect simultaneously.
                    // We now retry up to kMaxParallelReconnects peers per scan for faster recovery.
                    //
                    // Priority handling:
                    // - DEGRADED peers (pri=3): Retry immediately up to kMaxParallelReconnects
                    // - DISCONNECTED peers (pri=2): Retry one at a time after DEGRADED are handled
                    // - FAILED peers (pri=1): Retry with normal backoff policy
                    constexpr int kMaxParallelReconnects = 3;
                    int reconnects_this_scan = 0;
                    int degraded_reconnects = 0;
                    
                    for (const auto& cand : candidates) {
                        policy.track_peer(cand.peer_id);
                        
                        // DEGRADED peers get aggressive immediate retry (bypass backoff)
                        const bool is_degraded = (cand.priority == 3);
                        const bool should_retry = is_degraded || policy.should_reconnect_now(cand.peer_id);
                        
                        if (!should_retry) {
                            continue;
                        }
                        
                        // Parallel reconnects only for DEGRADED peers
                        if (is_degraded) {
                            if (degraded_reconnects >= kMaxParallelReconnects) {
                                continue; // Skip additional DEGRADED peers this scan
                            }
                            degraded_reconnects++;
                            LOG_INFO("MM: Aggressive reconnect for DEGRADED peer " + cand.peer_id + 
                                     " (" + std::to_string(degraded_reconnects) + "/" + 
                                     std::to_string(kMaxParallelReconnects) + ")");
                        } else {
                            // Non-degraded: only one per scan to avoid storming
                            if (reconnects_this_scan > 0) {
                                break;
                            }
                            if (cand.known_prior) {
                                LOG_INFO("MM: Restart-recovery reconnect for previously-known peer " +
                                         cand.peer_id + " (stale remote session; sending CONTROL_CONNECT to re-key)");
                            } else {
                                LOG_INFO("MM: Scheduling reconnect attempt for non-connected peer " + cand.peer_id);
                            }
                        }
                        
                        m_sm->connectToPeer(cand.peer_id, is_degraded, "maintenance_retry");
                        Telemetry::getInstance().inc_counter("maintenance_reconnect_attempt_total");
                        reconnects_this_scan++;
                    }
                }
            }
        }

        // DB-first reconnect + DB maintenance. This will only contact signaling on-demand:
        // - when the peer DB is empty, or
        // - when all DB candidates have been tried and no peers are reachable.
        m_sm->db_first_connect_and_prune_tick_();
        
        // --- LAN RE-DISCOVERY (when on WiFi) ---
        // Periodically trigger LAN discovery for known peers to find/refresh local endpoints
        performLanRediscovery();
        
        // --- ENDPOINT FALLBACK CHECK ---
        // Check peers that are failing to connect and try alternate endpoints
        checkEndpointFallback();
    }
    
    void MaintenanceManager::performLanRediscovery() {
        // Only run LAN discovery when on WiFi
        if (!m_sm->m_is_wifi.load(std::memory_order_acquire)) {
            return;
        }
        
        // Rate limit: run every 10 seconds when on WiFi
        auto now = std::chrono::steady_clock::now();
        auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(now - m_last_lan_discovery_scan).count();
        if (elapsed_sec < 10) {
            return;
        }
        m_last_lan_discovery_scan = now;
        
        // Check if broadcast discovery is available
        if (!m_sm->m_broadcast_discovery || !m_sm->m_broadcast_discovery->is_running()) {
            return;
        }
        
        // Collect peers that need LAN discovery:
        // - Not connected, or
        // - Connected but using WAN endpoint (could upgrade to LAN), or
        // - LAN endpoint candidate is stale (>30s since last seen)
        // Also capture known LAN IPs as hints for direct probing (bypasses AP isolation)
        struct DiscoveryTarget {
            std::string peer_id;
            std::string hint_ip;
            int hint_port = 0;
        };
        std::vector<DiscoveryTarget> peers_to_discover;
        {
            std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
            const uint64_t now_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
            
            for (const auto& kv : m_sm->m_peers) {
                const Peer& peer = kv.second;
                
                // Skip if we're already discovering this peer
                {
                    std::lock_guard<std::mutex> sched_lock(m_sm->m_scheduledEventsMutex);
                    if (m_sm->m_peers_being_discovered.count(peer.id)) {
                        continue;
                    }
                }
                
                bool needs_discovery = false;
                std::string best_lan_ip;
                int best_lan_port = 0;
                
                // Check if current network_id is a WAN (public) IP
                bool current_is_lan = false;
                if (!peer.network_id.empty()) {
                    auto colon_pos = peer.network_id.find_last_of(':');
                    if (colon_pos != std::string::npos) {
                        std::string ip = peer.network_id.substr(0, colon_pos);
                        // Check if IP is private (LAN)
                        if (ip.rfind("10.", 0) == 0 || ip.rfind("192.168.", 0) == 0 || 
                            ip.rfind("127.", 0) == 0 || ip.rfind("169.254.", 0) == 0) {
                            current_is_lan = true;
                        } else if (ip.rfind("172.", 0) == 0) {
                            auto dot = ip.find('.', 4);
                            if (dot != std::string::npos) {
                                try {
                                    int second = std::stoi(ip.substr(4, dot - 4));
                                    if (second >= 16 && second <= 31) {
                                        current_is_lan = true;
                                    }
                                } catch (...) {}
                            }
                        }
                    }
                }
                
                // Find any known LAN endpoint candidate to use as hint for direct probing
                for (const auto& candidate : peer.endpoint_candidates) {
                    if (candidate.type == EndpointType::LAN && !candidate.ip.empty() && candidate.port > 0) {
                        // Prefer the most recently seen LAN candidate
                        if (best_lan_ip.empty() || candidate.last_seen_ms > 0) {
                            best_lan_ip = candidate.ip;
                            best_lan_port = candidate.port;
                        }
                    }
                }
                
                if (!peer.connected) {
                    // Not connected - always try to discover LAN endpoint
                    needs_discovery = true;
                } else if (!current_is_lan) {
                    // Connected via WAN - try to find LAN endpoint for faster path
                    needs_discovery = true;
                } else {
                    // Connected via LAN - check if any LAN candidate is stale
                    for (const auto& candidate : peer.endpoint_candidates) {
                        if (candidate.type == EndpointType::LAN) {
                            if (candidate.last_seen_ms > 0 && now_ms - candidate.last_seen_ms > 30000) {
                                needs_discovery = true;
                                break;
                            }
                        }
                    }
                }
                
                if (needs_discovery) {
                    DiscoveryTarget target;
                    target.peer_id = peer.id;
                    target.hint_ip = best_lan_ip;
                    target.hint_port = best_lan_port;
                    peers_to_discover.push_back(target);
                }
            }
        }
        
        // Trigger discovery for up to 3 peers per scan to avoid storming
        int discovery_count = 0;
        for (const auto& target : peers_to_discover) {
            if (discovery_count >= 3) break;
            
            {
                std::lock_guard<std::mutex> lock(m_sm->m_scheduledEventsMutex);
                if (m_sm->m_peers_being_discovered.count(target.peer_id)) {
                    continue;
                }
                m_sm->m_peers_being_discovered.insert(target.peer_id);
            }
            
            // Use discover_peer_with_hint if we have a known LAN IP, otherwise use regular discover_peer
            // The hint enables direct probing which bypasses AP isolation that blocks broadcasts
            if (!target.hint_ip.empty() && target.hint_port > 0) {
                LOG_INFO("MM: Triggering LAN re-discovery for peer " + target.peer_id + 
                         " (hint=" + target.hint_ip + ":" + std::to_string(target.hint_port) + ")");
                m_sm->m_broadcast_discovery->discover_peer_with_hint(target.peer_id,
                    target.hint_ip, target.hint_port,
                    [this, peer_id = target.peer_id](const DiscoveryResponse& response) {
                        m_sm->handleDiscoveryResponseWithEndpoint(
                            response.responder_peer_id,
                            response.responder_ip,
                            response.responder_port,
                            response.latency_ms);
                    });
            } else {
                LOG_INFO("MM: Triggering LAN re-discovery for peer " + target.peer_id);
                m_sm->m_broadcast_discovery->discover_peer(target.peer_id,
                    [this, peer_id = target.peer_id](const DiscoveryResponse& response) {
                        m_sm->handleDiscoveryResponseWithEndpoint(
                            response.responder_peer_id,
                            response.responder_ip,
                            response.responder_port,
                            response.latency_ms);
                    });
            }
            
            discovery_count++;
            Telemetry::getInstance().inc_counter("lan_rediscovery_triggered");
        }
    }
    
    void MaintenanceManager::checkEndpointFallback() {
        // Rate limit: run every 5 seconds
        auto now = std::chrono::steady_clock::now();
        auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(now - m_last_endpoint_fallback_check).count();
        if (elapsed_sec < 5) {
            return;
        }
        m_last_endpoint_fallback_check = now;
        
        // Collect peers that are CONNECTING or FAILED with multiple endpoint candidates
        std::vector<std::pair<std::string, std::string>> peers_to_fallback; // (peer_id, alternate_network_id)
        
        {
            std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
            const uint64_t now_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
            const bool is_wifi = m_sm->m_is_wifi.load(std::memory_order_acquire);
            
            for (const auto& kv : m_sm->m_peer_contexts) {
                const std::string& peer_id = kv.first;
                const PeerContext& ctx = kv.second;
                
                // Only consider peers that are stuck in CONNECTING or recently FAILED
                if (ctx.state != PeerState::CONNECTING && 
                    ctx.state != PeerState::FAILED &&
                    ctx.state != PeerState::DEGRADED) {
                    continue;
                }
                
                auto peer_it = m_sm->m_peers.find(peer_id);
                if (peer_it == m_sm->m_peers.end()) {
                    continue;
                }
                
                const Peer& peer = peer_it->second;
                if (peer.endpoint_candidates.size() < 2) {
                    continue; // No alternate endpoints
                }
                
                // Find the current endpoint
                const std::string current_network_id = peer.network_id;
                
                // Find best alternate endpoint
                const EndpointCandidate* best_alternate = nullptr;
                float best_score = -1000.0f;
                
                for (const auto& candidate : peer.endpoint_candidates) {
                    std::string candidate_network_id = candidate.ip + ":" + std::to_string(candidate.port);
                    if (candidate_network_id == current_network_id) {
                        continue; // Skip current endpoint
                    }
                    
                    // Check if this endpoint type is reachable
                    if (candidate.type == EndpointType::LAN && !is_wifi) {
                        continue; // LAN endpoints not reachable without WiFi
                    }
                    
                    // Skip endpoints with recent failures
                    if (candidate.consecutive_failures >= 3) {
                        continue;
                    }
                    
                    float score = candidate.compute_score(now_ms);
                    if (score > best_score) {
                        best_score = score;
                        best_alternate = &candidate;
                    }
                }
                
                if (best_alternate != nullptr && best_score > 0) {
                    std::string alternate_network_id = best_alternate->ip + ":" + std::to_string(best_alternate->port);
                    peers_to_fallback.emplace_back(peer_id, alternate_network_id);
                }
            }
        }
        
        // Apply fallbacks (outside lock)
        for (const auto& item : peers_to_fallback) {
            const std::string& peer_id = item.first;
            const std::string& alternate_network_id = item.second;
            
            LOG_INFO("MM: Endpoint fallback for peer " + peer_id + " -> " + alternate_network_id);
            
            // Update the peer's network_id to the alternate endpoint
            {
                SessionManager::Impl::PeersThenNetworkIndexLock lock(*m_sm);
                
                Peer* peer = m_sm->find_peer_by_id(peer_id);
                if (!peer) continue;
                
                // Check for collision
                auto collision_it = m_sm->m_network_id_to_peer_id.find(alternate_network_id);
                if (collision_it != m_sm->m_network_id_to_peer_id.end() && 
                    collision_it->second != peer_id) {
                    LOG_WARN("MM: Cannot fallback peer " + peer_id + " to " + alternate_network_id + 
                             " - already mapped to " + collision_it->second);
                    continue;
                }
                
                // Update mappings
                std::string old_network_id = peer->network_id;
                m_sm->remove_peer_from_network_index_locked_(old_network_id);
                
                // Parse the alternate network_id
                auto colon_pos = alternate_network_id.find_last_of(':');
                if (colon_pos != std::string::npos) {
                    peer->ip = alternate_network_id.substr(0, colon_pos);
                    try {
                        peer->port = std::stoi(alternate_network_id.substr(colon_pos + 1));
                    } catch (...) {
                        peer->port = -1;
                    }
                }
                peer->network_id = alternate_network_id;
                
                m_sm->add_peer_to_network_index_locked_(peer_id, alternate_network_id);
                
                // Update context
                auto ctx_it = m_sm->m_peer_contexts.find(peer_id);
                if (ctx_it != m_sm->m_peer_contexts.end()) {
                    ctx_it->second.network_id = alternate_network_id;
                }
                
                // Mark failure on old endpoint
                for (auto& candidate : peer->endpoint_candidates) {
                    std::string cand_net_id = candidate.ip + ":" + std::to_string(candidate.port);
                    if (cand_net_id == old_network_id) {
                        candidate.consecutive_failures++;
                        candidate.total_failures++;
                        candidate.last_failure_ms = static_cast<uint64_t>(
                            std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now().time_since_epoch()).count());
                        break;
                    }
                }
            }
            
            // Reset backoff and trigger reconnect
            PeerReconnectPolicy::getInstance().reset_peer_stats(peer_id);
            m_sm->connectToPeer(peer_id, true, "endpoint_fallback");
            
            Telemetry::getInstance().inc_counter("endpoint_fallback_triggered");
        }
    }
}

void detail::MaintenanceManager::detectStalledPeers() {
    const int64_t threshold_ms = ConfigManager::getInstance().getAnomalyStallThresholdMs();
    if (threshold_ms <= 0) return;

    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
    for (const auto& kv : m_sm->m_peer_contexts) {
        const PeerContext& ctx = kv.second;
        const int state_int = static_cast<int>(ctx.state);
        const bool is_transient = (ctx.state == PeerState::CONNECTING || ctx.state == PeerState::HANDSHAKING);
        if (!is_transient) {
            m_reported_stall_state.erase(ctx.peer_id);
            continue;
        }
        const auto stuck_for = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   now - ctx.last_state_change)
                                   .count();
        if (stuck_for < threshold_ms) continue;

        // Report once per (peer, state) episode — not on every maintenance tick.
        const auto it = m_reported_stall_state.find(ctx.peer_id);
        if (it != m_reported_stall_state.end() && it->second == state_int) {
            continue;
        }
        m_reported_stall_state[ctx.peer_id] = state_int;

        AnomalyReporter::Event ev;
        ev.type = "stall_not_recovered";
        ev.peer_id = ctx.peer_id;
        ev.network_id = ctx.network_id;
        ev.detail = "Peer stuck in " + m_sm->state_to_string(ctx.state) + " for " +
                    std::to_string(stuck_for) + " ms (threshold " +
                    std::to_string(threshold_ms) + " ms); recovery did not complete";
        ev.extras.emplace_back("state", m_sm->state_to_string(ctx.state));
        ev.extras.emplace_back("stuck_ms", std::to_string(stuck_for));
        ev.extras.emplace_back("threshold_ms", std::to_string(threshold_ms));
        AnomalyReporter::getInstance().report(ev);
        LOG_WARN("MM: STALL NOT RECOVERED peer=" + ctx.peer_id +
                 " state=" + m_sm->state_to_string(ctx.state) +
                 " stuck_ms=" + std::to_string(stuck_for));
    }
}

