#include "maintenance_manager.h"
#include "session_manager_p.h"
#include "config_manager.h"
#include "telemetry.h"
#include "wire_codec.h"
#include "../../discovery/include/discovery.h"

namespace detail {
    MaintenanceManager::MaintenanceManager(SessionManager::Impl* sm) 
        : m_sm(sm), 
          m_last_heartbeat(std::chrono::steady_clock::now() - std::chrono::seconds(ConfigManager::getInstance().getHeartbeatIntervalSec())),
          m_last_discovery_broadcast(std::chrono::steady_clock::now()) {}

    void MaintenanceManager::handleTimerTick(const TimerTickEvent& event) {
        LOG_DEBUG("MM: handleTimerTick called");
        // Shutdown guard
        if (m_sm->m_shutting_down.load(std::memory_order_acquire)) {
            return;
        }

        // Telemetry tick + basic gauges (cheap, best-effort).
        {
            Telemetry& t = Telemetry::getInstance();
            t.tick();

            int64_t peers_total = 0;
            int64_t peers_connected = 0;
            {
                std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                peers_total = static_cast<int64_t>(m_sm->m_peers.size());
                for (const auto& kv : m_sm->m_peers) {
                    if (kv.second.connected) peers_connected++;
                }
            }
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
        const int heartbeat_interval_sec = ConfigManager::getInstance().getHeartbeatIntervalSec();
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

                if (peer.connected) {
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

                // Drive FSM cleanup (removes READY Noise session, etc.).
                m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::DISCONNECT_DETECTED});

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
        constexpr auto kConnectingTimeoutMs = 15000; // 15 seconds
        // HANDSHAKING can also hang (e.g., stale Noise session, packet loss, asymmetric reachability).
        // Never allow an unbounded handshake: fail and let reconnect policy retry.
        constexpr auto kHandshakingTimeoutMs = 20000; // 20 seconds
        std::vector<std::string> stuck_connecting_peers;
        std::vector<std::string> stuck_handshaking_peers;
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
                    }
                }
            }
        }
        
        if (!stuck_connecting_peers.empty()) {
            LOG_INFO("MM: Found " + std::to_string(stuck_connecting_peers.size()) + 
                     " peers stuck in CONNECTING state for >" + std::to_string(kConnectingTimeoutMs) + "ms");
            for (const auto& peer_id : stuck_connecting_peers) {
                LOG_WARN("MM: Peer " + peer_id + " stuck in CONNECTING - marking as CONNECT_FAILED");
                m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::CONNECT_FAILED});
            }
        }

        if (!stuck_handshaking_peers.empty()) {
            LOG_INFO("MM: Found " + std::to_string(stuck_handshaking_peers.size()) +
                     " peers stuck in HANDSHAKING state for >" + std::to_string(kHandshakingTimeoutMs) + "ms");
            for (const auto& peer_id : stuck_handshaking_peers) {
                LOG_WARN("MM: Peer " + peer_id + " stuck in HANDSHAKING - marking as HANDSHAKE_FAILED");
                m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_FAILED});
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
                    std::string ping_payload = std::to_string(
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()
                        ).count()
                    );
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

        // DB-first reconnect + DB maintenance. This will only contact signaling on-demand:
        // - when the peer DB is empty, or
        // - when all DB candidates have been tried and no peers are reachable.
        m_sm->db_first_connect_and_prune_tick_();
    }
}
