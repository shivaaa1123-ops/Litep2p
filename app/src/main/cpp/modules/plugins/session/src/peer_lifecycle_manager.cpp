#include "peer_lifecycle_manager.h"
#include "session_manager_p.h"
#include "config_manager.h"
#include "telemetry.h"
#include "../../routing/include/peer_reconnect_policy.h"

#include <chrono>

namespace {
    struct NetworkEndpoint {
        std::string ip;
        int port = -1;
    };

    bool isPrivateIpv4(const std::string& ip) {
        // Minimal RFC1918 + loopback + link-local checks (IPv4 only).
        if (ip.rfind("10.", 0) == 0) return true;
        if (ip.rfind("127.", 0) == 0) return true;
        if (ip.rfind("192.168.", 0) == 0) return true;
        if (ip.rfind("169.254.", 0) == 0) return true;
        if (ip.rfind("172.", 0) == 0) {
            // 172.16.0.0/12
            const size_t dot = ip.find('.', 4);
            if (dot != std::string::npos) {
                try {
                    const int second = std::stoi(ip.substr(4, dot - 4));
                    if (second >= 16 && second <= 31) {
                        return true;
                    }
                } catch (...) {
                    // best-effort
                }
            }
        }
        return false;
    }

    NetworkEndpoint parseNetworkId(const std::string& network_id) {
        NetworkEndpoint endpoint;

        if (network_id.empty()) {
            return endpoint;
        }

        auto separator = network_id.find_last_of(':');
        if (separator == std::string::npos) {
            endpoint.ip = network_id;
            return endpoint;
        }

        endpoint.ip = network_id.substr(0, separator);
        std::string port_str = network_id.substr(separator + 1);

        if (port_str.empty()) {
            LOG_WARN("SM: Empty port component in network_id: " + network_id);
            return endpoint;
        }

        try {
            int parsed = std::stoi(port_str);
            if (parsed >= 0 && parsed <= 65535) {
                endpoint.port = parsed;
            } else {
                LOG_WARN("SM: Parsed port out of range in network_id: " + network_id);
            }
        } catch (const std::exception& e) {
            LOG_WARN("SM: Failed to parse port from network_id: " + network_id + ", error: " + e.what());
        }

        return endpoint;
    }
}

namespace detail {
    PeerLifecycleManager::PeerLifecycleManager(SessionManager::Impl* sm) : m_sm(sm) {}

    namespace {
        int64_t system_now_ms() {
            using namespace std::chrono;
            return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
        }

        bool isConnectable(const std::string& ip, int port) {
            return !ip.empty() && port > 0 && port <= 65535;
        }
    }

    void PeerLifecycleManager::handlePeerDisconnect(const PeerDisconnectEvent& event) {
        // Shutdown guard - early return if shutting down
        if (m_sm->m_shutting_down.load(std::memory_order_acquire)) {
            return;
        }
        
        std::string peer_id_to_remove;

        // SCOPE: Brief lock to find peer
        {
            std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
            const Peer* peer = m_sm->find_peer_by_network_id(event.network_id);
            if (peer) {
                peer_id_to_remove = peer->id;
            }
        } // Lock released

        if (!peer_id_to_remove.empty()) {
            LOG_INFO("SM: Peer disconnected: " + peer_id_to_remove);
            m_sm->pushEvent(FSMEvent{peer_id_to_remove, PeerEvent::DISCONNECT_DETECTED});

            // IMPORTANT: Do NOT remove the peer entry on disconnect.
            // On mobile networks and during restarts we may see transient disconnects;
            // removing the peer makes subsequent inbound CONTROL_CONNECT impossible
            // unless discovery happens first. We keep the peer and allow reconnection.
            {
                std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                Peer* peer = m_sm->find_peer_by_id(peer_id_to_remove);
                if (peer) {
                    peer->connected = false;
                    peer->last_seen = std::chrono::steady_clock::now();
                }
            }

            // Best-effort: clear any ephemeral mapping for this network_id so we don't route to stale sockets.
            {
                std::lock_guard<std::mutex> index_lock(m_sm->m_network_index_mutex);
                m_sm->m_ephemeral_to_advertised_port_map.erase(event.network_id);
            }

            m_sm->notifyPeerUpdate();

            // Best-effort persistence
            if (m_sm->m_local_peer_db && m_sm->m_local_peer_db->is_open()) {
                m_sm->m_local_peer_db->set_peer_connected(peer_id_to_remove, false, system_now_ms());
            }
        }
    }

    void PeerLifecycleManager::handlePeerDiscovered(const PeerDiscoveredEvent& event) {
        // Shutdown guard - early return if shutting down
        if (m_sm->m_shutting_down.load(std::memory_order_acquire)) {
            return;
        }
        
        // Ignore self-discovery
        if (event.peerId == m_sm->m_localPeerId) {
            LOG_DEBUG("SM: Ignoring self-discovery for peer: " + event.peerId);
            return;
        }
        
        // Check if peer is already known
        const auto endpoint = parseNetworkId(event.networkId);
        const bool incoming_is_ipv6_literal = (endpoint.ip.find(':') != std::string::npos);
        const bool incoming_connectable = !endpoint.ip.empty() && !incoming_is_ipv6_literal && endpoint.port > 0 && endpoint.port <= 65535;
        const auto now = std::chrono::steady_clock::now();

        // DB persistence snapshot (avoid doing I/O while holding peer locks)
        bool persist = false;
        bool push_fsm_discovered = false;
        std::string persist_peer_id;
        std::string persist_network_id;
        std::string persist_ip;
        int persist_port = 0;
        int64_t persist_last_seen_ms = 0;
        int64_t persist_last_discovery_ms = 0;

        {
            std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
            Peer* existing_peer = m_sm->find_peer_by_id(event.peerId);
            if (existing_peer != nullptr) {
                // Snapshot FSM context so we can recover if the peer endpoint changes mid-connect.
                PeerState prior_state = PeerState::UNKNOWN;
                std::string prior_connect_target;
                {
                    auto ctx_it = m_sm->m_peer_contexts.find(event.peerId);
                    if (ctx_it != m_sm->m_peer_contexts.end()) {
                        prior_state = ctx_it->second.state;
                        prior_connect_target = ctx_it->second.last_connect_target_network_id;
                    }
                }

                // Always track discovery announcements.
                existing_peer->last_discovery_seen = now;

                // Keep the latest advertised endpoint up to date. Never overwrite a real ip:port
                // with a placeholder (e.g., "signaling-<peer>") once we have a connectable endpoint.
                if (incoming_connectable || existing_peer->advertised_network_id.empty() || existing_peer->advertised_network_id.find(':') == std::string::npos) {
                    existing_peer->advertised_network_id = event.networkId;
                }

                // Only treat discovery as session liveness when NOT connected.
                // For connected peers, liveness should come from authenticated/control traffic
                // (e.g., PONG, application messages, CONTROL_CONNECT), otherwise a restarted peer
                // can keep a stale READY Noise session alive forever via discovery.
                if (!existing_peer->connected) {
                    existing_peer->last_seen = now;
                }
                // Also update network_id in case IP/Port changed
                // NOTE: For CONNECTED peers, do NOT switch the active endpoint immediately; instead,
                // we rely on advertised_network_id to take effect on the next reconnect.
                if (existing_peer->network_id != event.networkId) {
                    
                    // Check if current network_id is a tracked ephemeral port
                    bool is_ephemeral = false;
                    {
                        std::lock_guard<std::mutex> index_lock(m_sm->m_network_index_mutex);
                        if (m_sm->m_ephemeral_to_advertised_port_map.find(existing_peer->network_id) != m_sm->m_ephemeral_to_advertised_port_map.end()) {
                            is_ephemeral = true;
                        }
                    }

                    const auto new_ep = parseNetworkId(event.networkId);
                    const bool new_is_private = isPrivateIpv4(new_ep.ip) && new_ep.port > 0;

                    // IMPORTANT:
                    // During reconnect races and network flaps, we can accidentally end up "CONNECTING"
                    // to a public/STUN endpoint (WAN) that is not reachable from the same LAN (no NAT hairpin).
                    // If discovery provides a private IPv4 endpoint while we're CONNECTING, prefer it even if
                    // the currently stored endpoint is tagged as "ephemeral".
                    //
                    // This is safe because:
                    // - We only do it for NOT-connected peers
                    // - We only do it when the new endpoint is a valid private IPv4 ip:port
                    // - It unblocks the common "LTE->WiFi" or "WAN->LAN" recovery path.
                    if (is_ephemeral && new_is_private && prior_state == PeerState::CONNECTING) {
                        LOG_INFO("SM: Upgrading CONNECTING peer " + event.peerId +
                                 " endpoint from ephemeral " + existing_peer->network_id + " -> " + event.networkId +
                                 " (discovered private IPv4)");

                        // Remove old index entry (even if ephemeral) and adopt the discovered stable endpoint.
                        m_sm->remove_peer_from_network_index(existing_peer->network_id);
                        existing_peer->network_id = event.networkId;
                        m_sm->add_peer_to_network_index(event.peerId, event.networkId);

                        // Keep context's endpoint in sync.
                        auto ctx_it2 = m_sm->m_peer_contexts.find(event.peerId);
                        if (ctx_it2 != m_sm->m_peer_contexts.end()) {
                            ctx_it2->second.network_id = event.networkId;
                        }

                        // Best-effort: cancel any WAN hole-punch work now that we have a direct LAN path.
                        NATTraversal::getInstance().unregisterPeer(event.peerId);

                        // Trigger a new connect attempt; debouncer will allow it because target changed.
                        m_sm->pushEvent(ConnectToPeerEvent{event.peerId});
                    } else if (is_ephemeral) {
                        LOG_INFO("SM: Ignoring network_id update for peer " + event.peerId +
                                 " because current ID " + existing_peer->network_id + " is a tracked ephemeral port.");
                    } else if (existing_peer->connected) {
                        // Peer is connected but discovery/signaling shows a different endpoint.
                        // DO NOT switch the active send endpoint immediately (could break a healthy LAN session).
                        // Instead, remember the new endpoint via advertised_network_id so that when the
                        // session goes stale/disconnects we can reconnect to the latest advertised mapping.
                        LOG_INFO("SM: Peer " + event.peerId + " is CONNECTED to " + existing_peer->network_id +
                                 " but advertised on " + event.networkId + " - storing advertised endpoint for future reconnect");

                        // Reset per-peer reconnect backoff so that when we do reconnect we don't get
                        // stuck behind stale backoff/circuit-breaker state caused by the old endpoint.
                        // This is safe because it only happens on endpoint change.
                        PeerReconnectPolicy::getInstance().reset_peer_stats(event.peerId);
                    } else {
                        // Not connected and not ephemeral - safe to update
                        // Only switch the active endpoint if the incoming endpoint is connectable or
                        // we currently don't have a connectable endpoint.
                        const auto cur_ep = parseNetworkId(existing_peer->network_id);
                        const bool cur_is_ipv6_literal = (cur_ep.ip.find(':') != std::string::npos);
                        const bool cur_connectable = !cur_ep.ip.empty() && !cur_is_ipv6_literal && cur_ep.port > 0 && cur_ep.port <= 65535;

                        if (incoming_connectable || !cur_connectable || existing_peer->network_id.empty()) {
                            LOG_INFO("SM: Updating network_id for peer " + event.peerId + ": " + existing_peer->network_id + " -> " + event.networkId);
                            m_sm->remove_peer_from_network_index(existing_peer->network_id);
                            existing_peer->network_id = event.networkId;
                            m_sm->add_peer_to_network_index(event.peerId, event.networkId);

                            // Keep peer context's endpoint in sync for debouncing/reconnect logic.
                            auto ctx_it = m_sm->m_peer_contexts.find(event.peerId);
                            if (ctx_it != m_sm->m_peer_contexts.end()) {
                                ctx_it->second.network_id = event.networkId;
                            }

                            // If we're currently CONNECTING to a different endpoint, immediately attempt the
                            // updated endpoint.
                            if (prior_state == PeerState::CONNECTING && !prior_connect_target.empty() && prior_connect_target != event.networkId) {
                                LOG_INFO("SM: Endpoint changed while CONNECTING for " + event.peerId + ": " + prior_connect_target + " -> " + event.networkId + " (retrying connect)");
                                // Endpoint changed: clear backoff so the new attempt is not delayed.
                                PeerReconnectPolicy::getInstance().reset_peer_stats(event.peerId);
                                m_sm->pushEvent(ConnectToPeerEvent{event.peerId});
                            }
                        } else {
                            LOG_INFO("SM: Keeping existing connectable network_id for peer " + event.peerId +
                                     " (current=" + existing_peer->network_id + ", advertised=" + event.networkId + ")");
                        }
                    }
                }

                // Keep UI-visible endpoint info consistent with what we learned most recently.
                existing_peer->ip = endpoint.ip;
                existing_peer->port = endpoint.port;
                LOG_DEBUG("SM: Updated last_seen for existing peer: " + event.peerId);

                // If the peer was previously marked FAILED/DISCONNECTED (common after abrupt remote kill),
                // discovery should resurrect the FSM so outbound connects are allowed again.
                auto ctx_it = m_sm->m_peer_contexts.find(event.peerId);
                if (ctx_it != m_sm->m_peer_contexts.end()) {
                    const PeerState st = ctx_it->second.state;
                    if (st == PeerState::FAILED || st == PeerState::DISCONNECTED || st == PeerState::UNKNOWN) {
                        push_fsm_discovered = true;
                    }
                } else {
                    // No FSM context yet; ensure one exists and gets a DISCOVERED event.
                    m_sm->m_peer_contexts[event.peerId] = PeerContext{event.peerId, existing_peer->network_id};
                    push_fsm_discovered = true;
                }

                // Snapshot for persistence
                persist = true;
                persist_peer_id = existing_peer->id;
                // Persist the latest advertised endpoint (preferred for reconnect). If it's not a real
                // ip:port, fall back to the active network_id.
                if (!existing_peer->advertised_network_id.empty() && existing_peer->advertised_network_id.find(':') != std::string::npos) {
                    persist_network_id = existing_peer->advertised_network_id;
                } else {
                    persist_network_id = existing_peer->network_id;
                }
                persist_ip = existing_peer->ip;
                persist_port = existing_peer->port;
                persist_last_seen_ms = system_now_ms();
                persist_last_discovery_ms = persist_last_seen_ms;
                // Existing peer handled; return after best-effort persistence outside the lock.
            }
        } // Lock released

        if (push_fsm_discovered) {
            m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::DISCOVERED});
        }

        if (persist) {
            if (m_sm->m_local_peer_db && m_sm->m_local_peer_db->is_open()) {
                m_sm->m_local_peer_db->upsert_peer(
                    persist_peer_id,
                    persist_network_id,
                    persist_ip,
                    persist_port,
                    isConnectable(persist_ip, persist_port),
                    persist_last_seen_ms,
                    persist_last_discovery_ms);
            }
            return;
        }

        // Check for stale peer with same network_id (e.g. peer restarted with new ID)
        std::string stale_peer_id;
        {
            std::lock_guard<std::mutex> lock(m_sm->m_network_index_mutex);
            auto it = m_sm->m_network_id_to_peer_id.find(event.networkId);
            if (it != m_sm->m_network_id_to_peer_id.end()) {
                if (it->second != event.peerId) {
                    stale_peer_id = it->second;
                }
            }
        }

        if (!stale_peer_id.empty()) {
            LOG_INFO("SM: Found stale peer " + stale_peer_id + " on network " + event.networkId + ". Removing it.");
            m_sm->remove_peer_by_id(stale_peer_id);
        }
        
        LOG_INFO("SM: Discovered new peer: " + event.peerId);
        Peer new_peer;
        new_peer.id = event.peerId;
        new_peer.network_id = event.networkId;
        new_peer.advertised_network_id = event.networkId;
        new_peer.ip = endpoint.ip;
        new_peer.port = endpoint.port;
        new_peer.connected = false;
        new_peer.last_seen = now;
        new_peer.last_discovery_seen = now;
        new_peer.latency = -1;
        new_peer.tier = (m_sm->m_peer_tier_manager) ? m_sm->m_peer_tier_manager->get_peer_tier(event.peerId) : PeerTier::TIER_1;
        
        // SCOPE: Lock to add peer and create its context
        {
            std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
            m_sm->m_peers[event.peerId] = new_peer;
            m_sm->add_peer_to_network_index(event.peerId, new_peer.network_id);
            
            // Create FSM context for the new peer
            m_sm->m_peer_contexts[event.peerId] = PeerContext{event.peerId, event.networkId};
        } // Lock released
        
        m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::DISCOVERED});
        m_sm->notifyPeerUpdate();

        // Best-effort persistence
        if (m_sm->m_local_peer_db && m_sm->m_local_peer_db->is_open()) {
            const int64_t ts = system_now_ms();
            m_sm->m_local_peer_db->upsert_peer(
                new_peer.id,
                new_peer.network_id,
                new_peer.ip,
                new_peer.port,
                isConnectable(new_peer.ip, new_peer.port),
                ts,
                ts);
        }
    }

    void PeerLifecycleManager::handleConnectToPeer(const ConnectToPeerEvent& event) {
        // Shutdown guard - early return if shutting down
        if (m_sm->m_shutting_down.load(std::memory_order_acquire)) {
            return;
        }

        const auto now = std::chrono::steady_clock::now();

        std::string network_id;
        bool already_connected = false;
        std::chrono::steady_clock::time_point peer_last_seen{};
        std::chrono::steady_clock::time_point peer_last_discovery{};

        // Snapshot FSM state for connect debouncing.
        PeerState ctx_state = PeerState::UNKNOWN;
        std::chrono::steady_clock::time_point ctx_last_change{};
        std::string ctx_network_id;
        std::chrono::steady_clock::time_point ctx_last_connect_attempt{};
        std::string ctx_last_connect_target;
        // SCOPE: Brief lock to find peer
        {
            std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
            Peer* peer = m_sm->find_peer_by_id(event.peerId);
            if (!peer) {
                // Allow outbound connects by peer_id before discovery/signaling has provided an endpoint.
                // This is required for flows like proxy gateway auto-connect and signaling-based
                // CONNECT_REQUEST bootstrapping.
                LOG_INFO("SM: connectToPeer for unknown peer, creating placeholder: " + event.peerId);

                Peer placeholder;
                placeholder.id = event.peerId;
                placeholder.network_id.clear();
                placeholder.advertised_network_id.clear();
                placeholder.ip.clear();
                placeholder.port = 0;
                placeholder.connected = false;
                placeholder.last_seen = now;
                placeholder.last_discovery_seen = now;
                placeholder.latency = -1;
                placeholder.tier = (m_sm->m_peer_tier_manager)
                    ? m_sm->m_peer_tier_manager->get_peer_tier(event.peerId)
                    : PeerTier::TIER_1;

                m_sm->m_peers[event.peerId] = placeholder;

                // Ensure the peer has a context so the FSM can progress.
                // Mark as DISCOVERED since we have a peer id but may not yet have an endpoint.
                PeerContext ctx{event.peerId, std::string{}};
                ctx.state = PeerState::DISCOVERED;
                m_sm->m_peer_contexts[event.peerId] = std::move(ctx);

                peer = m_sm->find_peer_by_id(event.peerId);
            }

            if (!peer) {
                LOG_WARN("SM: Failed to create placeholder peer for: " + event.peerId);
                return;
            }

            // Use the active endpoint when we're currently connected.
            // Otherwise, prefer the latest advertised endpoint (signaling/discovery) so
            // reconnect after restart/network change uses the freshest mapping.
            if (peer->connected) {
                network_id = peer->network_id;
            } else if (!peer->advertised_network_id.empty()) {
                network_id = peer->advertised_network_id;
            } else {
                network_id = peer->network_id;
            }

            // If we are NOT currently connected and we're about to try a different target endpoint,
            // update the active endpoint now so future sends/heartbeats route correctly once the
            // connect succeeds.
            if (!peer->connected && !network_id.empty() && peer->network_id != network_id) {
                if (!peer->network_id.empty()) {
                    m_sm->remove_peer_from_network_index(peer->network_id);
                }
                peer->network_id = network_id;
                m_sm->add_peer_to_network_index(event.peerId, peer->network_id);

                const auto ep = parseNetworkId(peer->network_id);
                if (!ep.ip.empty() && ep.port > 0 && ep.port <= 65535 && ep.ip.find(':') == std::string::npos) {
                    peer->ip = ep.ip;
                    peer->port = ep.port;
                }

                auto ctx_it2 = m_sm->m_peer_contexts.find(event.peerId);
                if (ctx_it2 != m_sm->m_peer_contexts.end()) {
                    ctx_it2->second.network_id = peer->network_id;
                }
            }
            already_connected = peer->connected;
            peer_last_seen = peer->last_seen;
            peer_last_discovery = peer->last_discovery_seen;

            auto ctx_it = m_sm->m_peer_contexts.find(event.peerId);
            if (ctx_it != m_sm->m_peer_contexts.end()) {
                ctx_state = ctx_it->second.state;
                ctx_last_change = ctx_it->second.last_state_change;
                ctx_network_id = ctx_it->second.network_id;
                ctx_last_connect_attempt = ctx_it->second.last_connect_attempt;
                ctx_last_connect_target = ctx_it->second.last_connect_target_network_id;
            }
        } // Lock released

        // Debounce repeated connect requests while a connect attempt is already in progress.
        // IMPORTANT: Do not debounce when the target endpoint changes (e.g., discovery provides a LAN
        // endpoint while we're still CONNECTING to a WAN/signaling endpoint). In that case we want to
        // immediately attempt the new endpoint.
        if (ctx_state == PeerState::CONNECTING && ctx_last_connect_target == network_id) {
            const auto elapsed = now - ctx_last_connect_attempt;
            if (elapsed < std::chrono::milliseconds(1500)) {
                LOG_INFO("SM: ConnectToPeer debounced for " + event.peerId + " (already CONNECTING to " + network_id + ")");
                return;
            }
        }

        // Per-peer reconnect policy gating:
        // - Prevent hot "connect forever" loops during network flaps / stale endpoints.
        // - Still allow an immediate retry when discovery upgrades us to a private/LAN endpoint
        //   while we were CONNECTING to a WAN endpoint (this is the key LAN reliability path).
        {
            PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
            policy.track_peer(event.peerId);

            bool bypass_policy = false;
            if (ctx_state == PeerState::CONNECTING && !ctx_last_connect_target.empty() && ctx_last_connect_target != network_id) {
                const auto ep = parseNetworkId(network_id);
                if (isPrivateIpv4(ep.ip) && ep.port > 0) {
                    bypass_policy = true;
                }
            }

            if (!bypass_policy && !policy.should_reconnect_now(event.peerId)) {
                auto strat = policy.get_retry_strategy(event.peerId);
                LOG_INFO("SM: ConnectToPeer suppressed by reconnect policy for " + event.peerId +
                         " (backoff_ms=" + std::to_string(strat.backoff_ms) +
                         ", should_retry=" + std::string(strat.should_retry ? "true" : "false") + ")");
                Telemetry::getInstance().inc_counter("connect_suppressed_total");
                return;
            }
        }

        // Record this connect attempt target (used by the debouncer and endpoint-update recovery).
        {
            std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
            auto ctx_it = m_sm->m_peer_contexts.find(event.peerId);
            if (ctx_it != m_sm->m_peer_contexts.end()) {
                ctx_it->second.last_connect_attempt = now;
                ctx_it->second.last_connect_target_network_id = network_id;
            }
        }

        // If we're already connected, do not re-send CONTROL_CONNECT.
        // The CLI/test harness may call `connect` repeatedly; re-sending CONTROL_CONNECT can
        // force re-handshakes and invalidate Noise sessions while application data is batched.
        if (already_connected) {
            const auto silent_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - peer_last_seen).count();
            const auto discovery_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - peer_last_discovery).count();

            // If discovery is fresh but authenticated/control traffic is stale, assume a restarted peer
            // (new Noise keys) and force a reconnect. This avoids the "stuck connected" state where
            // we never resend CONTROL_CONNECT and handshake never completes.
            const int heartbeat_interval_sec = ConfigManager::getInstance().getHeartbeatIntervalSec();
            const int restart_suspected_ms = std::max(8000, heartbeat_interval_sec * 2 * 1000);
            const int discovery_recent_ms = 5000;

            const bool restart_suspected = (discovery_ms >= 0 && discovery_ms < discovery_recent_ms && silent_ms > restart_suspected_ms);
            if (!restart_suspected) {
                LOG_INFO("SM: Already connected to peer: " + event.peerId + ", network_id=" + network_id + " - skipping CONTROL_CONNECT");
                m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::CONNECT_SUCCESS});
#if HAVE_NOISE_PROTOCOL
                if (m_sm->m_use_noise_protocol && m_sm->shouldInitiateNoiseHandshake(event.peerId)) {
                    bool ready = false;
                    if (m_sm->m_secure_session_manager) {
                        std::lock_guard<std::mutex> lock(m_sm->m_secure_session_mutex);
                        ready = m_sm->m_secure_session_manager->is_session_ready(event.peerId);
                    }
                    if (!ready) {
                        m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::HANDSHAKE_REQUIRED});
                    }
                }
#endif
                return;
            }

            LOG_WARN("SM: Peer appears CONNECTED but session is stale (silent_ms=" + std::to_string(silent_ms) +
                     ", discovery_ms=" + std::to_string(discovery_ms) + ") - forcing reconnect for " + event.peerId);

            // Drive cleanup (removes READY Noise session, clears state).
            m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::DISCONNECT_DETECTED});
            {
                std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                Peer* p = m_sm->find_peer_by_id(event.peerId);
                if (p) {
                    p->connected = false;
                    // Keep last_seen as-is (represents authenticated traffic). Do not overwrite it here.
                }
            }
            // Fall through into normal connect attempt (will send CONTROL_CONNECT).
        }

        LOG_INFO("SM: Attempting to connect to peer: " + event.peerId + ", network_id=" + network_id + ", comms_mode=" + m_sm->m_comms_mode);

        const auto endpoint = parseNetworkId(network_id);
        if (endpoint.ip.empty() || endpoint.port <= 0) {
            // This commonly happens for signaling-discovered peers before they've published their
            // endpoint (network_id) via UPDATE. In that case, don't fail the connect attempt.
            // Instead, ask the remote peer to initiate a reciprocal connect to OUR published
            // endpoint, which is enough to establish the session.
            LOG_WARN("SM: Invalid network_id (expected ip:port): " + network_id + " (will try signaling CONNECT_REQUEST)");

            std::string my_network_id;
            {
                std::lock_guard<std::mutex> lock(m_sm->m_signaling_update_mutex);
                my_network_id = m_sm->m_pending_signaling_network_id;
            }

            if (!my_network_id.empty() && m_sm->m_signaling_client &&
                m_sm->m_signaling_registered.load(std::memory_order_acquire)) {
                const std::string payload = "CONNECT_REQUEST|" + my_network_id + "|" + m_sm->m_comms_mode;
                m_sm->m_signaling_client->sendSignal(event.peerId, payload);
                LOG_INFO("SM: Sent CONNECT_REQUEST via signaling to " + event.peerId + " (" + my_network_id + ")");
            } else {
                LOG_WARN("SM: Cannot send CONNECT_REQUEST (signaling not ready or local network_id unknown)");
            }

            m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::CONNECT_REQUESTED});
            return;
        }

        // Current transport stack is IPv4-only (AF_INET). If we see an IPv6 literal, fail fast with a clear log.
        if (endpoint.ip.find(':') != std::string::npos) {
            LOG_WARN("SM: Refusing to connect to IPv6 endpoint (IPv4-only transport): " + endpoint.ip + ":" + std::to_string(endpoint.port));
            m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::CONNECT_REQUESTED});
            m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::CONNECT_FAILED});
            return;
        }

        // Best-effort: if this looks like a public endpoint, ask the remote peer to initiate a
        // reciprocal connect as well (helps NAT traversal on restricted NATs).
        if (m_sm->m_comms_mode != "TCP" && !isPrivateIpv4(endpoint.ip)) {
            std::string my_network_id;
            {
                std::lock_guard<std::mutex> lock(m_sm->m_signaling_update_mutex);
                my_network_id = m_sm->m_pending_signaling_network_id;
            }
            if (!my_network_id.empty() && m_sm->m_signaling_client &&
                m_sm->m_signaling_registered.load(std::memory_order_acquire)) {
                // NOTE: payload must be JSON-string-safe (SignalingClient does not escape quotes).
                const std::string payload = "CONNECT_REQUEST|" + my_network_id + "|" + m_sm->m_comms_mode;
                m_sm->m_signaling_client->sendSignal(event.peerId, payload);
                LOG_INFO("SM: Sent CONNECT_REQUEST via signaling to " + event.peerId + " (" + my_network_id + ")");
            }

            // Also kick off STUN-style hole punching to open up mappings before CONTROL_CONNECT.
            NATTraversal& nat = NATTraversal::getInstance();
            PeerAddress p;
            p.peer_id = event.peerId;
            p.network_id = "wan";
            p.external_ip = endpoint.ip;
            p.external_port = static_cast<uint16_t>(endpoint.port);
            p.discovered_at_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            nat.registerPeer(p);
            const bool scheduled = nat.performHolePunching(event.peerId);
            LOG_INFO("SM: NAT hole-punch scheduled for " + event.peerId + " -> " + endpoint.ip + ":" + std::to_string(endpoint.port) +
                     " (scheduled=" + std::string(scheduled ? "true" : "false") + ")");
        }
        
        bool connection_success = false;
        
        // Defer the actual connection logic to the appropriate connection manager
        if (m_sm->m_comms_mode == "TCP") {
            connection_success = m_sm->m_tcpConnectionManager->connectToPeer(endpoint.ip, endpoint.port);
        } else {
            // Handle UDP/QUIC connection
            LOG_INFO("SM: Handling UDP/QUIC connection for " + network_id);
            if (m_sm->m_udpConnectionManager) {
                LOG_INFO("SM: Calling m_udpConnectionManager->connectToPeer(" + endpoint.ip + ", " + std::to_string(endpoint.port) + ")");
                connection_success = m_sm->m_udpConnectionManager->connectToPeer(endpoint.ip, endpoint.port);
                LOG_INFO("SM: connectToPeer returned " + std::string(connection_success ? "true" : "false"));
            } else {
                LOG_WARN("SM: UDP connection manager is null");
                connection_success = false;
            }
        }

        // Generate FSM events based on connection result
        m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::CONNECT_REQUESTED});
        
        if (!connection_success) {
            LOG_WARN("SM: Connection attempt failed immediately, generating CONNECT_FAILED event");
            m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::CONNECT_FAILED});
        } else {
            // For both TCP and UDP/QUIC, send the initial CONNECT message after successful connection
            LOG_INFO("SM: Sending initial CONTROL_CONNECT message to " + event.peerId);
            
            std::string payload = m_sm->m_localPeerId;
#if HAVE_NOISE_PROTOCOL
            if (m_sm->m_use_noise_protocol && m_sm->m_noise_key_store) {
                auto pk = m_sm->m_noise_key_store->get_local_static_public_key();
                std::string pk_hex;
                const char* hex_chars = "0123456789abcdef";
                for (uint8_t b : pk) {
                    pk_hex.push_back(hex_chars[b >> 4]);
                    pk_hex.push_back(hex_chars[b & 0x0F]);
                }
                payload += "|" + pk_hex;
            }
#endif
            std::string connect_msg = wire::encode_message(MessageType::CONTROL_CONNECT, payload);
            m_sm->send_message_to_peer(network_id, connect_msg);
        }
    }
}
