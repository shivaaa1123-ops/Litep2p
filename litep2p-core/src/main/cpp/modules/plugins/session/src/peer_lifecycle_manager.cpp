#include "peer_lifecycle_manager.h"
#include "session_manager_p.h"
#include "device_utils.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include "config_manager.h"
#include "telemetry.h"
#include "../../routing/include/peer_reconnect_policy.h"
#include "../../discovery/include/broadcast_discovery_manager.h"
#include "../../discovery/include/discovery.h"

#include <chrono>

namespace {
    struct NetworkEndpoint {
        std::string ip;
        int port = -1;
    };

    bool isPrivateIpv4(const std::string& ip) {
        // IPv6: link-local (fe80::/10), unique-local (fc00::/7) and loopback
        // are private; global addresses are public.
        if (is_ipv6_literal(ip)) {
            struct in6_addr a;
            if (inet_pton(AF_INET6, ip.c_str(), &a) != 1) return true; // malformed
            if (IN6_IS_ADDR_LOOPBACK(&a)) return true;
            if ((a.s6_addr[0] == 0xFE) && ((a.s6_addr[1] & 0xC0) == 0x80)) return true; // fe80::/10
            if ((a.s6_addr[0] & 0xFE) == 0xFC) return true; // fc00::/7
            return false; // global IPv6
        }

        // IPv4: RFC1918 + loopback + link-local.
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

    bool isLoopbackIpv4(const std::string& ip) {
        if (is_ipv6_literal(ip)) {
            struct in6_addr a;
            if (inet_pton(AF_INET6, ip.c_str(), &a) == 1) return IN6_IS_ADDR_LOOPBACK(&a);
            return false;
        }
        return ip.rfind("127.", 0) == 0;
    }

    NetworkEndpoint parseNetworkId(const std::string& network_id) {
        // Delegate to the shared IPv6-aware parser ("a.b.c.d:port" / "[v6]:port").
        NetworkEndpoint endpoint;
        std::string host;
        uint16_t port = 0;
        if (!parse_network_id(network_id, host, port)) {
            return endpoint;
        }
        endpoint.ip = host;
        endpoint.port = static_cast<int>(port);
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

        // Validate peer IDs to reject phantom/malformed entries.
        // Returns false for IDs that look like error strings, reserved words, or are too short.
        bool isValidPeerId(const std::string& peer_id) {
            if (peer_id.empty()) return false;
            if (peer_id.length() < 3) return false;  // Too short to be meaningful
            if (peer_id.length() > 128) return false; // Unreasonably long
            
            // Reject common error/sentinel strings that can appear due to parsing bugs
            static const std::vector<std::string> invalid_peer_ids = {
                "TIMEOUT", "timeout", "ERROR", "error", "NULL", "null",
                "undefined", "UNDEFINED", "none", "NONE", "unknown", "UNKNOWN",
                "invalid", "INVALID", "<null>", "<error>"
            };
            for (const auto& invalid : invalid_peer_ids) {
                if (peer_id == invalid) {
                    return false;
                }
            }
            
            // Peer ID should contain only printable ASCII characters
            for (char c : peer_id) {
                if (c < 32 || c > 126) {
                    return false;
                }
            }
            
            return true;
        }
        
        // Build CONNECT_REQUEST payload with optional LAN IP
        // Format: "CONNECT_REQUEST|<wan_network_id>|<comms_mode>[|<lan_ip>|<lan_port>]"
        // The LAN fields are optional for backward compatibility
        std::string buildConnectRequestPayload(const std::string& wan_network_id, 
                                                const std::string& comms_mode,
                                                int connection_port) {
            std::string payload = "CONNECT_REQUEST|" + wan_network_id + "|" + comms_mode;
            
            // Try to get local LAN IP to include in the payload
            Discovery* discovery = getGlobalDiscoveryInstance();
            if (discovery) {
                std::string lan_ip = discovery->getLocalLanIP();
                if (!lan_ip.empty() && connection_port > 0) {
                    payload += "|" + lan_ip + "|" + std::to_string(connection_port);
                }
            }
            
            return payload;
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
            // Lock order enforced: peers -> network index
            SessionManager::Impl::PeersThenNetworkIndexLock guard(*m_sm);
            const Peer* peer = m_sm->find_peer_by_network_id_locked_(event.network_id);
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

        // Private (LAN) endpoints are only reachable when we're actually on WiFi.
        // During LTE/cellular phases, adopting a 192.168.x.x network_id causes us to
        // send CONTROL_CONNECT/handshake traffic into the void, leading to repeated
        // handshaking watchdog timeouts.
        const bool allow_private_endpoints = m_sm->m_is_wifi.load(std::memory_order_acquire);
        
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

        bool should_unregister_nat = false;
        bool should_trigger_connect = false;

        {
            // Lock order enforced: peers -> network index
            SessionManager::Impl::PeersThenNetworkIndexLock guard(*m_sm);
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

                // Keep the latest advertised endpoint up to date.
                // IMPORTANT: Do not overwrite a known public (WAN) endpoint with a private (LAN)
                // endpoint. We need the WAN endpoint to reconnect while on cellular.
                // We still allow adopting a private advertised endpoint if we *don't* yet have
                // a connectable public endpoint.
                {
                    const bool incoming_is_private = isPrivateIpv4(endpoint.ip) && endpoint.port > 0;
                    const auto adv_ep = parseNetworkId(existing_peer->advertised_network_id);
                    const bool adv_is_ipv6_literal = (!adv_ep.ip.empty() && adv_ep.ip.find(':') != std::string::npos);
                    const bool adv_connectable = (!adv_ep.ip.empty() && !adv_is_ipv6_literal && adv_ep.port > 0 && adv_ep.port <= 65535);
                    const bool adv_is_private = adv_connectable && isPrivateIpv4(adv_ep.ip);
                    const bool adv_is_public_connectable = adv_connectable && !adv_is_private;

                    // Never overwrite a real ip:port with a placeholder (e.g., "signaling-<peer>").
                    const bool adv_is_placeholder = (!existing_peer->advertised_network_id.empty() && existing_peer->advertised_network_id.find(':') == std::string::npos);

                    if (!incoming_connectable) {
                        // Keep whatever we already have.
                    } else if (!incoming_is_private) {
                        // Public endpoint: always adopt.
                        existing_peer->advertised_network_id = event.networkId;
                    } else {
                        // Private endpoint: only adopt if we don't already have a public endpoint.
                        if (!adv_is_public_connectable || adv_is_placeholder || existing_peer->advertised_network_id.empty()) {
                            existing_peer->advertised_network_id = event.networkId;
                        }
                    }
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
                    const bool is_ephemeral = (m_sm->m_ephemeral_to_advertised_port_map.find(existing_peer->network_id) != m_sm->m_ephemeral_to_advertised_port_map.end());

                    const auto new_ep = parseNetworkId(event.networkId);
                    const bool new_is_private = isPrivateIpv4(new_ep.ip) && new_ep.port > 0;
                    
                    // Check if current endpoint is a public (WAN) IP
                    const auto cur_ep = parseNetworkId(existing_peer->network_id);
                    const bool cur_is_public = !cur_ep.ip.empty() && cur_ep.port > 0 && 
                                               !isPrivateIpv4(cur_ep.ip) && !isLoopbackIpv4(cur_ep.ip);

                    // IMPORTANT:
                    // During reconnect races and network flaps, we can accidentally end up "CONNECTING"
                    // to a public/STUN endpoint (WAN) that is not reachable from the same LAN (no NAT hairpin).
                    // If discovery provides a private IPv4 endpoint while we're CONNECTING, prefer it even if
                    // the currently stored endpoint is tagged as "ephemeral".
                    //
                    // EXTENDED: Also upgrade when current endpoint is a WAN IP and new is LAN IP.
                    // This handles the common bootstrap race where PEER_JOINED arrives with WAN IP first,
                    // we start connecting, then LAN_IP_UPDATE arrives with LAN IP. Without this, the
                    // initial handshake would complete over WAN even when both peers are on the same LAN.
                    //
                    // This is safe because:
                    // - We only do it for NOT-connected peers (CONNECTING state)
                    // - We only do it when the new endpoint is a valid private IPv4 ip:port
                    // - It unblocks the common "LTE->WiFi" or "WAN->LAN" recovery path.
                    // - It also enables LAN-preferred initial connections during bootstrap.
                    // EXTENDED (restart recovery): apply the LAN upgrade not only while
                    // CONNECTING but for ANY non-connected state (DEGRADED, DISCONNECTED,
                    // FAILED). After a full fleet restart the stored active endpoint can be
                    // the WAN/STUN IP from the previous session ("advertised endpoint for
                    // future reconnect"), which is unreachable from the same LAN (no NAT
                    // hairpin). A fresh LAN broadcast is then the authoritative, cheap path
                    // back — without this, reconnect attempts keep dialing the WAN IP,
                    // accrue backoff, and get suppressed by the reconnect policy, leaving
                    // the peer stuck until backoff expires (observed as "Android can't
                    // connect to the desktop after restart; resolves after repeated
                    // retries").
                    const bool peer_not_connected_state =
                        (prior_state == PeerState::CONNECTING ||
                         prior_state == PeerState::DEGRADED ||
                         prior_state == PeerState::DISCONNECTED ||
                         prior_state == PeerState::FAILED);
                    if ((is_ephemeral || cur_is_public) && new_is_private &&
                        peer_not_connected_state && allow_private_endpoints) {
                        bool collision = false;
                        std::string owner;
                        auto it2 = m_sm->m_network_id_to_peer_id.find(event.networkId);
                        if (it2 != m_sm->m_network_id_to_peer_id.end() && it2->second != event.peerId) {
                            collision = true;
                            owner = it2->second;
                        }

                        if (collision) {
                            LOG_WARN("SM: Refusing to upgrade CONNECTING peer " + event.peerId +
                                     " to colliding endpoint " + event.networkId +
                                     " (owned by " + owner + ")");
                            // Keep advertised endpoint for future reconnect; do not disturb current mapping.
                            PeerReconnectPolicy::getInstance().reset_peer_stats(event.peerId);
                        } else {
                        LOG_INFO("SM: Upgrading CONNECTING peer " + event.peerId +
                                 " from " + (cur_is_public ? "WAN" : "ephemeral") + " " + existing_peer->network_id + 
                                 " -> LAN " + event.networkId + " (LAN preferred during handshake)");

                        // Remove old index entry (even if ephemeral) and adopt the discovered stable endpoint.
                        m_sm->remove_peer_from_network_index_locked_(existing_peer->network_id);
                        existing_peer->network_id = event.networkId;
                        m_sm->add_peer_to_network_index_locked_(event.peerId, event.networkId);

                        // Keep context's endpoint in sync.
                        auto ctx_it2 = m_sm->m_peer_contexts.find(event.peerId);
                        if (ctx_it2 != m_sm->m_peer_contexts.end()) {
                            ctx_it2->second.network_id = event.networkId;
                        }

                        // Best-effort: cancel any WAN hole-punch work now that we have a direct LAN path.
                        should_unregister_nat = true;

                        // A fresh local endpoint invalidates whatever backoff was accrued
                        // against the unreachable WAN endpoint; otherwise the reconnect
                        // policy keeps suppressing subsequent discovery-driven connects.
                        PeerReconnectPolicy::getInstance().reset_peer_stats(event.peerId);

                        // Trigger a new connect attempt; debouncer will allow it because target changed.
                        should_trigger_connect = true;
                        }
                    } else if (is_ephemeral) {
                        LOG_INFO("SM: Ignoring network_id update for peer " + event.peerId +
                                 " because current ID " + existing_peer->network_id + " is a tracked ephemeral port.");
                    } else if (existing_peer->connected) {
                        // Peer is connected but discovery/signaling shows a different endpoint.
                        // Check if this is a WAN-to-LAN upgrade opportunity.
                        const auto cur_ep = parseNetworkId(existing_peer->network_id);
                        const bool cur_is_private = !cur_ep.ip.empty() && isPrivateIpv4(cur_ep.ip);
                        const bool incoming_is_public_connectable = incoming_connectable && !new_is_private;
                        
                        if (!cur_is_private && new_is_private && allow_private_endpoints) {
                            // UPGRADE: Currently connected via WAN, but discovered LAN endpoint.
                            // Switch to LAN immediately for faster, more reliable connection.
                            LOG_INFO("SM: UPGRADING connected peer " + event.peerId + 
                                     " from WAN (" + existing_peer->network_id + ") to LAN (" + 
                                     event.networkId + ") - LAN preferred when on same network");
                            
                            // Check for collisions
                            auto collision_it = m_sm->m_network_id_to_peer_id.find(event.networkId);
                            if (collision_it != m_sm->m_network_id_to_peer_id.end() && 
                                collision_it->second != event.peerId) {
                                LOG_WARN("SM: Cannot upgrade peer " + event.peerId + " to LAN endpoint " + 
                                         event.networkId + " - already mapped to " + collision_it->second);
                            } else {
                                // Remove old mapping and add new
                                m_sm->remove_peer_from_network_index_locked_(existing_peer->network_id);
                                existing_peer->network_id = event.networkId;
                                existing_peer->advertised_network_id = event.networkId;
                                existing_peer->ip = new_ep.ip;
                                existing_peer->port = new_ep.port;
                                m_sm->add_peer_to_network_index_locked_(event.peerId, event.networkId);
                                
                                // Update peer context
                                auto ctx_upgrade_it = m_sm->m_peer_contexts.find(event.peerId);
                                if (ctx_upgrade_it != m_sm->m_peer_contexts.end()) {
                                    ctx_upgrade_it->second.network_id = event.networkId;
                                }
                                
                                // Clear reconnect backoff
                                PeerReconnectPolicy::getInstance().reset_peer_stats(event.peerId);
                                should_unregister_nat = true;
                                LOG_INFO("SM: Peer " + event.peerId + " upgraded to LAN endpoint: " + event.networkId);
                            }
                        } else if (cur_is_private && !allow_private_endpoints && incoming_is_public_connectable) {
                            // DOWNGRADE: Currently connected via LAN but WiFi is OFF (e.g. switched to 4G).
                            // The LAN endpoint is no longer reachable. Switch to public immediately.
                            LOG_INFO("SM: DOWNGRADING connected peer " + event.peerId + 
                                     " from LAN (" + existing_peer->network_id + ") to WAN (" + 
                                     event.networkId + ") - WiFi OFF, LAN unreachable");
                            
                            // Check for collisions
                            auto collision_it = m_sm->m_network_id_to_peer_id.find(event.networkId);
                            if (collision_it != m_sm->m_network_id_to_peer_id.end() && 
                                collision_it->second != event.peerId) {
                                LOG_WARN("SM: Cannot downgrade peer " + event.peerId + " to WAN endpoint " + 
                                         event.networkId + " - already mapped to " + collision_it->second);
                            } else {
                                // Remove old LAN mapping and add new WAN
                                m_sm->remove_peer_from_network_index_locked_(existing_peer->network_id);
                                existing_peer->network_id = event.networkId;
                                existing_peer->advertised_network_id = event.networkId;
                                existing_peer->ip = new_ep.ip;
                                existing_peer->port = new_ep.port;
                                m_sm->add_peer_to_network_index_locked_(event.peerId, event.networkId);
                                
                                // Update peer context
                                auto ctx_it = m_sm->m_peer_contexts.find(event.peerId);
                                if (ctx_it != m_sm->m_peer_contexts.end()) {
                                    ctx_it->second.network_id = event.networkId;
                                }
                                
                                // Clear reconnect backoff - need fresh start with WAN endpoint
                                PeerReconnectPolicy::getInstance().reset_peer_stats(event.peerId);
                                // Mark for reconnect since current session is broken
                                should_trigger_connect = true;
                                LOG_INFO("SM: Peer " + event.peerId + " downgraded to WAN endpoint: " + event.networkId);
                            }
                        } else {
                            // Not a WAN-to-LAN upgrade or LAN-to-WAN downgrade - store for future reconnect
                            LOG_INFO("SM: Peer " + event.peerId + " is CONNECTED to " + existing_peer->network_id +
                                     " but advertised on " + event.networkId + " - storing advertised endpoint for future reconnect");

                            // FAST HANDOFF: Also add the new endpoint to the network index so we can
                            // receive packets from it. This is critical for network handoff scenarios
                            // where the remote peer's IP changes but they're trying to send us handshake
                            // messages from the new IP. Without this, we drop packets as "unknown peer".
                            if (incoming_connectable) {
                                auto existing_mapping = m_sm->m_network_id_to_peer_id.find(event.networkId);
                                if (existing_mapping == m_sm->m_network_id_to_peer_id.end() ||
                                    existing_mapping->second == event.peerId) {
                                    m_sm->add_peer_to_network_index_locked_(event.peerId, event.networkId);
                                    LOG_INFO("SM: Added secondary receive mapping for peer " + event.peerId +
                                             " from new endpoint " + event.networkId);
                                }
                            }

                            // Reset per-peer reconnect backoff so that when we do reconnect we don't get
                            // stuck behind stale backoff/circuit-breaker state caused by the old endpoint.
                            PeerReconnectPolicy::getInstance().reset_peer_stats(event.peerId);
                        }
                    } else {
                        // Not connected and not ephemeral - safe to update
                        // Only switch the active endpoint if the incoming endpoint is connectable or
                        // we currently don't have a connectable endpoint.
                        const auto cur_ep = parseNetworkId(existing_peer->network_id);
                        const bool cur_is_ipv6_literal = (cur_ep.ip.find(':') != std::string::npos);
                        const bool cur_connectable = !cur_ep.ip.empty() && !cur_is_ipv6_literal && cur_ep.port > 0 && cur_ep.port <= 65535;
                        const bool cur_is_private = cur_connectable && isPrivateIpv4(cur_ep.ip);
                        const bool incoming_is_public_connectable = incoming_connectable && !new_is_private;

                        if (incoming_connectable || !cur_connectable || existing_peer->network_id.empty()) {
                            if (new_is_private && !allow_private_endpoints && !isLoopbackIpv4(new_ep.ip)) {
                                LOG_INFO("SM: Ignoring private network_id update for peer " + event.peerId +
                                         " while not on WiFi: " + existing_peer->network_id + " -> " + event.networkId);
                                // Keep advertised endpoint (already updated above) so we can adopt it
                                // when WiFi becomes available.
                                PeerReconnectPolicy::getInstance().reset_peer_stats(event.peerId);
                            } else if (allow_private_endpoints && cur_is_private && incoming_is_public_connectable) {
                                // We're on WiFi and already have a valid private (LAN) endpoint for this peer.
                                // HOWEVER: If the peer was recently DISCONNECTED, DEGRADED, or is stuck CONNECTING,
                                // the cached LAN endpoint is likely stale (peer may have switched networks).
                                // In that case, prefer the new WAN endpoint for faster recovery.
                                const bool peer_is_recovering = (prior_state == PeerState::DISCONNECTED ||
                                                                 prior_state == PeerState::DEGRADED ||
                                                                 prior_state == PeerState::CONNECTING);
                                
                                if (peer_is_recovering) {
                                    // Same-NAT guard: if the advertised WAN endpoint's IP is our OWN
                                    // public IP, the two peers are behind the same router. Hairpinning
                                    // out to our own public IP then back is pointless for a LAN peer and,
                                    // worse, every CONNECTING->WAN switch re-runs the Noise handshake and
                                    // re-keys the session. Because the peer state is DISCONNECTED/DEGRADED/
                                    // CONNECTING, the next signaling update triggers this switch again ->
                                    // an endless reconnect+re-key storm that makes application messages
                                    // fail with "auth tag mismatch" (message encrypted on session gen N,
                                    // decrypted after a re-key on gen N+1). For same-NAT peers, keep the
                                    // (reachable) LAN endpoint instead.
                                    bool same_nat_wan = false;
                                    std::string my_public;
                                    {
                                        auto wan_ep = parseNetworkId(event.networkId);
                                        std::lock_guard<std::mutex> lock(m_sm->m_signaling_update_mutex);
                                        my_public = m_sm->m_pending_signaling_network_id;
                                        auto my_ep = parseNetworkId(my_public);
                                        if (!wan_ep.ip.empty() && !my_ep.ip.empty() && wan_ep.ip == my_ep.ip) {
                                            same_nat_wan = true;
                                        }
                                    }

                                    if (same_nat_wan) {
                                        LOG_INFO("SM: Peer " + event.peerId +
                                                 " advertised WAN endpoint " + event.networkId +
                                                 " equals our own public IP (" + my_public +
                                                 "); same-NAT, keeping LAN endpoint to avoid re-key storm");
                                        m_sm->add_peer_to_network_index_locked_(event.peerId, event.networkId);
                                    } else {
                                        // Peer was disconnected - LAN endpoint likely stale, switch to WAN
                                        LOG_INFO("SM: Peer " + event.peerId + " was DISCONNECTED/DEGRADED/CONNECTING, switching to new WAN endpoint: " +
                                                 existing_peer->network_id + " -> " + event.networkId);
                                    
                                    // Check for collisions
                                    auto collision_it = m_sm->m_network_id_to_peer_id.find(event.networkId);
                                    if (collision_it != m_sm->m_network_id_to_peer_id.end() && 
                                        collision_it->second != event.peerId) {
                                        LOG_WARN("SM: Cannot switch peer " + event.peerId + " to WAN endpoint " + 
                                                 event.networkId + " - already mapped to " + collision_it->second);
                                        // Fall back to keeping existing and adding secondary mapping
                                        m_sm->add_peer_to_network_index_locked_(event.peerId, event.networkId);
                                    } else {
                                        // Update to new WAN endpoint
                                        m_sm->remove_peer_from_network_index_locked_(existing_peer->network_id);
                                        existing_peer->network_id = event.networkId;
                                        m_sm->add_peer_to_network_index_locked_(event.peerId, event.networkId);
                                        
                                        auto ctx_it = m_sm->m_peer_contexts.find(event.peerId);
                                        if (ctx_it != m_sm->m_peer_contexts.end()) {
                                            ctx_it->second.network_id = event.networkId;
                                        }
                                        
                                        // Trigger reconnect with new endpoint
                                        should_trigger_connect = true;
                                    }
                                    PeerReconnectPolicy::getInstance().reset_peer_stats(event.peerId);
                                }
                                } else {
                                    // Peer is READY or has stable connection - keep LAN endpoint
                                    // Do NOT replace it with a public (WAN) endpoint from signaling; doing so can
                                    // prevent LAN handoff and cause NAT hairpin failures.
                                    LOG_INFO("SM: Keeping existing private LAN endpoint for peer " + event.peerId +
                                             " while on WiFi (current=" + existing_peer->network_id + ", advertised=" + event.networkId + ")");

                                    // Best-effort: accept incoming packets from the advertised public endpoint too,
                                    // without changing the active send endpoint.
                                    auto existing_mapping = m_sm->m_network_id_to_peer_id.find(event.networkId);
                                    if (existing_mapping == m_sm->m_network_id_to_peer_id.end() ||
                                        existing_mapping->second == event.peerId) {
                                        m_sm->add_peer_to_network_index_locked_(event.peerId, event.networkId);
                                        LOG_INFO("SM: Added secondary receive mapping for peer " + event.peerId +
                                                 " from advertised public endpoint " + event.networkId);
                                    }
                                    PeerReconnectPolicy::getInstance().reset_peer_stats(event.peerId);
                                }
                            } else if (!allow_private_endpoints && cur_is_private && incoming_is_public_connectable) {
                                // We're on 4G/mobile and already have a valid private (LAN) endpoint cached.
                                // Preserve the LAN endpoint so WiFi handoff can use it immediately when
                                // WiFi returns, instead of trying NAT hole punching through the public IP.
                                LOG_INFO("SM: Preserving cached LAN endpoint for peer " + event.peerId +
                                         " while on mobile (current=" + existing_peer->network_id + ", advertised=" + event.networkId + ")");

                                // Accept incoming packets from the advertised public endpoint for the
                                // current 4G session, without replacing the cached LAN endpoint.
                                auto existing_mapping = m_sm->m_network_id_to_peer_id.find(event.networkId);
                                if (existing_mapping == m_sm->m_network_id_to_peer_id.end() ||
                                    existing_mapping->second == event.peerId) {
                                    m_sm->add_peer_to_network_index_locked_(event.peerId, event.networkId);
                                    LOG_INFO("SM: Added secondary receive mapping for peer " + event.peerId +
                                             " from advertised public endpoint (while on mobile) " + event.networkId);
                                }
                                PeerReconnectPolicy::getInstance().reset_peer_stats(event.peerId);
                            } else {
                            bool collision = false;
                            std::string owner;
                            auto it2 = m_sm->m_network_id_to_peer_id.find(event.networkId);
                            if (it2 != m_sm->m_network_id_to_peer_id.end() && it2->second != event.peerId) {
                                collision = true;
                                owner = it2->second;
                            }

                            if (collision) {
                                LOG_WARN("SM: Ignoring network_id update for peer " + event.peerId +
                                         " to colliding endpoint " + event.networkId +
                                         " (already mapped to " + owner + ")");
                                // Keep the advertised endpoint (already stored above) for future diagnostics,
                                // but do not switch the active send endpoint or index mapping.
                                PeerReconnectPolicy::getInstance().reset_peer_stats(event.peerId);
                            } else {
                            LOG_INFO("SM: Updating network_id for peer " + event.peerId + ": " + existing_peer->network_id + " -> " + event.networkId);
                            m_sm->remove_peer_from_network_index_locked_(existing_peer->network_id);
                            existing_peer->network_id = event.networkId;
                            m_sm->add_peer_to_network_index_locked_(event.peerId, event.networkId);

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
                                should_trigger_connect = true;
                            }
                            }
                            }
                        } else {
                            LOG_INFO("SM: Keeping existing connectable network_id for peer " + event.peerId +
                                     " (current=" + existing_peer->network_id + ", advertised=" + event.networkId + ")");
                        }
                    }
                }

                // Keep UI-visible endpoint info consistent with the endpoint we will actually use.
                // IMPORTANT:
                // When we receive a colliding/invalid advertised endpoint, we may intentionally NOT
                // adopt it as the active network_id. In that case, do NOT overwrite ip/port with the
                // rejected endpoint (it makes the UI look like two peers share the same network_id).
                auto is_connectable_ipv4_ep = [](const NetworkEndpoint& ep) {
                    if (ep.ip.empty()) return false;
                    // Reject IPv6 literals (they contain ':').
                    if (ep.ip.find(':') != std::string::npos) return false;
                    return ep.port > 0 && ep.port <= 65535;
                };

                const auto active_ep = parseNetworkId(existing_peer->network_id);
                const auto adv_ep = parseNetworkId(existing_peer->advertised_network_id);

                if (is_connectable_ipv4_ep(active_ep)) {
                    existing_peer->ip = active_ep.ip;
                    existing_peer->port = active_ep.port;
                } else if (is_connectable_ipv4_ep(adv_ep)) {
                    existing_peer->ip = adv_ep.ip;
                    existing_peer->port = adv_ep.port;
                } else {
                    // Best-effort fallback (may be placeholder or malformed).
                    existing_peer->ip = endpoint.ip;
                    existing_peer->port = endpoint.port;
                }
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

        if (should_unregister_nat) {
            NATTraversal::getInstance().unregisterPeer(event.peerId);
        }

        if (should_trigger_connect) {
            m_sm->pushEvent(ConnectToPeerEvent{event.peerId});
        }

        if (push_fsm_discovered) {
            m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::DISCOVERED});
            
            // IMPORTANT: When resurrecting a FAILED/DISCONNECTED peer via discovery,
            // also trigger a connect attempt. Without this, the peer stays in DISCOVERED
            // state and never initiates reconnection after WiFi toggle or network handoff.
            // This is especially important for AP isolation scenarios where one side
            // (e.g., desktop) can't receive direct UDP from the other (e.g., Android).
            if (!should_trigger_connect) {
                LOG_INFO("SM: Triggering connect for resurrected peer: " + event.peerId);
                m_sm->pushEvent(ConnectToPeerEvent{event.peerId, false, "discovery_resurrection"});
            }
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
            
            // Notify BroadcastDiscoveryManager if this is a LAN discovery
            // This connects the Discovery UDP broadcast system with BroadcastDiscoveryManager
            if (allow_private_endpoints && isPrivateIpv4(endpoint.ip) && endpoint.port > 0) {
                if (m_sm->m_broadcast_discovery && m_sm->m_broadcast_discovery->is_running()) {
                    m_sm->m_broadcast_discovery->notify_peer_discovered(
                        event.peerId, endpoint.ip, endpoint.port);
                }
            }
            
            return;
        }

        // IMPORTANT:
        // Do NOT remove an existing peer solely because another peer announces the same network_id.
        // In the field, duplicate advertised endpoints can happen transiently (stale STUN results,
        // local listen-port being advertised as WAN port, or router port mapping churn).
        // Deleting the existing peer here can cascade into disconnects and inconsistent UI state.
        bool index_collision = false;
        std::string index_owner;
        if (incoming_connectable) {
            std::lock_guard<std::mutex> lock(m_sm->m_network_index_mutex);
            auto it = m_sm->m_network_id_to_peer_id.find(event.networkId);
            if (it != m_sm->m_network_id_to_peer_id.end() && it->second != event.peerId) {
                index_collision = true;
                index_owner = it->second;
            }
        }
        
        LOG_INFO("SM: Discovered new peer: " + event.peerId);
        Peer new_peer;
        new_peer.id = event.peerId;
        // IMPORTANT:
        // If the advertised endpoint collides with another peer's active mapping, do NOT adopt it
        // as the active send endpoint. Doing so would cause outbound CONTROL_CONNECT/PING to be sent
        // to an endpoint we already believe belongs to a different peer.
        // We still record it as `advertised_network_id` so that if the peer later publishes a
        // unique endpoint, or if the collision clears, we can connect.
        const bool incoming_private = isPrivateIpv4(endpoint.ip) && endpoint.port > 0;
        new_peer.network_id = (index_collision || (incoming_private && !allow_private_endpoints && !isLoopbackIpv4(endpoint.ip))) ? std::string{} : event.networkId;
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
            // Lock order enforced: peers -> network index
            SessionManager::Impl::PeersThenNetworkIndexLock guard(*m_sm);
            m_sm->m_peers[event.peerId] = new_peer;
            if (index_collision) {
                LOG_WARN("SM: Discovered peer " + event.peerId + " with colliding endpoint " + event.networkId +
                         " (already mapped to " + index_owner + "). Keeping both peers; deferring index update until we see authenticated traffic.");
            } else {
                m_sm->add_peer_to_network_index_locked_(event.peerId, new_peer.network_id);
            }
            
            // Create FSM context for the new peer
            m_sm->m_peer_contexts[event.peerId] = PeerContext{event.peerId, new_peer.network_id};
        } // Lock released
        
        m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::DISCOVERED});
        m_sm->notifyPeerUpdate();

        // Best-effort persistence
        if (m_sm->m_local_peer_db && m_sm->m_local_peer_db->is_open()) {
            const int64_t ts = system_now_ms();
            m_sm->m_local_peer_db->upsert_peer(
                new_peer.id,
                // Persist the best known reconnectable endpoint.
                (!new_peer.advertised_network_id.empty() && new_peer.advertised_network_id.find(':') != std::string::npos)
                    ? new_peer.advertised_network_id
                    : new_peer.network_id,
                new_peer.ip,
                new_peer.port,
                isConnectable(new_peer.ip, new_peer.port),
                ts,
                ts);
        }
        
        // Notify BroadcastDiscoveryManager if this is a LAN discovery
        // This connects the Discovery UDP broadcast system with BroadcastDiscoveryManager
        if (allow_private_endpoints && isPrivateIpv4(endpoint.ip) && endpoint.port > 0) {
            if (m_sm->m_broadcast_discovery && m_sm->m_broadcast_discovery->is_running()) {
                m_sm->m_broadcast_discovery->notify_peer_discovered(
                    event.peerId, endpoint.ip, endpoint.port);
            }
        }
    }

    void PeerLifecycleManager::handleConnectToPeer(const ConnectToPeerEvent& event) {
        // Shutdown guard - early return if shutting down
        if (m_sm->m_shutting_down.load(std::memory_order_acquire)) {
            return;
        }

        // Respect explicit user disconnects: internal/discovery-driven connect
        // attempts must not revive a peer the user disconnected. Only explicit
        // user_api connects (which clear the suppression before pushing) may
        // proceed. Direct callers that build ConnectToPeerEvent without a
        // user_api source are treated as internal.
        if (event.source.rfind("user_api", 0) != 0) {
            std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
            if (m_sm->m_user_disconnected_peers.count(event.peerId)) {
                LOG_DEBUG("SM: handleConnectToPeer suppressed for user-disconnected peer " +
                          event.peerId + " (source=" + (event.source.empty() ? "?" : event.source) + ")");
                return;
            }
        }

        // Private (LAN) endpoints are only reachable when we're on WiFi.
        const bool allow_private_endpoints = m_sm->m_is_wifi.load(std::memory_order_acquire);

        const auto now = std::chrono::steady_clock::now();

        std::string network_id;
        std::string desired_network_id;
        std::string current_network_id;
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
                // Validate peer_id before creating placeholder
                if (!isValidPeerId(event.peerId)) {
                    LOG_WARN("SM: Rejecting invalid/phantom peer ID: '" + event.peerId + "'");
                    Telemetry::getInstance().inc_counter("phantom_peer_rejected_total");
                    return;
                }
                
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
                desired_network_id = peer->network_id;
            } else {
                // When on WiFi, prefer the last known LAN endpoint (peer->network_id) if it's private.
                // When on cellular, prefer the advertised WAN endpoint.
                const auto net_ep = parseNetworkId(peer->network_id);
                const bool net_is_ipv6_literal = (!net_ep.ip.empty() && net_ep.ip.find(':') != std::string::npos);
                const bool net_connectable = (!net_ep.ip.empty() && !net_is_ipv6_literal && net_ep.port > 0 && net_ep.port <= 65535);
                const bool net_is_private = net_connectable && isPrivateIpv4(net_ep.ip);
                const bool net_is_loopback = net_connectable && isLoopbackIpv4(net_ep.ip);

                const auto adv_ep = parseNetworkId(peer->advertised_network_id);
                const bool adv_is_ipv6_literal = (!adv_ep.ip.empty() && adv_ep.ip.find(':') != std::string::npos);
                const bool adv_connectable = (!adv_ep.ip.empty() && !adv_is_ipv6_literal && adv_ep.port > 0 && adv_ep.port <= 65535);
                const bool adv_is_private = adv_connectable && isPrivateIpv4(adv_ep.ip);
                const bool adv_is_public_connectable = adv_connectable && !adv_is_private;

                // Unit-test/dev-only special-case: loopback is always reachable regardless of WiFi state.
                // Prefer it over an advertised public endpoint so endpoint-upgrade tests can succeed.
                if (net_is_loopback) {
                    desired_network_id = peer->network_id;
                } else if (adv_connectable && isLoopbackIpv4(adv_ep.ip)) {
                    desired_network_id = peer->advertised_network_id;
                } else

                if (allow_private_endpoints && net_is_private) {
                    desired_network_id = peer->network_id;
                } else if (!allow_private_endpoints && adv_is_public_connectable) {
                    desired_network_id = peer->advertised_network_id;
                } else if (!peer->advertised_network_id.empty()) {
                    desired_network_id = peer->advertised_network_id;
                } else {
                    desired_network_id = peer->network_id;
                }
            }

            current_network_id = peer->network_id;

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

        // Decide whether the desired target collides with a different peer.
        bool target_collides = false;
        std::string collision_owner;
        if (!already_connected && !desired_network_id.empty()) {
            const auto ep = parseNetworkId(desired_network_id);
            const bool is_ipv6_literal = (!ep.ip.empty() && ep.ip.find(':') != std::string::npos);
            const bool connectable = (!ep.ip.empty() && !is_ipv6_literal && ep.port > 0 && ep.port <= 65535);
            if (connectable) {
                std::lock_guard<std::mutex> lock(m_sm->m_network_index_mutex);
                auto it = m_sm->m_network_id_to_peer_id.find(desired_network_id);
                if (it != m_sm->m_network_id_to_peer_id.end() && it->second != event.peerId) {
                    target_collides = true;
                    collision_owner = it->second;
                }
            }
        }

        // If we are NOT currently connected and we're about to try a different target endpoint,
        // update the active endpoint now so future sends/heartbeats route correctly once the
        // connect succeeds.
        // NOTE: Never adopt a colliding endpoint as the active endpoint.
        {
            const auto desired_ep = parseNetworkId(desired_network_id);
            const bool desired_is_private = isPrivateIpv4(desired_ep.ip) && desired_ep.port > 0;
            if (!already_connected && !desired_network_id.empty() && current_network_id != desired_network_id && !target_collides &&
                !(desired_is_private && !allow_private_endpoints && !isLoopbackIpv4(desired_ep.ip))) {
            // Lock order enforced: peers -> network index
            SessionManager::Impl::PeersThenNetworkIndexLock guard(*m_sm);
            Peer* peer = m_sm->find_peer_by_id(event.peerId);
            if (peer) {
                if (!peer->network_id.empty()) {
                    m_sm->remove_peer_from_network_index_locked_(peer->network_id);
                }
                peer->network_id = desired_network_id;
                m_sm->add_peer_to_network_index_locked_(event.peerId, peer->network_id);

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
            }
        }

        // The network_id we will attempt to use for this connect (if any).
        network_id = desired_network_id;

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

        // If we're already connected, do not run reconnect-policy gating.
        // The CLI/test harness (and signaling bootstrap) may call `connectToPeer` repeatedly; these
        // calls must be idempotent and must NOT force a disconnect/reconnect cycle.
        //
        // Previously we attempted to infer a peer restart via "fresh discovery" + "silent control
        // traffic". In practice, discovery can be frequent even when the session is healthy (e.g.
        // idle peers, no app-level messages), which caused false DISCONNECT_DETECTED transitions and
        // made handoffs flaky under strict SLAs.
        //
        // IMPORTANT FIX: If the advertised endpoint has changed (e.g., WiFi->LTE network handoff),
        // we must NOT skip connection even if peer->connected is true. The old path is likely dead
        // and waiting for heartbeat timeout adds unnecessary latency. Force reconnection to the new
        // endpoint immediately.
        bool endpoint_changed = false;
        if (already_connected && !current_network_id.empty() && !desired_network_id.empty()) {
            // Check if the advertised endpoint differs from our current connected endpoint
            if (current_network_id != desired_network_id) {
                const auto desired_ep = parseNetworkId(desired_network_id);
                const bool desired_is_private = isPrivateIpv4(desired_ep.ip) && desired_ep.port > 0;
                if (desired_is_private && !allow_private_endpoints && !isLoopbackIpv4(desired_ep.ip)) {
                    LOG_INFO("SM: Endpoint changed to private for connected peer " + event.peerId +
                             " while not on WiFi (ignoring for now): " + current_network_id + " -> " + desired_network_id);
                } else {
                    endpoint_changed = true;
                    LOG_INFO("SM: Endpoint changed for connected peer " + event.peerId + 
                             ": " + current_network_id + " -> " + desired_network_id + 
                             " - forcing reconnection to new endpoint");
                }
            }
        }

        // Check for stale connection - if last_seen is too old, treat as not actually connected
        bool connection_is_stale = false;
        {
            std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
            Peer* peer = m_sm->find_peer_by_id(event.peerId);
            if (peer && peer->connected) {
                auto age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - peer->last_seen).count();
                // If we haven't heard from this peer in 10+ seconds but claim connected,
                // the connection is likely stale (e.g., after network change)
                if (age_ms > 10000) {
                    connection_is_stale = true;
                    LOG_INFO("SM: Peer " + event.peerId + " marked connected but last_seen " + 
                             std::to_string(age_ms) + "ms ago - treating as stale");
                    Telemetry::getInstance().inc_counter("stale_connection_detected_total");
                }
            }
        }
        
        if (already_connected && !endpoint_changed && !connection_is_stale) {
            // Even if we think we're connected, the peer sent us a CONNECT_REQUEST which
            // means THEY need to reconnect (likely their session was invalidated due to
            // network change). We should still send CONTROL_CONNECT to help them reconnect
            // on the new path, rather than waiting for our stale detection to kick in.
            LOG_INFO("SM: Already connected to peer: " + event.peerId + ", network_id=" + network_id + " - but peer sent CONNECT_REQUEST, sending CONTROL_CONNECT to help reconnect");
            
            // Send CONTROL_CONNECT to the peer's new endpoint
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
                payload += "|" + pk_hex + "|" + std::to_string(m_sm->m_local_boot_id);
            }
#endif
            std::string connect_msg = wire::encode_message(MessageType::CONTROL_CONNECT, payload);
            m_sm->send_message_to_peer(network_id, connect_msg);
            
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

        // If endpoint changed on a connected peer, we need to update the endpoint and clear the
        // old Noise session so a fresh handshake can occur on the new path.
        if (endpoint_changed) {
            // Update the peer's endpoint to the new one
            {
                SessionManager::Impl::PeersThenNetworkIndexLock guard(*m_sm);
                Peer* peer = m_sm->find_peer_by_id(event.peerId);
                if (peer) {
                    if (!peer->network_id.empty()) {
                        m_sm->remove_peer_from_network_index_locked_(peer->network_id);
                    }
                    peer->network_id = desired_network_id;
                    m_sm->add_peer_to_network_index_locked_(event.peerId, peer->network_id);

                    const auto ep = parseNetworkId(peer->network_id);
                    if (!ep.ip.empty() && ep.port > 0 && ep.port <= 65535 && ep.ip.find(':') == std::string::npos) {
                        peer->ip = ep.ip;
                        peer->port = ep.port;
                    }

                    // Mark as not connected so we go through the full connect flow
                    peer->connected = false;

                    auto ctx_it2 = m_sm->m_peer_contexts.find(event.peerId);
                    if (ctx_it2 != m_sm->m_peer_contexts.end()) {
                        ctx_it2->second.network_id = peer->network_id;
                        // Reset state to trigger fresh connection
                        ctx_it2->second.state = PeerState::DISCOVERED;
                    }
                }
            }

#if HAVE_NOISE_PROTOCOL
            // Clear the old Noise session so we do a fresh handshake on the new path
            if (m_sm->m_use_noise_protocol && m_sm->m_secure_session_manager) {
                std::lock_guard<std::mutex> lock(m_sm->m_secure_session_mutex);
                m_sm->m_secure_session_manager->remove_session(event.peerId);
                LOG_INFO("SM: Cleared Noise session for " + event.peerId + " after endpoint change");
            }
#endif
            // Update network_id for subsequent logic
            network_id = desired_network_id;
            already_connected = false;
        }

        // If the only endpoint we have for this peer collides with another peer, do not dial it.
        // Instead, request a reciprocal connect via signaling (best-effort) and wait for a unique
        // endpoint update from discovery/signaling.
        if (!already_connected && target_collides) {
            LOG_WARN("SM: Refusing to dial colliding endpoint for " + event.peerId + ": " + network_id +
                     " (owned by " + collision_owner + ") - will try signaling CONNECT_REQUEST");

            // Record this as a connect attempt target for debouncing.
            {
                std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                auto ctx_it = m_sm->m_peer_contexts.find(event.peerId);
                if (ctx_it != m_sm->m_peer_contexts.end()) {
                    ctx_it->second.last_connect_attempt = now;
                    ctx_it->second.last_connect_target_network_id = network_id;
                }
            }

            std::string my_network_id;
            {
                std::lock_guard<std::mutex> lock(m_sm->m_signaling_update_mutex);
                my_network_id = m_sm->m_pending_signaling_network_id;
            }

            if (!my_network_id.empty() && m_sm->m_signaling_client &&
                m_sm->m_signaling_registered.load(std::memory_order_acquire)) {
                const std::string payload = buildConnectRequestPayload(my_network_id, m_sm->m_comms_mode, m_sm->m_listen_port);
                m_sm->m_signaling_client->sendSignal(event.peerId, payload);
                LOG_INFO("SM: Sent CONNECT_REQUEST via signaling to " + event.peerId + " (" + my_network_id + ")");
            } else {
                LOG_WARN("SM: Cannot send CONNECT_REQUEST (signaling not ready or local network_id unknown)");
            }

            m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::CONNECT_REQUESTED});
            return;
        }

        // Per-peer reconnect policy gating:
        // - Prevent hot "connect forever" loops during network flaps / stale endpoints.
        // - Still allow an immediate retry when discovery upgrades us to a private/LAN endpoint
        //   while we were CONNECTING to a WAN endpoint (this is the key LAN reliability path).
        {
            PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
            policy.track_peer(event.peerId);

            bool bypass_policy = event.bypass_reconnect_policy;
            if (ctx_state == PeerState::CONNECTING && !ctx_last_connect_target.empty() && ctx_last_connect_target != network_id) {
                const auto ep = parseNetworkId(network_id);
                if (isPrivateIpv4(ep.ip) && ep.port > 0) {
                    bypass_policy = true;
                }
            }

            // If the peer is still DISCOVERED, allow the first ever connection attempt (no prior
            // backoff/circuit-breaker state). If the reconnect policy is actively suppressing
            // retries, we must NOT bypass (unit tests rely on suppression telemetry).
            if (ctx_state == PeerState::DISCOVERED && !bypass_policy) {
                const auto st = policy.get_peer_stats(event.peerId);
                const bool no_backoff = (st.consecutive_failures == 0 && st.next_retry_time_ms == 0 && st.circuit_breaker_until_ms == 0);
                if (no_backoff) {
                    bypass_policy = true;
                }
            }

            if (bypass_policy && event.bypass_reconnect_policy) {
                LOG_INFO("SM: ConnectToPeer bypassing reconnect policy for " + event.peerId +
                         (event.source.empty() ? std::string("") : (" (source=" + event.source + ")")));
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
                const std::string payload = buildConnectRequestPayload(my_network_id, m_sm->m_comms_mode, m_sm->m_listen_port);
                m_sm->m_signaling_client->sendSignal(event.peerId, payload);
                LOG_INFO("SM: Sent CONNECT_REQUEST via signaling to " + event.peerId + " (" + my_network_id + ")");
            } else {
                LOG_WARN("SM: Cannot send CONNECT_REQUEST (signaling not ready or local network_id unknown)");
            }

            m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::CONNECT_REQUESTED});
            return;
        }

        // If we're not on WiFi, refuse to dial private RFC1918 endpoints.
        // This prevents us from wasting the handshake window sending traffic to an unreachable LAN IP.
        if (isPrivateIpv4(endpoint.ip) && !allow_private_endpoints && !isLoopbackIpv4(endpoint.ip)) {
            LOG_WARN("SM: Refusing to connect to private endpoint while not on WiFi: " + endpoint.ip + ":" + std::to_string(endpoint.port) +
                     " (peer=" + event.peerId + ") - will try signaling CONNECT_REQUEST");

            std::string my_network_id;
            {
                std::lock_guard<std::mutex> lock(m_sm->m_signaling_update_mutex);
                my_network_id = m_sm->m_pending_signaling_network_id;
            }

            if (!my_network_id.empty() && m_sm->m_signaling_client &&
                m_sm->m_signaling_registered.load(std::memory_order_acquire)) {
                const std::string payload = buildConnectRequestPayload(my_network_id, m_sm->m_comms_mode, m_sm->m_listen_port);
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
                const std::string payload = buildConnectRequestPayload(my_network_id, m_sm->m_comms_mode, m_sm->m_listen_port);
                m_sm->m_signaling_client->sendSignal(event.peerId, payload);
                LOG_INFO("SM: Sent CONNECT_REQUEST via signaling to " + event.peerId + " (" + my_network_id + ")");
            }

            // Also kick off STUN-style hole punching to open up mappings before CONTROL_CONNECT.
            // This can be cleared by stop(); re-register defensively so punch scheduling is reliable.
            m_sm->ensure_nat_connection_manager_registered_();
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
        
        // Defer the actual connection logic to the appropriate connection manager.
        // Homogeneous mode always uses the single configured protocol; heterogeneous
        // mode uses the transport the peer connected on (or UDP for unknown peers).
        const std::string transport = m_sm->outbound_transport_for_peer(event.peerId);
        if (transport == "TCP") {
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
                payload += "|" + pk_hex + "|" + std::to_string(m_sm->m_local_boot_id);
            }
#endif
            std::string connect_msg = wire::encode_message(MessageType::CONTROL_CONNECT, payload);
            m_sm->send_message_to_peer(network_id, connect_msg);
        }
    }

    void PeerLifecycleManager::handleLanDiscoveryResult(const LanDiscoveryResultEvent& event) {
        // Validate the discovered LAN endpoint
        if (event.peerId.empty() || event.lanIp.empty() || event.lanPort <= 0 || event.lanPort > 65535) {
            LOG_WARN("SM: Invalid LAN discovery result: peer=" + event.peerId + 
                     " ip=" + event.lanIp + " port=" + std::to_string(event.lanPort));
            return;
        }
        
        // Validate this is actually a private/LAN IP
        if (!isPrivateIpv4(event.lanIp)) {
            LOG_WARN("SM: LAN discovery returned non-private IP for peer " + event.peerId + 
                     ": " + event.lanIp + " (ignoring)");
            return;
        }
        
        // Check if we're on WiFi - LAN endpoints are only reachable when on WiFi
        const bool allow_lan_endpoints = m_sm->m_is_wifi.load(std::memory_order_acquire);
        if (!allow_lan_endpoints) {
            LOG_INFO("SM: LAN discovery result for " + event.peerId + " (" + event.lanIp + ":" + 
                     std::to_string(event.lanPort) + ") ignored - not on WiFi");
            return;
        }
        
        const std::string lan_network_id = event.lanIp + ":" + std::to_string(event.lanPort);
        const auto now = std::chrono::steady_clock::now();
        const uint64_t now_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
        
        LOG_INFO("SM: LAN discovery result for peer " + event.peerId + ": " + lan_network_id + 
                 " (latency=" + std::to_string(event.latencyMs) + "ms, hops=" + std::to_string(event.hopCount) + ")");
        
        SessionManager::Impl::PeersThenNetworkIndexLock lock(*m_sm);
        
        Peer* existing_peer = m_sm->find_peer_by_id(event.peerId);
        if (!existing_peer) {
            // Peer not yet known - create a new peer entry with LAN endpoint
            LOG_INFO("SM: Creating new peer from LAN discovery: " + event.peerId + " at " + lan_network_id);
            
            Peer new_peer;
            new_peer.id = event.peerId;
            new_peer.ip = event.lanIp;
            new_peer.port = event.lanPort;
            new_peer.network_id = lan_network_id;
            new_peer.advertised_network_id = lan_network_id;
            new_peer.last_seen = now;
            new_peer.last_discovery_seen = now;
            new_peer.connected = false;
            new_peer.tier = PeerTier::TIER_1;
            
            // Add LAN endpoint candidate
            new_peer.update_endpoint_candidate(event.lanIp, event.lanPort, EndpointType::LAN, now_ms);
            
            m_sm->m_peers[event.peerId] = new_peer;
            m_sm->add_peer_to_network_index_locked_(event.peerId, lan_network_id);
            
            // Create peer context for FSM
            PeerContext ctx;
            ctx.peer_id = event.peerId;
            ctx.network_id = lan_network_id;
            ctx.state = PeerState::DISCOVERED;
            m_sm->m_peer_contexts[event.peerId] = ctx;
            
            LOG_INFO("[PeerFSM] NEW --(DISCOVERED via LAN)--> DISCOVERED peer=" + event.peerId);
            
            // Register with NAT traversal for potential hole punching (as LAN endpoint)
            NATTraversal& nat = NATTraversal::getInstance();
            PeerAddress p;
            p.peer_id = event.peerId;
            p.network_id = "lan";
            p.external_ip = event.lanIp;
            p.external_port = static_cast<uint16_t>(event.lanPort);
            p.discovered_at_ms = now_ms;
            nat.registerPeer(p);
            
            return;
        }
        
        // Peer exists - update with LAN endpoint
        const std::string old_network_id = existing_peer->network_id;
        const auto ctx_it = m_sm->m_peer_contexts.find(event.peerId);
        const PeerState current_state = (ctx_it != m_sm->m_peer_contexts.end()) ? ctx_it->second.state : PeerState::UNKNOWN;
        
        // Always add/update the LAN endpoint candidate
        existing_peer->update_endpoint_candidate(event.lanIp, event.lanPort, EndpointType::LAN, now_ms);
        existing_peer->last_discovery_seen = now;
        
        // Check if we should switch to the LAN endpoint
        const auto old_ep = parseNetworkId(old_network_id);
        const bool old_is_private = !old_ep.ip.empty() && isPrivateIpv4(old_ep.ip);
        const bool old_is_same_endpoint = (old_ep.ip == event.lanIp && old_ep.port == event.lanPort);
        
        if (old_is_same_endpoint) {
            // Already using this LAN endpoint - just update last_seen
            LOG_DEBUG("SM: LAN discovery confirmed existing endpoint for " + event.peerId + ": " + lan_network_id);
            return;
        }
        
        // Decide whether to switch the active endpoint based on connection state
        bool should_switch_endpoint = false;
        bool should_trigger_connect = false;
        
        if (!existing_peer->connected) {
            // Not connected - LAN endpoints are always preferred when on WiFi
            if (!old_is_private) {
                // Currently using WAN endpoint, switch to LAN
                LOG_INFO("SM: Upgrading peer " + event.peerId + " from WAN (" + old_network_id + 
                         ") to LAN (" + lan_network_id + ")");
                should_switch_endpoint = true;
                should_trigger_connect = true;
            } else if (event.latencyMs > 0 && event.latencyMs < 50) {
                // Already private but this LAN endpoint has very low latency - prefer it
                LOG_INFO("SM: Switching peer " + event.peerId + " to faster LAN endpoint (" + 
                         lan_network_id + ", " + std::to_string(event.latencyMs) + "ms)");
                should_switch_endpoint = true;
                should_trigger_connect = true;
            }
        } else {
            // Peer is connected - check if we should upgrade from WAN to LAN
            // When on WiFi and currently connected via public IP, immediately upgrade to LAN
            // because LAN is faster, more reliable, and WAN may become stale after network change.
            if (!old_is_private) {
                LOG_INFO("SM: UPGRADING connected peer " + event.peerId + " from WAN (" + old_network_id + 
                         ") to LAN (" + lan_network_id + ") - LAN is always preferred when on same network");
                should_switch_endpoint = true;
                // Don't trigger reconnect since we're already connected - just switch the endpoint
                // The connection will continue to work as packets will be sent/received via LAN
            } else {
                // Already connected via private/LAN endpoint - just update the candidate
                LOG_DEBUG("SM: Peer " + event.peerId + " is CONNECTED via private " + old_network_id + 
                         " - LAN endpoint " + lan_network_id + " stored as alternative");
            }
            
            // Add secondary receive mapping so we can accept packets from both endpoints
            auto existing_mapping = m_sm->m_network_id_to_peer_id.find(lan_network_id);
            if (existing_mapping == m_sm->m_network_id_to_peer_id.end() ||
                existing_mapping->second == event.peerId) {
                m_sm->add_peer_to_network_index_locked_(event.peerId, lan_network_id);
                LOG_INFO("SM: Added secondary LAN receive mapping for peer " + event.peerId + 
                         " from " + lan_network_id);
            }
            
            // Store as advertised for future reconnect
            existing_peer->advertised_network_id = lan_network_id;
        }
        
        if (should_switch_endpoint) {
            // Check for collisions
            auto collision_it = m_sm->m_network_id_to_peer_id.find(lan_network_id);
            if (collision_it != m_sm->m_network_id_to_peer_id.end() && 
                collision_it->second != event.peerId) {
                LOG_WARN("SM: Cannot switch peer " + event.peerId + " to LAN endpoint " + 
                         lan_network_id + " - already mapped to " + collision_it->second);
                return;
            }
            
            // CRITICAL FIX: Clear all ephemeral mappings that would redirect traffic away from
            // the new LAN endpoint. This is essential after WiFi handoff when switching from
            // WAN to LAN, because stale ephemeral mappings can cause traffic to be sent to
            // the old WAN IP instead of the new LAN IP.
            //
            // There are two types of stale mappings to clear:
            // 1. Mappings where the NEW LAN endpoint is the key (LAN -> WAN) - these would
            //    redirect outgoing traffic to the old WAN address
            // 2. Mappings where the OLD WAN endpoint is the value (ephemeral -> WAN) - these
            //    are obsolete now that we're using LAN
            {
                // Note: We already hold m_network_index_mutex via PeersThenNetworkIndexLock
                size_t removed_count = 0;
                for (auto it = m_sm->m_ephemeral_to_advertised_port_map.begin(); 
                     it != m_sm->m_ephemeral_to_advertised_port_map.end();) {
                    // Remove if:
                    // - Key equals the new LAN endpoint (would redirect LAN traffic elsewhere)
                    // - Value equals the old WAN endpoint (obsolete WAN mapping)
                    // - Value equals the new LAN endpoint (prevents LAN -> LAN mapping loops)
                    if (it->first == lan_network_id || 
                        it->second == old_network_id ||
                        it->second == lan_network_id) {
                        LOG_INFO("SM: Clearing stale ephemeral mapping during LAN switch: " + 
                                 it->first + " -> " + it->second);
                        it = m_sm->m_ephemeral_to_advertised_port_map.erase(it);
                        removed_count++;
                    } else {
                        ++it;
                    }
                }
                if (removed_count > 0) {
                    LOG_INFO("SM: Cleared " + std::to_string(removed_count) + 
                             " stale ephemeral mappings for peer " + event.peerId + 
                             " during WAN->LAN switch");
                }
            }
            
            // Remove old mapping and add new
            m_sm->remove_peer_from_network_index_locked_(old_network_id);
            existing_peer->network_id = lan_network_id;
            existing_peer->ip = event.lanIp;
            existing_peer->port = event.lanPort;
            existing_peer->advertised_network_id = lan_network_id;
            m_sm->add_peer_to_network_index_locked_(event.peerId, lan_network_id);
            
            // Update peer context
            if (ctx_it != m_sm->m_peer_contexts.end()) {
                ctx_it->second.network_id = lan_network_id;
            }
            
            // Register as LAN peer with NAT traversal
            NATTraversal& nat = NATTraversal::getInstance();
            PeerAddress p;
            p.peer_id = event.peerId;
            p.network_id = "lan";
            p.external_ip = event.lanIp;
            p.external_port = static_cast<uint16_t>(event.lanPort);
            p.discovered_at_ms = now_ms;
            nat.registerPeer(p);
            
            // Clear reconnect backoff since we have a fresh endpoint
            PeerReconnectPolicy::getInstance().reset_peer_stats(event.peerId);
            
            LOG_INFO("SM: Peer " + event.peerId + " endpoint switched to LAN: " + lan_network_id);
        }
        
        // Trigger connect if needed (released lock before connect to avoid deadlock)
        if (should_trigger_connect && (current_state == PeerState::DISCOVERED || 
                                        current_state == PeerState::DISCONNECTED ||
                                        current_state == PeerState::FAILED ||
                                        current_state == PeerState::DEGRADED)) {
            // Push connect event - will be handled outside the lock
            m_sm->pushEvent(ConnectToPeerEvent{event.peerId, true, "lan_discovery"});
        }
    }

    bool PeerLifecycleManager::isPrivateLanIp(const std::string& ip) {
        return isPrivateIpv4(ip);
    }

} // namespace detail