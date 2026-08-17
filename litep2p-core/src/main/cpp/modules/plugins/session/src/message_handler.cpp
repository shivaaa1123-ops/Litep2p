#include "message_handler.h"
#include "session_manager_p.h"
#include "device_utils.h"
#include "crypto_utils.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include "message_types.h"
#include "config_manager.h"
#include "telemetry.h"
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>

#if defined(__ANDROID__)
#include "../../jni/include/jni_bridge.h"
#endif

namespace {
    int64_t now_epoch_ms() {
        using namespace std::chrono;
        return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    }
}

namespace {
    std::vector<std::string> splitPipeFields(const std::string& s) {
        std::vector<std::string> out;
        std::stringstream ss(s);
        std::string item;
        while (std::getline(ss, item, '|')) {
            out.push_back(item);
        }
        return out;
    }

    uint64_t parseBootId(const std::string& s) {
        if (s.empty()) return 0;
        try {
            // Support decimal and 0x-prefixed hex.
            size_t idx = 0;
            int base = 10;
            if (s.size() > 2 && (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0)) {
                base = 16;
            }
            const uint64_t v = std::stoull(s, &idx, base);
            if (idx != s.size()) return 0;
            return v;
        } catch (...) {
            return 0;
        }
    }
}

namespace {
    struct NetworkEndpoint {
        std::string ip;
        int port{-1};
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
            const size_t dot = ip.find('.', 4);
            if (dot != std::string::npos) {
                try {
                    const int second = std::stoi(ip.substr(4, dot - 4));
                    if (second >= 16 && second <= 31) return true;
                } catch (...) {
                }
            }
        }
        return false;
    }

    bool looksLikePlaceholderNetworkId(const std::string& network_id) {
        return network_id.rfind("signaling-", 0) == 0;
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
    MessageHandler::MessageHandler(SessionManager::Impl* sm) : m_sm(sm) {}

    void MessageHandler::handleDataReceived(const DataReceivedEvent& event) {
        // Shutdown guard - early return if shutting down
        if (m_sm->m_shutting_down.load(std::memory_order_acquire)) {
            return;
        }

        Telemetry::getInstance().inc_counter("rx_events_total");
        Telemetry::getInstance().inc_counter("rx_bytes_total", static_cast<int64_t>(event.data.size()));
        
        LOG_INFO("MH: === START handleDataReceived ===");
        LOG_INFO("MH: Received data from network_id=" + event.network_id + ", length=" + std::to_string(event.data.length()));
        
        std::string peer_id;
        const Peer* peer_ptr = nullptr;

        // SCOPE: Brief lock to find peer and get state
        {
            // Lock order enforced: peers -> network index
            SessionManager::Impl::PeersThenNetworkIndexLock guard(*m_sm);

            peer_ptr = m_sm->find_peer_by_network_id_locked_(event.network_id);
            
            // If not found by full network_id, try to match by IP address only
            // This handles incoming connections which use ephemeral ports
            if (!peer_ptr) {
                // DISABLE IP MATCHING for stress test
                /*
                size_t colon_pos = event.network_id.find(':');
                if (colon_pos != std::string::npos) {
                    std::string incoming_ip = event.network_id.substr(0, colon_pos);
                    
                    // Search for any peer with matching IP
                    for (const auto& kv : m_sm->m_peers) {
                        const Peer& candidate = kv.second;
                        size_t peer_colon_pos = candidate.network_id.find(':');
                        if (peer_colon_pos != std::string::npos) {
                            std::string peer_ip = candidate.network_id.substr(0, peer_colon_pos);
                            if (peer_ip == incoming_ip) {
                                peer_ptr = &candidate;
                                LOG_INFO("MH: Matched peer by IP: " + candidate.id + " (incoming: " + event.network_id + ", stored: " + candidate.network_id + ")");
                                break;
                            }
                        }
                    }
                }
                */
            }
            
            if (!peer_ptr) {
                LOG_WARN("SM: Peer not found for network ID: " + event.network_id);
            } else {
                peer_id = peer_ptr->id;
            }
        } // locks released

        LOG_DEBUG("SM: Data from " + (peer_id.empty() ? "unknown" : peer_id) + " (length=" + std::to_string(event.data.length()) + ")");

        MessageType type;
        std::string payload;

        LOG_INFO("MH: Attempting to decode message from " + (peer_id.empty() ? "unknown peer" : peer_id));
        if (!wire::decode_message(event.data, type, payload)) {
            LOG_WARN("SM: Failed to decode message");
            LOG_INFO("MH: === END handleDataReceived (decode failed) ===");
            return;
        }
        
        LOG_INFO("MH: Successfully decoded message type=" + std::to_string(static_cast<int>(type)) + ", payload_length=" + std::to_string(payload.length()));

        if (peer_id.empty()) {
            if (type == MessageType::CONTROL_CONNECT) {
                size_t delimiter = payload.find('|');
                if (delimiter != std::string::npos) {
                    peer_id = payload.substr(0, delimiter);
                } else {
                    peer_id = payload;
                }
                LOG_INFO("MH: Identified unknown peer as " + peer_id + " from CONNECT message");
                
                // Flag to track if we created a new peer (for notifyPeerUpdate outside lock)
                bool created_new_peer = false;
                bool upgraded_endpoint = false;
                {
                    // Lock order enforced: peers -> network index
                    SessionManager::Impl::PeersThenNetworkIndexLock guard(*m_sm);
                    Peer* peer = m_sm->find_peer_by_id(peer_id);
                    if (peer) {
                        // IMPORTANT:
                        // - `peer->network_id` is the stable, advertised endpoint (ip:port) discovered via LAN discovery/signaling.
                        // - For UDP, incoming packets may come from a different (ephemeral/NAT-mapped) source port.
                        // - We must NOT overwrite `peer->network_id` with the ephemeral source, otherwise we lose the stable
                        //   advertised endpoint and can create mapping chains across restarts (ephemeral -> ephemeral), which
                        //   breaks routing and CONNECT_ACK delivery.
                        LOG_INFO("MH: Received CONTROL_CONNECT from known peer " + peer_id + " at " + event.network_id + " (advertised=" + peer->network_id + ")");

                        // If the peer restarted and switched networks, we may have a stale advertised endpoint
                        // (e.g., old WAN STUN result) while the observed source is now a direct LAN address.
                        // Heuristic: upgrade public/placeholder -> private endpoint when we observe a private IPv4 source.
                        // CRITICAL: Only do this if we're on WiFi (allow_private_endpoints). Otherwise stale LAN packets
                        // arriving after WiFi-disable can incorrectly switch us to unreachable LAN endpoints.
                        const bool allow_private_endpoints = m_sm->m_is_wifi.load(std::memory_order_acquire);
                        const std::string observed = event.network_id;
                        const std::string advertised = peer->network_id;
                        const NetworkEndpoint obs_ep = parseNetworkId(observed);
                        const NetworkEndpoint adv_ep = parseNetworkId(advertised);
                        const bool obs_private = !obs_ep.ip.empty() && isPrivateIpv4(obs_ep.ip) && obs_ep.port > 0;
                        const bool adv_private = !adv_ep.ip.empty() && isPrivateIpv4(adv_ep.ip) && adv_ep.port > 0;
                        const bool adv_placeholder = advertised.empty() || looksLikePlaceholderNetworkId(advertised);
                        const bool adv_public_like = !adv_private && !advertised.empty() && !adv_ep.ip.empty();

                        // Only upgrade to private if WiFi is active (allow_private_endpoints)
                        if (allow_private_endpoints && obs_private && observed != advertised && (adv_placeholder || adv_public_like)) {
                            LOG_INFO("MH: Upgrading peer " + peer_id + " endpoint " + (advertised.empty() ? std::string("<empty>") : advertised) + " -> " + observed + " (observed private IPv4, WiFi active)");
                            m_sm->remove_peer_from_network_index_locked_(peer->network_id);
                            peer->network_id = observed;
                            peer->advertised_network_id = observed;
                            peer->ip = obs_ep.ip;
                            peer->port = obs_ep.port;
                            m_sm->add_peer_to_network_index_locked_(peer_id, peer->network_id);

                            auto ctx_it = m_sm->m_peer_contexts.find(peer_id);
                            if (ctx_it != m_sm->m_peer_contexts.end()) {
                                ctx_it->second.network_id = peer->network_id;
                            }

                            // Stop any WAN hole-punch work now that we have a direct LAN path.
                            upgraded_endpoint = true;
                        } else if (!allow_private_endpoints && obs_private && observed != advertised && (adv_placeholder || adv_public_like)) {
                            // Stale LAN packet arrived after WiFi disabled - ignore the private endpoint
                            LOG_INFO("MH: IGNORING stale LAN packet from " + observed + " (WiFi OFF, keeping " + advertised + ")");
                        }

                        // Store ephemeral -> advertised mapping only if we did not upgrade the advertised endpoint.
                        // CRITICAL FIX: Also skip if this would create a LAN->WAN redirection mapping.
                        if (!upgraded_endpoint) {
                            // Check if peer is now on LAN but packet came from WAN
                            bool peer_is_lan = (peer->network_id.find("192.168.") == 0 ||
                                               peer->network_id.find("10.") == 0 ||
                                               (peer->network_id.find("172.") == 0));  // simplified check
                            bool event_is_lan = (event.network_id.find("192.168.") == 0 ||
                                                event.network_id.find("10.") == 0 ||
                                                (event.network_id.find("172.") == 0));
                            
                            if (peer_is_lan && !event_is_lan) {
                                // Skip - would redirect LAN traffic to WAN
                                LOG_INFO("MH: CONTROL_CONNECT: Skipping ephemeral mapping - would redirect LAN " +
                                         peer->network_id + " to WAN " + event.network_id);
                            } else {
                                // Keep only the newest ephemeral mapping for this advertised network_id.
                                m_sm->upsert_ephemeral_mapping_locked_(event.network_id, peer->network_id);
                            }
                        }

                        // Refresh liveness.
                        peer->last_seen = std::chrono::steady_clock::now();
                    } else {
                        // Peer not known locally (e.g. discovery race or peer was removed after disconnect).
                        // Create minimal peer+context so the inbound connection can complete.
                        LOG_INFO("MH: Creating new peer entry from inbound CONTROL_CONNECT: " + peer_id + " at " + event.network_id);
                        Peer new_peer;
                        new_peer.id = peer_id;
                        new_peer.network_id = event.network_id;
                        new_peer.advertised_network_id = event.network_id;
                        new_peer.connected = false;
                        new_peer.last_seen = std::chrono::steady_clock::now();
                        new_peer.last_discovery_seen = new_peer.last_seen;
                        new_peer.latency = -1;
                        new_peer.tier = (m_sm->m_peer_tier_manager) ? m_sm->m_peer_tier_manager->get_peer_tier(peer_id) : PeerTier::TIER_1;
                        m_sm->m_peers[peer_id] = new_peer;
                        m_sm->add_peer_to_network_index_locked_(peer_id, event.network_id);
                        m_sm->m_peer_contexts[peer_id] = PeerContext{peer_id, event.network_id};
                        m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::DISCOVERED});
                        created_new_peer = true;  // Defer notifyPeerUpdate to avoid deadlock
                    }
                }

                if (upgraded_endpoint) {
                    NATTraversal::getInstance().unregisterPeer(peer_id);
                }

                // CRITICAL: notifyPeerUpdate() acquires m_peers_mutex, so call OUTSIDE the lock scope
                if (created_new_peer) {
                    m_sm->notifyPeerUpdate();
                }
            } else {
                LOG_WARN("SM: Received non-CONNECT message from unknown peer. Dropping.");
                LOG_INFO("MH: === END handleDataReceived (unknown peer) ===");
                return;
            }
        }

        switch (type) {
            case MessageType::CONTROL_PING: {
                LOG_INFO("SM: Received PING from " + peer_id + ", sending PONG response");

                // IMPORTANT:
                // Incoming UDP packets can come from a different source port than the peer's advertised
                // (discovered) endpoint. This is common even on LAN depending on the transport stack.
                // We must NOT overwrite peer->network_id here, otherwise we corrupt the stable
                // advertised endpoint and can create mapping chains (ephemeral -> ephemeral), which
                // breaks peer lookup and routing after restarts.
                {
                    // Lock order enforced: peers -> network index
                    SessionManager::Impl::PeersThenNetworkIndexLock guard(*m_sm);
                    Peer* peer = m_sm->find_peer_by_id(peer_id);
                    if (peer) {
                        // Refresh liveness.
                        peer->last_seen = std::chrono::steady_clock::now();
                        if (peer->last_discovery_seen.time_since_epoch().count() == 0) {
                            peer->last_discovery_seen = peer->last_seen;
                        }

                        // Update ephemeral->advertised mapping if needed.
                        // CRITICAL FIX: Only create ephemeral mappings when appropriate.
                        // If peer->network_id is a LAN IP and event.network_id is a WAN IP,
                        // do NOT create a mapping because it would redirect LAN traffic to WAN.
                        // This commonly happens after WiFi handoff when stale WAN packets arrive.
                        if (!peer->network_id.empty() && peer->network_id != event.network_id) {
                            // Check if this would create a bad LAN->WAN redirection
                            bool peer_is_lan = false;
                            bool event_is_lan = false;
                            
                            // Simple heuristic: 192.168.x.x, 10.x.x.x, 172.16-31.x.x are LAN
                            auto isLanIp = [](const std::string& network_id) -> bool {
                                if (network_id.empty()) return false;
                                if (network_id.find("192.168.") == 0) return true;
                                if (network_id.find("10.") == 0) return true;
                                if (network_id.find("172.") == 0) {
                                    // Check 172.16-31.x.x range
                                    size_t dot = network_id.find('.', 4);
                                    if (dot != std::string::npos) {
                                        try {
                                            int second_octet = std::stoi(network_id.substr(4, dot - 4));
                                            if (second_octet >= 16 && second_octet <= 31) return true;
                                        } catch (...) {}
                                    }
                                }
                                return false;
                            };
                            
                            peer_is_lan = isLanIp(peer->network_id);
                            event_is_lan = isLanIp(event.network_id);
                            
                            // Only create ephemeral mapping if it doesn't redirect LAN to WAN
                            if (peer_is_lan && !event_is_lan) {
                                // This would create WAN -> LAN, which when reversed during send
                                // would redirect LAN traffic to WAN. Skip it.
                                LOG_INFO("SM: PING: Skipping ephemeral mapping creation - would redirect LAN " +
                                         peer->network_id + " to WAN " + event.network_id);
                            } else {
                                m_sm->upsert_ephemeral_mapping_locked_(event.network_id, peer->network_id);
                            }
                        }
                    }
                }
                
                std::string pong_message = wire::encode_message(MessageType::CONTROL_PONG, payload);
                m_sm->send_message_to_peer(event.network_id, pong_message);
                LOG_INFO("SM: PONG sent to " + peer_id);
                break;
            }
            case MessageType::CONTROL_PONG: {
                LOG_INFO("SM: Received PONG from " + peer_id);
                uint64_t token = 0;
                try {
                    token = static_cast<uint64_t>(std::stoull(payload));
                } catch (...) {
                    LOG_WARN("SM: Error parsing PONG token from " + peer_id + ": payload='" + payload + "'");
                    break;
                }

                // Look up the send timestamp recorded when we sent the last PING to this peer.
                std::chrono::steady_clock::time_point sent_time;
                bool have_sent_time = false;
                {
                    std::lock_guard<std::mutex> lk(m_sm->m_ping_mutex);
                    auto it = m_sm->m_last_ping_by_peer.find(peer_id);
                    if (it != m_sm->m_last_ping_by_peer.end() && it->second.first == token) {
                        sent_time = it->second.second;
                        have_sent_time = true;
                    }
                }

                if (!have_sent_time) {
                    // Either we rebooted, the peer is running an older build, or this PONG is stale/out-of-order.
                    // Do not fabricate a latency value.
                    LOG_DEBUG("SM: Ignoring unmatched PONG token from " + peer_id + ": token=" + std::to_string(token));
                    // Still treat this as liveness.
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    Peer* peer = m_sm->find_peer_by_id(peer_id);
                    if (peer) {
                        peer->last_seen = std::chrono::steady_clock::now();
                        if (peer->last_discovery_seen.time_since_epoch().count() == 0) {
                            peer->last_discovery_seen = peer->last_seen;
                        }
                    }
                    break;
                }

                const auto now = std::chrono::steady_clock::now();
                const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - sent_time).count();
                if (ms < 0 || ms > 30000) {
                    LOG_WARN("SM: Ignoring implausible PONG RTT from " + peer_id + ": " + std::to_string(ms) + "ms");
                    break;
                }

                {
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    Peer* peer = m_sm->find_peer_by_id(peer_id);
                    if (peer) {
                        peer->last_seen = now;
                        if (peer->last_discovery_seen.time_since_epoch().count() == 0) {
                            peer->last_discovery_seen = peer->last_seen;
                        }
                        peer->latency = static_cast<int>(ms);
                    }
                }
                LOG_INFO("SM: PONG latency from " + peer_id + ": " + std::to_string(ms) + "ms");

                // v0.4: resolve a pending app-level ping (litep2p_ping) if the
                // token matches, and fire the ping-result callback with the RTT.
                {
                    SessionManager::PingResultCallback ping_cb;
                    bool matched = false;
                    {
                        std::lock_guard<std::mutex> lk(m_sm->m_app_ping_mutex);
                        auto it = m_sm->m_pending_pings.find(peer_id);
                        if (it != m_sm->m_pending_pings.end() && it->second.token == token) {
                            m_sm->m_pending_pings.erase(it);
                            matched = true;
                        }
                    }
                    if (matched) {
                        std::lock_guard<std::mutex> lk(m_sm->m_v04_cb_mutex);
                        ping_cb = m_sm->m_ping_result_cb;
                    }
                    if (ping_cb) ping_cb(peer_id, static_cast<int64_t>(ms));
                }

                if (m_sm->m_peer_tier_manager) {
                    m_sm->m_peer_tier_manager->record_latency(peer_id, static_cast<int>(ms));
                }
                break;
            }
            case MessageType::CONTROL_CONNECT: {
                // An inbound connection from a peer the user previously
                // disconnected clears the suppression: the peer is reaching out
                // again, so it should be treated as a fresh connection.
                {
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    m_sm->m_user_disconnected_peers.erase(peer_id);
                }

                // Extract the remote public key and optional boot id from CONTROL_CONNECT payload.
                // Format: "peer_id|public_key_hex|boot_id"
                std::string remote_pk_hex;
                uint64_t remote_boot_id = 0;
                {
                    const auto fields = splitPipeFields(payload);
                    if (fields.size() >= 2) {
                        remote_pk_hex = fields[1];
                    }
                    if (fields.size() >= 3) {
                        remote_boot_id = parseBootId(fields[2]);
                    }
                }
                
                // Parse the public key bytes
                std::vector<uint8_t> incoming_pk;
                for (size_t i = 0; i + 1 < remote_pk_hex.length(); i += 2) {
                    std::string byteString = remote_pk_hex.substr(i, 2);
                    uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
                    incoming_pk.push_back(byte);
                }
                
                // Check if we're getting a CONNECT from a peer that was already connected
                bool peer_was_connected = false;
                uint64_t stored_remote_boot_id = 0;
                {
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    Peer* peer = m_sm->find_peer_by_id(peer_id);
                    if (peer && peer->connected) {
                        peer_was_connected = true;
                    }

                    auto ctx_it = m_sm->m_peer_contexts.find(peer_id);
                    if (ctx_it != m_sm->m_peer_contexts.end()) {
                        stored_remote_boot_id = ctx_it->second.remote_boot_id;
                    }
                }
                
                // IMPORTANT: Only clear a READY Noise session if the remote peer's public key
                // is DIFFERENT from what we have stored. This indicates a true restart/re-key.
                // If the key is the SAME, the remote is just retrying CONTROL_CONNECT (common
                // during reconnect storms or endpoint flaps) and we should NOT disrupt the session.
                bool remote_key_changed = false;
                bool remote_boot_changed = false;
#if HAVE_NOISE_PROTOCOL
                if (m_sm->m_use_noise_protocol && incoming_pk.size() == 32 && m_sm->m_noise_key_store) {
                    auto stored_pk = m_sm->m_noise_key_store->get_peer_key(peer_id);
                    if (stored_pk.empty()) {
                        // No stored key - first contact, not a key change
                        remote_key_changed = false;
                    } else if (stored_pk != incoming_pk) {
                        // Key is different - remote peer restarted with new keys
                        LOG_INFO("MH: Peer " + peer_id + " public key CHANGED - likely true restart");
                        remote_key_changed = true;
                    }
                    // Register/update the key
                    m_sm->m_noise_key_store->register_peer_key(peer_id, incoming_pk);
                    LOG_DEBUG("MH: Registered public key for peer " + peer_id);
                }
                
                bool cleared_ready_noise = false;
                // Restart safety: clear the Noise session + derived transport keys when the
                // remote restarts.
                if (remote_boot_id != 0 && stored_remote_boot_id != 0 && remote_boot_id != stored_remote_boot_id) {
                    remote_boot_changed = true;
                    LOG_INFO("MH: Peer " + peer_id + " boot id CHANGED - likely process restart (old=" + std::to_string(stored_remote_boot_id) + ", new=" + std::to_string(remote_boot_id) + ")");
                }
                // A changed boot id or a changed static public key is a DEFINITIVE signal that the
                // remote process restarted, so its previous Noise session and the per-peer transport
                // keys derived from it are invalid on the remote side. We must drop our copy of that
                // session and those transport keys regardless of whether we currently consider the
                // peer connected.
                //
                // IMPORTANT: Do NOT gate this on `peer_was_connected`. When the remote goes down we
                // usually mark it DISCONNECTED *before* it comes back and re-sends CONTROL_CONNECT.
                // If we skip clearing in that case we keep the stale transport keys, and our
                // CONTROL_CONNECT_ACK / handshake replies get encrypted with keys the restarted peer
                // no longer holds, so it can never decrypt them and the reconnect deadlocks
                // (observed as: peer restarts once and reconnects, but a second restart leaves the
                // remote peers stuck in CONNECTING forever with "Decryption returned empty").
                if ((remote_key_changed || remote_boot_changed) && m_sm->m_secure_session_manager) {
                    bool had_ready_session = false;
                    {
                        std::lock_guard<std::mutex> lock(m_sm->m_secure_session_mutex);
                        auto existing = m_sm->m_secure_session_manager->get_session(peer_id);
                        had_ready_session = (existing && existing->is_ready());
                        // remove_session() clears the per-peer transport keys registered under
                        // `peer_id`.
                        m_sm->m_secure_session_manager->remove_session(peer_id);
                    }
                    // Transport keys are ALSO registered under the peer's network_id(s) (ip:port),
                    // because the transports only know ip:port and encrypt with
                    // encrypt_message_for_peer(network_id, ...). remove_session() only cleared the
                    // peer-id entry, so the stale network_id keys would still be used for outbound
                    // traffic to the restarted peer, which no longer holds them -> it can never
                    // decrypt our CONTROL_CONNECT/heartbeats and the reconnect stays deadlocked.
                    // Clear the peer's current/advertised network ids and the source of this
                    // CONTROL_CONNECT.
                    {
                        std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                        Peer* peer = m_sm->find_peer_by_id(peer_id);
                        if (peer) {
                            if (!peer->network_id.empty()) clear_peer_transport_keys(peer->network_id);
                            if (!peer->advertised_network_id.empty() &&
                                peer->advertised_network_id != peer->network_id) {
                                clear_peer_transport_keys(peer->advertised_network_id);
                            }
                        }
                    }
                    if (!event.network_id.empty()) {
                        clear_peer_transport_keys(event.network_id);
                    }
                    cleared_ready_noise = true;
                    LOG_INFO("MH: Cleared Noise session + transport keys for restarted peer " + peer_id +
                             " (had_ready_session=" + std::string(had_ready_session ? "true" : "false") +
                             ", peer_was_connected=" + std::string(peer_was_connected ? "true" : "false") +
                             ", key_changed=" + std::string(remote_key_changed ? "true" : "false") +
                             ", boot_id_changed=" + std::string(remote_boot_changed ? "true" : "false") + ")");
                }
                if (cleared_ready_noise) {
                    m_sm->clearQueuedMessages(peer_id);
                    if (m_sm->m_message_batcher) {
                        (void)m_sm->m_message_batcher->flush_peer(peer_id);
                    }
                }

                // Persist the remote boot id for this peer (even if we didn't clear).
                if (remote_boot_id != 0) {
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    auto ctx_it = m_sm->m_peer_contexts.find(peer_id);
                    if (ctx_it != m_sm->m_peer_contexts.end()) {
                        ctx_it->second.remote_boot_id = remote_boot_id;
                    }
                }
#else
                (void)peer_was_connected;
                (void)remote_key_changed;
(void)remote_boot_id;
(void)stored_remote_boot_id;
(void)remote_boot_changed;
#endif

                std::string ack_payload = m_sm->m_localPeerId;
#if HAVE_NOISE_PROTOCOL
                if (m_sm->m_use_noise_protocol && m_sm->m_noise_key_store) {
                    auto pk = m_sm->m_noise_key_store->get_local_static_public_key();
                    std::string pk_hex;
                    const char* hex_chars = "0123456789abcdef";
                    for (uint8_t b : pk) {
                        pk_hex.push_back(hex_chars[b >> 4]);
                        pk_hex.push_back(hex_chars[b & 0x0F]);
                    }
                    ack_payload += "|" + pk_hex;
                    ack_payload += "|" + std::to_string(m_sm->m_local_boot_id);
                }
#endif

                std::string ack_message = wire::encode_message(MessageType::CONTROL_CONNECT_ACK, ack_payload);
                m_sm->send_message_to_peer(event.network_id, ack_message);
                
                // Get current epoch for this peer to gate stale events
                uint64_t current_epoch = 0;
                {
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    auto ctx_it = m_sm->m_peer_contexts.find(peer_id);
                    if (ctx_it != m_sm->m_peer_contexts.end()) {
                        current_epoch = ctx_it->second.connect_epoch;
                    }
                }
                m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::CONNECT_SUCCESS, current_epoch});
#if HAVE_NOISE_PROTOCOL
                if (m_sm->m_use_noise_protocol && m_sm->shouldInitiateNoiseHandshake(peer_id)) {
                    bool ready = false;
                    if (m_sm->m_secure_session_manager) {
                        std::lock_guard<std::mutex> lock(m_sm->m_secure_session_mutex);
                        auto existing = m_sm->m_secure_session_manager->get_session(peer_id);
                        ready = (existing && existing->is_ready());
                    }
                    if (!ready) {
                        LOG_INFO("MH: Scheduling Noise handshake (initiator) for peer " + peer_id);
                        m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_REQUIRED});
                    } else {
                        LOG_DEBUG("MH: Noise session already READY for " + peer_id + " - skipping handshake scheduling");
                    }
                }
#endif
                break;
            }
            case MessageType::CONTROL_CONNECT_ACK: {
                // Format: "peer_id|public_key_hex|boot_id"
                std::string remote_pk_hex;
                uint64_t remote_boot_id = 0;
                {
                    const auto fields = splitPipeFields(payload);
                    if (fields.size() >= 2) {
                        remote_pk_hex = fields[1];
                    }
                    if (fields.size() >= 3) {
                        remote_boot_id = parseBootId(fields[2]);
                    }
                }

#if HAVE_NOISE_PROTOCOL
                if (m_sm->m_use_noise_protocol && !remote_pk_hex.empty() && m_sm->m_noise_key_store) {
                    std::vector<uint8_t> pk;
                    for (size_t i = 0; i < remote_pk_hex.length(); i += 2) {
                        if (i + 1 < remote_pk_hex.length()) {
                            std::string byteString = remote_pk_hex.substr(i, 2);
                            uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
                            pk.push_back(byte);
                        }
                    }
                    if (pk.size() == 32) {
                        m_sm->m_noise_key_store->register_peer_key(peer_id, pk);
                        LOG_INFO("MH: Registered public key for peer " + peer_id);
                    }
                }
#endif

                // Update remote boot id opportunistically, but avoid letting late ACKs overwrite
                // the boot id for already-connected peers.
                if (remote_boot_id != 0) {
                    bool accept = false;
                    {
                        std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                        Peer* peer = m_sm->find_peer_by_id(peer_id);
                        const bool connected = (peer && peer->connected);
                        auto ctx_it = m_sm->m_peer_contexts.find(peer_id);
                        if (ctx_it != m_sm->m_peer_contexts.end()) {
                            if (!connected || ctx_it->second.remote_boot_id == 0) {
                                ctx_it->second.remote_boot_id = remote_boot_id;
                                accept = true;
                            }
                        }
                    }
                    if (accept) {
                        LOG_DEBUG("MH: Stored remote boot id for peer " + peer_id + " from CONTROL_CONNECT_ACK: " + std::to_string(remote_boot_id));
                    }
                }

                // IMPORTANT:
                // Do NOT clear an existing READY Noise session on CONTROL_CONNECT_ACK.
                // A CONNECT_ACK can arrive after the handshake completed (reordering / fast paths),
                // and clearing here causes READY->HANDSHAKING loops and breaks stable messaging.
                //
                // Restart safety is handled on inbound CONTROL_CONNECT (fresh connect) where the receiver
                // can deterministically clear READY sessions and re-handshake.
                
                // Get current epoch for this peer
                uint64_t current_epoch = 0;
                {
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    auto ctx_it = m_sm->m_peer_contexts.find(peer_id);
                    if (ctx_it != m_sm->m_peer_contexts.end()) {
                        current_epoch = ctx_it->second.connect_epoch;
                    }
                }
                m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::CONNECT_SUCCESS, current_epoch});
#if HAVE_NOISE_PROTOCOL
                LOG_INFO("MH: Checking noise handshake initiation. use_noise=" + std::string(m_sm->m_use_noise_protocol ? "true" : "false"));
                if (m_sm->m_use_noise_protocol && m_sm->shouldInitiateNoiseHandshake(peer_id)) {
                    bool ready = false;
                    if (m_sm->m_secure_session_manager) {
                        std::lock_guard<std::mutex> lock(m_sm->m_secure_session_mutex);
                        auto existing = m_sm->m_secure_session_manager->get_session(peer_id);
                        ready = (existing && existing->is_ready());
                    }
                    if (!ready) {
                        LOG_INFO("MH: Scheduling Noise handshake (initiator) for peer " + peer_id);
                        m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_REQUIRED, current_epoch});
                    } else {
                        LOG_DEBUG("MH: Noise session already READY for " + peer_id + " - skipping handshake scheduling");
                    }
                }
#endif
                break;
            }
            case MessageType::FILE_TRANSFER: {
                // File-transfer frames are handled by FileTransferManager (not forwarded to app callbacks).
                auto* ft_mgr = m_sm->get_file_transfer_manager();
                if (ft_mgr) {
                    ft_mgr->handle_incoming_message(peer_id, payload);
                } else {
                    LOG_WARN("MH: FILE_TRANSFER received but file transfer manager is null");
                }
                break;
            }
            case MessageType::HANDSHAKE_NOISE:
#if HAVE_NOISE_PROTOCOL
                if (m_sm->m_use_noise_protocol) {
                    // LOG_INFO("MH: Received Noise handshake payload from " + peer_id + ", length=" + std::to_string(payload.length()));
                    {
                        std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                        auto ctx_it = m_sm->m_peer_contexts.find(peer_id);
                        if (ctx_it != m_sm->m_peer_contexts.end()) {
                            ctx_it->second.pending_handshake_message = payload;
                        } else {
                            LOG_WARN("MH: Received handshake payload for unknown context " + peer_id);
                        }
                    }
                    // Get current epoch for this peer
                    uint64_t current_epoch = 0;
                    {
                        std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                        auto ctx_it = m_sm->m_peer_contexts.find(peer_id);
                        if (ctx_it != m_sm->m_peer_contexts.end()) {
                            current_epoch = ctx_it->second.connect_epoch;
                        }
                    }
                    m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_MESSAGE_RECEIVED, current_epoch});
                } else {
                    LOG_WARN("MH: Noise handshake payload received but protocol disabled");
                }
#else
                LOG_WARN("MH: Noise handshake payload received but Noise protocol not compiled");
#endif
                break;
            case MessageType::ENCRYPTED_DATA:
                LOG_INFO("MH: Received ENCRYPTED_DATA from " + peer_id + ", payload_length=" + std::to_string(payload.length()));
#if HAVE_NOISE_PROTOCOL
                if (m_sm->m_use_noise_protocol) {
                    LOG_INFO("MH: Noise protocol enabled, attempting decryption");
                    std::shared_ptr<SecureSession> session;
                    {
                        std::lock_guard<std::mutex> lock(m_sm->m_secure_session_mutex);
                        session = m_sm->m_secure_session_manager->get_session(peer_id);
                    }
                    if (session && session->is_ready()) {
                        LOG_INFO("MH: Secure session ready, decrypting message");
                        bool replay_drop = false;
                        std::string decrypted_message = session->receive_message(payload, &replay_drop);
                        LOG_INFO("MH: Decryption complete, decrypted_length=" + std::to_string(decrypted_message.length())
                                 + (replay_drop ? " (replay/duplicate)" : ""));
                        if (!decrypted_message.empty()) {
                            LOG_INFO("MH: Recursively processing decrypted message");
                            m_consecutive_decrypt_fail.erase(peer_id);  // healthy again
                            DataReceivedEvent decrypted_event{event.network_id, decrypted_message, std::chrono::steady_clock::now()};
                            handleDataReceived(decrypted_event); // Recursive call with decrypted data
                        } else if (replay_drop) {
                            // A benign replay/duplicate (common on UDP bursts): the
                            // anti-replay window rejected the counter. Drop it silently.
                            // It is NOT a real auth failure and MUST NOT tear down the
                            // session — otherwise a single re-ordered/duplicated
                            // datagram would invalidate the session and lose the rest
                            // of the burst (observed as: burst of N delivered only the
                            // first ~65, everything after dropped as "no ready session").
                            Telemetry::getInstance().inc_counter("noise_replay_drop_total");
                            LOG_DEBUG("MH: Dropping replay/duplicate frame from " + peer_id);
                        } else {
                            // Count CONSECUTIVE real decryption failures. A single
                            // corrupt/reordered frame is normal on UDP and must not
                            // destroy the session — nuking it on any one auth failure
                            // loses the rest of the burst as "no ready session"
                            // (observed: a 600-message burst delivered only ~65).
                            // Only when several frames fail in a row do we treat it
                            // as stale keys / session desync and force a fresh
                            // handshake.
                            int& de_fails = m_consecutive_decrypt_fail[peer_id];
                            de_fails++;
                            Telemetry::getInstance().inc_counter("noise_decrypt_fail_total");
                            constexpr int kDecryptFailThreshold = 3;
                            if (de_fails < kDecryptFailThreshold) {
                                LOG_WARN("SM: Transient decrypt failure (" +
                                         std::to_string(de_fails) + "/" +
                                         std::to_string(kDecryptFailThreshold) +
                                         ") for " + peer_id + " - keeping session");
                                break;
                            }
                            de_fails = 0;
                            LOG_WARN("SM: Consecutive decrypt failures for " + peer_id +
                                     " - forcing session reset (stale keys/session desync)");
                            {
                                std::lock_guard<std::mutex> lock(m_sm->m_secure_session_mutex);
                                m_sm->m_secure_session_manager->remove_session(peer_id);
                            }
                            Telemetry::getInstance().inc_counter("noise_session_reset_total");
                            m_sm->clearQueuedMessages(peer_id);
                            if (m_sm->m_message_batcher) {
                                (void)m_sm->m_message_batcher->flush_peer(peer_id);
                            }

                            // Get current epoch for this peer
                            uint64_t current_epoch = 0;
                            {
                                std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                                auto ctx_it = m_sm->m_peer_contexts.find(peer_id);
                                if (ctx_it != m_sm->m_peer_contexts.end()) {
                                    current_epoch = ctx_it->second.connect_epoch;
                                }
                            }
                            
                            // If we are the deterministic initiator, start handshake now.
                            // Otherwise, send a CONTROL_CONNECT to prompt the initiator side.
                            if (m_sm->shouldInitiateNoiseHandshake(peer_id)) {
                                m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_REQUIRED, current_epoch});
                            } else {
                                std::string connect_payload = m_sm->m_localPeerId;
                                if (m_sm->m_noise_key_store) {
                                    auto pk = m_sm->m_noise_key_store->get_local_static_public_key();
                                    std::string pk_hex;
                                    const char* hex_chars = "0123456789abcdef";
                                    for (uint8_t b : pk) {
                                        pk_hex.push_back(hex_chars[b >> 4]);
                                        pk_hex.push_back(hex_chars[b & 0x0F]);
                                    }
                                    connect_payload += "|" + pk_hex + "|" + std::to_string(m_sm->m_local_boot_id);
                                }
                                const std::string connect_msg = wire::encode_message(MessageType::CONTROL_CONNECT, connect_payload);
                                m_sm->send_message_to_peer(event.network_id, connect_msg);
                                LOG_INFO("MH: Sent CONTROL_CONNECT to prompt re-handshake with " + peer_id + " after decrypt failure");
                            }
                        }
                    } else {
                        LOG_WARN("SM: No ready secure session for peer " + peer_id);
                    }
                } else {
                    LOG_WARN("MH: Noise protocol disabled but received ENCRYPTED_DATA");
                }
#else
                LOG_WARN("MH: ENCRYPTED_DATA received but Noise protocol not compiled");
#endif
                break;
            case MessageType::APPLICATION_DATA:
                Telemetry::getInstance().inc_counter("rx_app_messages_total");
                Telemetry::getInstance().inc_counter("rx_app_bytes_total", static_cast<int64_t>(payload.size()));

                // Traffic is liveness. Previously only PING/PONG/CONNECT refreshed
                // peer->last_seen, so a peer actively streaming a large burst could
                // still be expired by the heartbeat/liveness watchdog and torn down
                // mid-conversation (receiver drops exactly that peer). Refreshing
                // here also covers the encrypted path, which recurses into this
                // case after a successful decrypt.
                {
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    Peer* liveness_peer = m_sm->find_peer_by_id(peer_id);
                    if (liveness_peer) {
                        liveness_peer->last_seen = std::chrono::steady_clock::now();
                    }
                }

                // ------------------------------------------------------------
                // ------------------------------------------------------------
                // Reliable-send envelope (v0.4, ask.md §1): LP_RELIABLE
                // ------------------------------------------------------------
                // Payload: {"type":"LP_RELIABLE","msg_id":"...","body_b64":"..."}
                // Receiver dedupes on msg_id, ACKs with LP_RELIABLE_ACK, and
                // forwards the decoded body to the app callback exactly once.
                if (!payload.empty() && payload.front() == '{') {
                    if (payload.find("\"type\"") != std::string::npos &&
                        payload.find("LP_RELIABLE") != std::string::npos) {
                        try {
                            const auto j = nlohmann::json::parse(payload);
                            if (j.is_object() && j.value("type", std::string{}) == "LP_RELIABLE") {
                                const std::string msg_id = j.value("msg_id", std::string{});
                                const std::string body_b64 = j.value("body_b64", std::string{});

                                // Always ACK so the sender can mark DELIVERED.
                                if (!msg_id.empty()) {
                                    nlohmann::json ack;
                                    ack["type"] = "LP_RELIABLE_ACK";
                                    ack["msg_id"] = msg_id;
                                    const std::string ack_payload = ack.dump();
                                    const std::string ack_msg =
                                        wire::encode_message(MessageType::APPLICATION_ACK, ack_payload);
                                    m_sm->send_message_to_peer(event.network_id, ack_msg);
                                    Telemetry::getInstance().inc_counter("tx_reliable_acks_total");
                                }

                                // Dedup: fire onMessageReceived at most once per msg_id.
                                const bool dup = m_sm->m_reliable_send_manager &&
                                                 m_sm->m_reliable_send_manager->is_duplicate(msg_id);
                                if (!dup && m_sm->m_message_received_cb) {
                                    const std::string body = reliable_base64_decode(body_b64);
                                    m_sm->m_message_received_cb(peer_id, body);
                                }
                                break;
                            }
                        } catch (...) {
                            // Fall through to legacy handling.
                        }
                    }
                }

                // App-level ACK protocol (LP_APP envelope)
                // ------------------------------------------------------------
                // Expected payload (JSON):
                // {
                //   "type": "LP_APP",
                //   "msg_id": "...",
                //   "requires_ack": true,
                //   "sent_ts_ms": 123456789,
                //   "body": "..."   // UTF-8 text for now
                // }
                // If requires_ack=true, receiver responds with APPLICATION_ACK:
                // {
                //   "type": "LP_APP_ACK",
                //   "msg_id": "...",
                //   "sent_ts_ms": 123456789,
                //   "recv_ts_ms": 123456790
                // }
                if (!payload.empty() && payload.front() == '{') {
                    // Cheap substring gate to avoid parsing arbitrary app payloads.
                    if (payload.find("\"type\"") != std::string::npos && payload.find("LP_APP") != std::string::npos) {
                        try {
                            const auto j = nlohmann::json::parse(payload);
                            if (j.is_object() && j.value("type", std::string{}) == "LP_APP") {
                                const std::string msg_id = j.value("msg_id", std::string{});
                                const bool requires_ack = j.value("requires_ack", false);
                                const int64_t sent_ts_ms = j.value("sent_ts_ms", static_cast<int64_t>(0));
                                const std::string body = j.value("body", std::string{});

                                if (requires_ack && !msg_id.empty()) {
                                    nlohmann::json ack;
                                    ack["type"] = "LP_APP_ACK";
                                    ack["msg_id"] = msg_id;
                                    if (sent_ts_ms > 0) ack["sent_ts_ms"] = sent_ts_ms;
                                    ack["recv_ts_ms"] = now_epoch_ms();
                                    const std::string ack_payload = ack.dump();
                                    const std::string ack_msg = wire::encode_message(MessageType::APPLICATION_ACK, ack_payload);
                                    LOG_INFO("MH: SENDING app ACK for msg_id " + msg_id + " to peer " + peer_id);
                                    m_sm->send_message_to_peer(event.network_id, ack_msg);
                                    Telemetry::getInstance().inc_counter("tx_app_acks_total");
                                }

                                // Forward only the body to the normal app callback (keeps UI compatibility).
                                if (m_sm->m_message_received_cb) {
                                    m_sm->m_message_received_cb(peer_id, body);
                                }
                                break;
                            }
                        } catch (...) {
                            // Fall through to legacy handling.
                        }
                    }
                }

                // Remote control plane: LP_ADMIN is carried over APPLICATION_DATA as JSON.
                // If recognized, handle it here and prevent it from reaching the normal app callback.
                if (!payload.empty() && payload.front() == '{') {
                    // Cheap substring gate to avoid parsing arbitrary app payloads.
                    if (payload.find("\"type\"") != std::string::npos && payload.find("LP_ADMIN") != std::string::npos) {
                        if (m_sm->handle_admin_command_message(peer_id, payload)) {
                            LOG_INFO("MH: LP_ADMIN message handled from " + peer_id);
                            break;
                        }
                    }
                }
                LOG_INFO("========================================");
                LOG_INFO("MH: *** RECEIVED APPLICATION DATA ***");
                LOG_INFO("========================================");
                LOG_INFO("MH: Received application data from peer " + peer_id);
                LOG_INFO("MH: Message length: " + std::to_string(payload.length()));
                LOG_INFO("MH: Message content: [" + payload + "]");
                // Call the message received callback if registered
                if (m_sm->m_message_received_cb) {
                    LOG_INFO("MH: Message callback registered - invoking");
                    m_sm->m_message_received_cb(peer_id, payload);
                    LOG_INFO("MH: Message callback completed successfully");
                } else {
                    LOG_WARN("MH: No message received callback registered - message will be lost!");
                }
                LOG_INFO("========================================");
                break;

            case MessageType::APPLICATION_ACK: {
                Telemetry::getInstance().inc_counter("rx_app_acks_total");

                // Reliable-send ACK (v0.4): {"type":"LP_RELIABLE_ACK","msg_id":"..."}
                if (!payload.empty() && payload.front() == '{' &&
                    payload.find("LP_RELIABLE_ACK") != std::string::npos) {
                    try {
                        const auto j = nlohmann::json::parse(payload);
                        if (j.is_object() && j.value("type", std::string{}) == "LP_RELIABLE_ACK") {
                            const std::string msg_id = j.value("msg_id", std::string{});
                            if (!msg_id.empty() && m_sm->m_reliable_send_manager) {
                                m_sm->m_reliable_send_manager->on_ack(msg_id);
                            }
                            break;
                        }
                    } catch (...) {
                        // ignore; fall through
                    }
                }

                if (!payload.empty() && payload.front() == '{') {
                    // Cheap substring gate
                    if (payload.find("LP_APP_ACK") != std::string::npos && payload.find("\"msg_id\"") != std::string::npos) {
                        try {
                            const auto j = nlohmann::json::parse(payload);
                            if (j.is_object() && j.value("type", std::string{}) == "LP_APP_ACK") {
                                const std::string msg_id = j.value("msg_id", std::string{});
                                const int64_t sent_ts_ms = j.value("sent_ts_ms", static_cast<int64_t>(0));
                                const int64_t recv_ts_ms = j.value("recv_ts_ms", static_cast<int64_t>(0));
                                (void)sent_ts_ms;   // used only in Android UI path
                                (void)recv_ts_ms;

#if defined(__ANDROID__)
                                if (!msg_id.empty()) {
                                    LOG_INFO("MH: Received app ACK for msg_id " + msg_id);
                                    sendMessageAckToUI(msg_id, sent_ts_ms, recv_ts_ms);
                                }
#endif
                                break;
                            }
                        } catch (...) {
                            // ignore
                        }
                    }
                }
                break;
            }

            case MessageType::PROXY_CONTROL:
                LOG_INFO("MH: Received PROXY_CONTROL from " + peer_id + " len=" + std::to_string(payload.length()));
#if ENABLE_PROXY_MODULE
                if (m_sm->m_proxy_endpoint) {
                    LOG_INFO("MH: Dispatching PROXY_CONTROL to proxy endpoint");
                    m_sm->m_proxy_endpoint->on_control(peer_id, payload);
                } else {
                    LOG_WARN("MH: PROXY_CONTROL received but proxy endpoint not initialized");
                }
#else
                LOG_WARN("MH: PROXY_CONTROL received but proxy module not compiled");
#endif
                break;

            case MessageType::PROXY_STREAM_DATA:
                LOG_INFO("MH: Received PROXY_STREAM_DATA from " + peer_id);
#if ENABLE_PROXY_MODULE
                if (m_sm->m_proxy_endpoint) {
                    m_sm->m_proxy_endpoint->on_stream_data(peer_id, payload);
                } else {
                    LOG_WARN("MH: PROXY_STREAM_DATA received but proxy endpoint not initialized");
                }
#else
                LOG_WARN("MH: PROXY_STREAM_DATA received but proxy module not compiled");
#endif
                break;

            case MessageType::OVERLAY_FRAME:
                // Multi-hop overlay (LPX2). Frames arrive from *connected*
                // peers (the previous hop); contents may be relay traffic,
                // advertisements, mailbox operations, or deliveries for us.
#if ENABLE_OVERLAY_MODULE
                if (m_sm->m_overlay_router) {
                    m_sm->m_overlay_router->on_frame(peer_id, payload);
                }
#else
                LOG_WARN("MH: OVERLAY_FRAME received but overlay module not compiled");
#endif
                break;
            default:
                LOG_WARN("SM: Unknown message type received from " + peer_id + ", type=" + std::to_string(static_cast<int>(type)));
                break;
        }
        
        LOG_INFO("MH: === END handleDataReceived ===");
    }

    void MessageHandler::handleSendMessage(const SendMessageEvent& event) {
        // LOG_INFO("MH: handleSendMessage called for peer " + event.peerId + " with message length " + std::to_string(event.message.length()));
        
        // Shutdown guard - early return if shutting down
        if (m_sm->m_shutting_down.load(std::memory_order_acquire)) {
            LOG_WARN("MH: Ignoring message to " + event.peerId + " - session is shutting down");
            return;
        }
        
        std::string network_id;
        PeerState peer_state = PeerState::UNKNOWN;
        bool peer_connected = false;
        std::chrono::steady_clock::time_point peer_last_seen{};
        std::chrono::steady_clock::time_point peer_last_discovery_seen{};
        
        LOG_INFO("MH: About to acquire peers_mutex");
        // SCOPE: Brief lock to find peer and get state
        {
            std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
            LOG_INFO("MH: Acquired peers_mutex");
            
            // Use fast lookup instead of linear search
            const Peer* peer = m_sm->find_peer_by_id(event.peerId);
            if (!peer) {
                LOG_WARN("MH: Peer not found: " + event.peerId);
                return;
            }
            LOG_DEBUG("MH: Peer found");
            
            peer_connected = peer->connected;
            LOG_INFO("MH: *** MESSAGE SEND ATTEMPT *** peer=" + event.peerId + ", connected=" + std::to_string(peer_connected) + ", network_id=" + peer->network_id);

            peer_last_seen = peer->last_seen;
            peer_last_discovery_seen = peer->last_discovery_seen;
            
            // Lock the peer's mutex for accessing its data
            std::lock_guard<std::mutex> peer_lock(m_sm->get_peer_mutex(event.peerId));
            LOG_DEBUG("MH: Acquired peer_lock");
            
            network_id = peer->network_id;
            
            // Get peer state from FSM
            auto ctx_it = m_sm->m_peer_contexts.find(event.peerId);
            if (ctx_it != m_sm->m_peer_contexts.end()) {
                peer_state = ctx_it->second.state;
                LOG_INFO("MH: *** PEER FSM STATE = " + m_sm->state_to_string(peer_state) + " ***");
            } else {
                LOG_WARN("MH: No FSM context found for peer " + event.peerId);
            }
        }  // Locks released here - before any blocking operations
        LOG_DEBUG("MH: Released locks");
        
        try {
            const auto now = std::chrono::steady_clock::now();

            std::string internal_msg = event.message;
            MessageType msg_type;
            std::string msg_payload;
            
            // Check if message is already in structured format
            if (!wire::decode_message(event.message, msg_type, msg_payload)) {
                // If not, treat as application data and wrap it
                if (internal_msg.rfind("MSG:", 0) != 0 && 
                    internal_msg.rfind("PING:", 0) != 0 && 
                    internal_msg.rfind("PONG:", 0) != 0 &&
                    internal_msg.rfind("CONNECT:", 0) != 0 &&
                    internal_msg.rfind("CONNECT_ACK:", 0) != 0 &&
                    internal_msg.rfind("ENCRYPTED:", 0) != 0) {
                    internal_msg = wire::encode_message(MessageType::APPLICATION_DATA, internal_msg);
                } else {
                    // Convert legacy format to structured format
                    if (internal_msg.rfind("PING:", 0) == 0) {
                        internal_msg = wire::encode_message(MessageType::CONTROL_PING, internal_msg.substr(5));
                    } else if (internal_msg.rfind("PONG:", 0) == 0) {
                        internal_msg = wire::encode_message(MessageType::CONTROL_PONG, internal_msg.substr(5));
                    } else if (internal_msg.rfind("CONNECT:", 0) == 0) {
                        internal_msg = wire::encode_message(MessageType::CONTROL_CONNECT, internal_msg.substr(8));
                    } else if (internal_msg.rfind("CONNECT_ACK:", 0) == 0) {
                        internal_msg = wire::encode_message(MessageType::CONTROL_CONNECT_ACK, internal_msg.substr(12));
                    } else if (internal_msg.rfind("ENCRYPTED:", 0) == 0) {
                        internal_msg = wire::encode_message(MessageType::ENCRYPTED_DATA, internal_msg.substr(10));
                    } else {
                        internal_msg = wire::encode_message(MessageType::APPLICATION_DATA, internal_msg.substr(4)); // Skip "MSG:"
                    }
                }
            }
            
            // Determine if it's a control message
            bool is_control = false;
            if (wire::decode_message(internal_msg, msg_type, msg_payload)) {
                is_control = (msg_type == MessageType::CONTROL_PING || 
                             msg_type == MessageType::CONTROL_PONG ||
                             msg_type == MessageType::CONTROL_CONNECT ||
                             msg_type == MessageType::CONTROL_CONNECT_ACK);
            }

            // If we think we're "connected" but haven't heard from the peer in a while,
            // avoid sending application data into a black hole. This happens commonly when
            // the remote process is killed and restarts with new sockets/keys.
            // Instead, force a disconnect + reconnect and queue the message.
            //
            // Guard: if we are OUR OWN last client of this peer within the liveness window
            // (i.e. mid-burst), do NOT force-reconnect. A dense outbound burst keeps the
            // local event loop busy flushing sends, so inbound ACKs/PONGs queue up behind
            // it and the peer can look "stale" to ourselves purely because we are the ones
            // flooding it. Forcing a reconnect then drops queued messages (per-peer pending
            // is capped at MAX_QUEUED_MESSAGES) and starts a reconnect storm that tears the
            // link down. Since UDP is connectionless, writing to an idle peer is harmless;
            // a genuinely dead peer is caught by heartbeat expiry + the restart/decrypt
            // recovery paths instead.
            if (!is_control && peer_connected &&
                (peer_state == PeerState::READY || peer_state == PeerState::CONNECTED ||
                 peer_state == PeerState::HANDSHAKING || peer_state == PeerState::DEGRADED)) {
                const int heartbeat_interval_sec = ConfigManager::getInstance().getHeartbeatIntervalSec();
                const int heartbeat_liveness_ms = std::max(5000, heartbeat_interval_sec * 3 * 1000);
                const auto silent_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - peer_last_seen).count();
                const auto discovery_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - peer_last_discovery_seen).count();

                const bool actively_sending =
                    m_sm->recently_sent_to(event.peerId,
                                           std::chrono::milliseconds(heartbeat_liveness_ms));
                if (silent_ms > heartbeat_liveness_ms && !actively_sending) {
                    LOG_WARN("MH: Peer " + event.peerId + " appears stale while CONNECTED (silent_ms=" +
                             std::to_string(silent_ms) + ", discovery_ms=" + std::to_string(discovery_ms) +
                             ") - forcing reconnect and queueing message");

#if HAVE_NOISE_PROTOCOL
                    m_sm->queueMessage(event.peerId, internal_msg);
#endif
                    
                    // Get current epoch for this peer
                    uint64_t current_epoch = 0;
                    {
                        std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                        auto ctx_it = m_sm->m_peer_contexts.find(event.peerId);
                        if (ctx_it != m_sm->m_peer_contexts.end()) {
                            current_epoch = ctx_it->second.connect_epoch;
                        }
                    }
                    m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::DISCONNECT_DETECTED, current_epoch});
                    m_sm->pushEvent(ConnectToPeerEvent{event.peerId});
                    return;
                }
            }

            // Control whether this message is eligible for batching.
            // High-volume / latency-sensitive frames must bypass batching.
            const bool is_batchable = (!is_control &&
                                      msg_type != MessageType::FILE_TRANSFER &&
                                      msg_type != MessageType::PROXY_CONTROL &&
                                      msg_type != MessageType::PROXY_STREAM_DATA);

            const bool already_encrypted = (msg_type == MessageType::ENCRYPTED_DATA);
#if HAVE_NOISE_PROTOCOL
            const bool requires_secure_channel = m_sm->m_use_noise_protocol && !is_control && !already_encrypted;
#else
            constexpr bool requires_secure_channel = false;
#endif

            LOG_DEBUG("MH: Message send routing - peer_state=" + m_sm->state_to_string(peer_state) +
                      ", is_control=" + std::to_string(is_control) +
                      ", secure=" + std::to_string(requires_secure_channel));

            std::string outbound_msg = internal_msg;

            switch (peer_state) {
                case PeerState::DISCOVERED:
                case PeerState::CONNECTING: {
                    if (!is_control) {
                        LOG_INFO("MH: Queueing message for peer " + event.peerId + " while connecting (state=" + m_sm->state_to_string(peer_state) + ")");
#if HAVE_NOISE_PROTOCOL
                        m_sm->queueMessage(event.peerId, internal_msg);
#endif
                        return;
                    }
                    // Control messages may still be useful during connect attempts.
                    m_sm->handleSendMessageWithRetry(event.peerId, network_id, outbound_msg, "");
                    break;
                }

                case PeerState::READY: {
#if HAVE_NOISE_PROTOCOL
                    if (requires_secure_channel) {
                        // CRITICAL: Keep lock held during encryption to prevent nonce reuse.
                        // Noise NK maintains send/recv counters that increment with each message.
                        // If multiple threads encrypt concurrently, they may reuse the same nonce,
                        // causing decryption failures.
                        std::lock_guard<std::mutex> lock(m_sm->m_secure_session_mutex);
                        std::shared_ptr<SecureSession> secure_session = 
                            m_sm->m_secure_session_manager->get_session(event.peerId);

                        if (!secure_session || !secure_session->is_ready()) {
                            LOG_WARN("MH: Secure session not ready for peer " + event.peerId + ", queueing message");
                            m_sm->queueMessage(event.peerId, internal_msg);
                            if (m_sm->shouldInitiateNoiseHandshake(event.peerId)) {
                                m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::HANDSHAKE_REQUIRED});
                            }
                            return;
                        }

                        // Encrypt the entire internal_msg (includes APPLICATION_DATA type header)
                        // so receiver can decode it after decryption
                        std::string ciphertext = secure_session->send_message(internal_msg);
                        if (ciphertext.empty()) {
                            LOG_WARN("MH: Failed to encrypt payload for peer " + event.peerId);
                            return;
                        }
                        outbound_msg = wire::encode_message(MessageType::ENCRYPTED_DATA, ciphertext);
                    }
#endif

                    if (is_batchable) {
                        LOG_DEBUG("MH: Enqueuing application message to batcher for peer " + event.peerId);
                        int batch_id = m_sm->m_message_batcher->enqueue_message(event.peerId, outbound_msg, false);
                        if (batch_id != -1) {
                            LOG_DEBUG("MH: Message batched with ID " + std::to_string(batch_id) + " for peer " + event.peerId);
                            return;
                        }
                    }

                    LOG_INFO("MH: Sending message to peer " + event.peerId + " via network_id " + network_id);
                    m_sm->handleSendMessageWithRetry(event.peerId, network_id, outbound_msg, "");
                    break;
                }

                case PeerState::DEGRADED:
                case PeerState::CONNECTED: {
#if HAVE_NOISE_PROTOCOL
                    if (requires_secure_channel) {
                        LOG_INFO("MH: Queueing message for peer " + event.peerId + " during handshake/degraded state");
                        m_sm->queueMessage(event.peerId, internal_msg);
                        if (m_sm->shouldInitiateNoiseHandshake(event.peerId)) {
                            m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::HANDSHAKE_REQUIRED});
                        }
                        return;
                    }
#endif
                    if (is_batchable) {
                        int batch_id = m_sm->m_message_batcher->enqueue_message(event.peerId, outbound_msg, false);
                        if (batch_id != -1) {
                            return;
                        }
                    }
                    m_sm->handleSendMessageWithRetry(event.peerId, network_id, outbound_msg, "");
                    break;
                }

                case PeerState::HANDSHAKING: {
#if HAVE_NOISE_PROTOCOL
                    if (!is_control) {
                        LOG_INFO("MH: Queueing message for peer " + event.peerId + " during handshake");
                        m_sm->queueMessage(event.peerId, internal_msg);
                        return;
                    }
#endif
                    m_sm->handleSendMessageWithRetry(event.peerId, network_id, outbound_msg, "");
                    break;
                }

                case PeerState::UNKNOWN: {
                    if (!is_control) {
                        LOG_INFO("MH: Queueing message for peer " + event.peerId + " while peer context initializes (state=UNKNOWN)");
#if HAVE_NOISE_PROTOCOL
                        m_sm->queueMessage(event.peerId, internal_msg);
#endif
                        return;
                    }
                    LOG_WARN("MH: Cannot send control message to peer " + event.peerId + " - state is UNKNOWN");
                    break;
                }

                case PeerState::DISCONNECTED:
                case PeerState::FAILED:
                    LOG_WARN("MH: Cannot send to peer " + event.peerId + " - state is " + m_sm->state_to_string(peer_state));
                    LOG_DEBUG("SM: Dropping message for " + m_sm->state_to_string(peer_state) + " peer " + event.peerId);
                    break;

                default:
                    LOG_DEBUG("SM: Dropping message for unknown state peer " + event.peerId);
                    break;
            }
        } catch (const std::exception& e) {
            LOG_WARN("SM: Error in send handler: " + std::string(e.what()));
        }
    }
}
