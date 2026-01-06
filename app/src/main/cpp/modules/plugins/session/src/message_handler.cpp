#include "message_handler.h"
#include "session_manager_p.h"
#include "message_types.h"
#include "config_manager.h"
#include "telemetry.h"
#include <iostream>
#include <nlohmann/json.hpp>

namespace {
    struct NetworkEndpoint {
        std::string ip;
        int port{-1};
    };

    bool isPrivateIpv4(const std::string& ip) {
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
        NetworkEndpoint endpoint;
        if (network_id.empty()) {
            return endpoint;
        }
        const auto separator = network_id.find_last_of(':');
        if (separator == std::string::npos) {
            endpoint.ip = network_id;
            return endpoint;
        }
        endpoint.ip = network_id.substr(0, separator);
        const std::string port_str = network_id.substr(separator + 1);
        if (port_str.empty()) {
            return endpoint;
        }
        try {
            const int parsed = std::stoi(port_str);
            if (parsed >= 0 && parsed <= 65535) {
                endpoint.port = parsed;
            }
        } catch (...) {
        }
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
            std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);

            peer_ptr = m_sm->find_peer_by_network_id(event.network_id);
            
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
        } // Lock released

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
                {
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
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
                        const std::string observed = event.network_id;
                        const std::string advertised = peer->network_id;
                        const NetworkEndpoint obs_ep = parseNetworkId(observed);
                        const NetworkEndpoint adv_ep = parseNetworkId(advertised);
                        const bool obs_private = !obs_ep.ip.empty() && isPrivateIpv4(obs_ep.ip) && obs_ep.port > 0;
                        const bool adv_private = !adv_ep.ip.empty() && isPrivateIpv4(adv_ep.ip) && adv_ep.port > 0;
                        const bool adv_placeholder = advertised.empty() || looksLikePlaceholderNetworkId(advertised);
                        const bool adv_public_like = !adv_private && !advertised.empty() && !adv_ep.ip.empty();

                        bool upgraded_endpoint = false;
                        if (obs_private && observed != advertised && (adv_placeholder || adv_public_like)) {
                            LOG_INFO("MH: Upgrading peer " + peer_id + " endpoint " + (advertised.empty() ? std::string("<empty>") : advertised) + " -> " + observed + " (observed private IPv4)");
                            m_sm->remove_peer_from_network_index(peer->network_id);
                            peer->network_id = observed;
                            peer->advertised_network_id = observed;
                            peer->ip = obs_ep.ip;
                            peer->port = obs_ep.port;
                            m_sm->add_peer_to_network_index(peer_id, peer->network_id);

                            auto ctx_it = m_sm->m_peer_contexts.find(peer_id);
                            if (ctx_it != m_sm->m_peer_contexts.end()) {
                                ctx_it->second.network_id = peer->network_id;
                            }

                            // Stop any WAN hole-punch work now that we have a direct LAN path.
                            NATTraversal::getInstance().unregisterPeer(peer_id);
                            upgraded_endpoint = true;
                        }


                        // Store ephemeral -> advertised mapping only if we did not upgrade the advertised endpoint.
                        if (!upgraded_endpoint) {
                            {
                                std::lock_guard<std::mutex> index_lock(m_sm->m_network_index_mutex);
                                // Keep only the newest ephemeral mapping for this peer's advertised network_id.
                                // Multiple stale mappings can cause sends to route to a dead socket.
                                for (auto it = m_sm->m_ephemeral_to_advertised_port_map.begin();
                                     it != m_sm->m_ephemeral_to_advertised_port_map.end();) {
                                    if (it->second == peer->network_id) {
                                        it = m_sm->m_ephemeral_to_advertised_port_map.erase(it);
                                    } else {
                                        ++it;
                                    }
                                }
                                m_sm->m_ephemeral_to_advertised_port_map[event.network_id] = peer->network_id;
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
                        m_sm->add_peer_to_network_index(peer_id, event.network_id);
                        m_sm->m_peer_contexts[peer_id] = PeerContext{peer_id, event.network_id};
                        m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::DISCOVERED});
                        created_new_peer = true;  // Defer notifyPeerUpdate to avoid deadlock
                    }
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
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    Peer* peer = m_sm->find_peer_by_id(peer_id);
                    if (peer) {
                        // Refresh liveness.
                        peer->last_seen = std::chrono::steady_clock::now();
                        if (peer->last_discovery_seen.time_since_epoch().count() == 0) {
                            peer->last_discovery_seen = peer->last_seen;
                        }

                        // Update ephemeral->advertised mapping if needed.
                        if (!peer->network_id.empty() && peer->network_id != event.network_id) {
                            std::lock_guard<std::mutex> index_lock(m_sm->m_network_index_mutex);
                            // Keep only the newest ephemeral mapping for this peer's advertised network_id.
                            for (auto it = m_sm->m_ephemeral_to_advertised_port_map.begin();
                                 it != m_sm->m_ephemeral_to_advertised_port_map.end();) {
                                if (it->second == peer->network_id) {
                                    it = m_sm->m_ephemeral_to_advertised_port_map.erase(it);
                                } else {
                                    ++it;
                                }
                            }
                            m_sm->m_ephemeral_to_advertised_port_map[event.network_id] = peer->network_id;
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
                std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                Peer* peer = m_sm->find_peer_by_id(peer_id);
                if (peer) {
                    if (peer->last_discovery_seen.time_since_epoch().count() == 0) {
                        peer->last_discovery_seen = peer->last_seen;
                    }
                    try {
                        auto sent_time = std::chrono::steady_clock::time_point(std::chrono::nanoseconds(std::stoll(payload)));
                        auto now = std::chrono::steady_clock::now();
                        auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(now - sent_time);
                        peer->latency = latency.count();
                        LOG_INFO("SM: PONG latency from " + peer_id + ": " + std::to_string(latency.count()) + "ms");

                        if (m_sm->m_peer_tier_manager) {
                            m_sm->m_peer_tier_manager->record_latency(peer_id, peer->latency);
                        }
                    } catch (const std::exception& e) {
                        LOG_WARN("SM: Error parsing PONG payload: " + std::string(e.what()));
                    }
                }
                break;
            }
            case MessageType::CONTROL_CONNECT: {
                // Extract the remote public key from CONTROL_CONNECT payload FIRST
                // Format: "peer_id|public_key_hex"
                std::string remote_pk_hex;
                size_t delimiter = payload.find('|');
                if (delimiter != std::string::npos) {
                    remote_pk_hex = payload.substr(delimiter + 1);
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
                {
                    std::lock_guard<std::mutex> lock(m_sm->m_peers_mutex);
                    Peer* peer = m_sm->find_peer_by_id(peer_id);
                    if (peer && peer->connected) {
                        peer_was_connected = true;
                    }
                }
                
                // IMPORTANT: Only clear a READY Noise session if the remote peer's public key
                // is DIFFERENT from what we have stored. This indicates a true restart/re-key.
                // If the key is the SAME, the remote is just retrying CONTROL_CONNECT (common
                // during reconnect storms or endpoint flaps) and we should NOT disrupt the session.
                bool remote_key_changed = false;
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
                // Only clear READY session if: peer was connected AND key changed (true restart)
                if (peer_was_connected && remote_key_changed && m_sm->m_secure_session_manager) {
                    std::lock_guard<std::mutex> lock(m_sm->m_secure_session_mutex);
                    auto existing = m_sm->m_secure_session_manager->get_session(peer_id);
                    if (existing && existing->is_ready()) {
                        m_sm->m_secure_session_manager->remove_session(peer_id);
                        cleared_ready_noise = true;
                    }
                }
                if (cleared_ready_noise) {
                    LOG_INFO("MH: Cleared READY Noise session for peer " + peer_id + 
                             " upon CONTROL_CONNECT (peer_was_connected=true, key_changed=true)");
                    m_sm->clearQueuedMessages(peer_id);
                    if (m_sm->m_message_batcher) {
                        (void)m_sm->m_message_batcher->flush_peer(peer_id);
                    }
                }
#else
                (void)peer_was_connected;
                (void)remote_key_changed;
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
                }
#endif

                std::string ack_message = wire::encode_message(MessageType::CONTROL_CONNECT_ACK, ack_payload);
                m_sm->send_message_to_peer(event.network_id, ack_message);
                m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::CONNECT_SUCCESS});
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
                std::string remote_pk_hex;
                size_t delimiter = payload.find('|');
                if (delimiter != std::string::npos) {
                    remote_pk_hex = payload.substr(delimiter + 1);
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

                // IMPORTANT:
                // Do NOT clear an existing READY Noise session on CONTROL_CONNECT_ACK.
                // A CONNECT_ACK can arrive after the handshake completed (reordering / fast paths),
                // and clearing here causes READY->HANDSHAKING loops and breaks stable messaging.
                //
                // Restart safety is handled on inbound CONTROL_CONNECT (fresh connect) where the receiver
                // can deterministically clear READY sessions and re-handshake.
                
                m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::CONNECT_SUCCESS});
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
                        m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_REQUIRED});
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
                    m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_MESSAGE_RECEIVED});
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
                        std::string decrypted_message = session->receive_message(payload);
                        LOG_INFO("MH: Decryption complete, decrypted_length=" + std::to_string(decrypted_message.length()));
                        if (!decrypted_message.empty()) {
                            LOG_INFO("MH: Recursively processing decrypted message");
                            DataReceivedEvent decrypted_event{event.network_id, decrypted_message};
                            handleDataReceived(decrypted_event); // Recursive call with decrypted data
                        } else {
                            LOG_WARN("SM: Failed to decrypt message from " + peer_id + " (stale key/session?)");
                            Telemetry::getInstance().inc_counter("noise_decrypt_fail_total");

                            // Recovery path: likely stale keys (peer restart) or session desync.
                            // Clear READY session and trigger a fresh handshake/reconnect.
                            {
                                std::lock_guard<std::mutex> lock(m_sm->m_secure_session_mutex);
                                m_sm->m_secure_session_manager->remove_session(peer_id);
                            }
                            Telemetry::getInstance().inc_counter("noise_session_reset_total");
                            m_sm->clearQueuedMessages(peer_id);
                            if (m_sm->m_message_batcher) {
                                (void)m_sm->m_message_batcher->flush_peer(peer_id);
                            }

                            // If we are the deterministic initiator, start handshake now.
                            // Otherwise, send a CONTROL_CONNECT to prompt the initiator side.
                            if (m_sm->shouldInitiateNoiseHandshake(peer_id)) {
                                m_sm->pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_REQUIRED});
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
                                    connect_payload += "|" + pk_hex;
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
            if (!is_control && peer_connected &&
                (peer_state == PeerState::READY || peer_state == PeerState::CONNECTED ||
                 peer_state == PeerState::HANDSHAKING || peer_state == PeerState::DEGRADED)) {
                const int heartbeat_interval_sec = ConfigManager::getInstance().getHeartbeatIntervalSec();
                const int heartbeat_liveness_ms = std::max(5000, heartbeat_interval_sec * 3 * 1000);
                const auto silent_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - peer_last_seen).count();
                const auto discovery_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - peer_last_discovery_seen).count();

                if (silent_ms > heartbeat_liveness_ms) {
                    LOG_WARN("MH: Peer " + event.peerId + " appears stale while CONNECTED (silent_ms=" +
                             std::to_string(silent_ms) + ", discovery_ms=" + std::to_string(discovery_ms) +
                             ") - forcing reconnect and queueing message");

                    m_sm->queueMessage(event.peerId, internal_msg);
                    m_sm->pushEvent(FSMEvent{event.peerId, PeerEvent::DISCONNECT_DETECTED});
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
                        m_sm->queueMessage(event.peerId, internal_msg);
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
                        m_sm->queueMessage(event.peerId, internal_msg);
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
