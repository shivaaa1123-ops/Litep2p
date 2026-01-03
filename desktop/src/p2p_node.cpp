#include "p2p_node.h"
#include "logger.h"
#include "session_manager.h"
#include <sstream>
#include <iomanip>

#if ENABLE_PROXY_MODULE
#include "proxy_endpoint.h"
#endif

P2PNode::P2PNode() : running_(false), peer_id_("") {
    session_manager_ = std::make_unique<SessionManager>();
}

P2PNode::~P2PNode() {
    if (running_) {
        stop();
    }
}

bool P2PNode::start(int port, const std::string& peer_id, const std::string& comms_mode) {
    if (running_) {
        nativeLog("ERROR: Engine already running");
        return false;
    }
    
    nativeLog("Starting LiteP2P engine...");
    
    peer_id_ = peer_id;
    
    // Callback for peer updates
    auto peer_callback = [this](const std::vector<Peer>& peers) {
        // Build formatted list and current state snapshot outside locks.
        std::vector<std::string> formatted;
        formatted.reserve(peers.size());

        std::unordered_map<std::string, bool> current_state;
        current_state.reserve(peers.size());

        for (const auto& peer : peers) {
            std::string status = peer.connected ? "CONNECTED" : "DISCONNECTED";
            formatted.push_back(peer.id + " (" + peer.network_id + ") [" + status + "]");
            current_state[peer.id] = peer.connected;
        }

        // Compute deltas vs previous snapshot and update storage.
        std::vector<std::string> newly_discovered;
        std::vector<std::string> now_connected;
        std::vector<std::string> now_disconnected;

        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            // Determine new peers and connection transitions
            for (const auto& kv : current_state) {
                const std::string& id = kv.first;
                bool connected = kv.second;

                auto it_prev = peer_connected_state_.find(id);
                if (it_prev == peer_connected_state_.end()) {
                    newly_discovered.push_back(id);
                    if (connected) {
                        now_connected.push_back(id);
                    }
                } else {
                    bool prev_connected = it_prev->second;
                    if (!prev_connected && connected) {
                        now_connected.push_back(id);
                    } else if (prev_connected && !connected) {
                        now_disconnected.push_back(id);
                    }
                }
            }

            // Also detect peers that disappeared from the list.
            // Treat disappearance as disconnected.
            if (!peer_connected_state_.empty()) {
                for (const auto& prev_kv : peer_connected_state_) {
                    if (current_state.find(prev_kv.first) == current_state.end()) {
                        if (prev_kv.second) {
                            now_disconnected.push_back(prev_kv.first);
                        }
                    }
                }
            }

            discovered_peers_ = std::move(formatted);
            peer_connected_state_ = std::move(current_state);
        }

        // Copy callbacks under lock, then invoke without holding locks.
        std::function<void(const std::string&)> cb_discovered;
        std::function<void(const std::string&)> cb_connected;
        std::function<void(const std::string&)> cb_disconnected;
        {
            std::lock_guard<std::mutex> lock(callbacks_mutex_);
            cb_discovered = on_peer_discovered_cb_;
            cb_connected = on_peer_connected_cb_;
            cb_disconnected = on_peer_disconnected_cb_;
        }

        if (cb_discovered) {
            for (const auto& id : newly_discovered) cb_discovered(id);
        }
        if (cb_connected) {
            for (const auto& id : now_connected) cb_connected(id);
        }
        if (cb_disconnected) {
            for (const auto& id : now_disconnected) cb_disconnected(id);
        }
    };

    try {
        session_manager_->setMessageReceivedCallback([this](const std::string& peer_id, const std::string& message) {
            std::string formatted = "Message received from " + peer_id + ": " + message;
            nativeLog(formatted);
            updateLastReceivedMessage(formatted);

            std::function<void(const std::string&, const std::string&)> cb;
            {
                std::lock_guard<std::mutex> lock(callbacks_mutex_);
                cb = on_message_cb_;
            }
            if (cb) {
                cb(peer_id, message);
            }
        });

        session_manager_->start(port, peer_callback, comms_mode, peer_id);
        nativeLog("LiteP2P engine started successfully.");
        running_ = true;
        return true;
    } catch (const std::exception& e) {
        nativeLog("ERROR: Failed to start engine: " + std::string(e.what()));
        return false;
    }
}

void P2PNode::setPeerEventCallbacks(
    std::function<void(const std::string& peer_id)> on_discovered,
    std::function<void(const std::string& peer_id)> on_connected,
    std::function<void(const std::string& peer_id)> on_disconnected) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    on_peer_discovered_cb_ = std::move(on_discovered);
    on_peer_connected_cb_ = std::move(on_connected);
    on_peer_disconnected_cb_ = std::move(on_disconnected);
}

void P2PNode::setMessageEventCallback(
    std::function<void(const std::string& peer_id, const std::string& message)> on_message) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    on_message_cb_ = std::move(on_message);
}

void P2PNode::clearEventCallbacks() {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    on_peer_discovered_cb_ = nullptr;
    on_peer_connected_cb_ = nullptr;
    on_peer_disconnected_cb_ = nullptr;
    on_message_cb_ = nullptr;
}

std::string P2PNode::getLastReceivedMessage() const {
    std::lock_guard<std::mutex> lock(message_mutex_);
    return last_received_message_;
}

void P2PNode::updateLastReceivedMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(message_mutex_);
    last_received_message_ = message;
}

void P2PNode::stop() {
    if (!running_) {
        return;
    }
    
    nativeLog("Stopping LiteP2P engine...");
    
    if (session_manager_) {
        session_manager_->stop();
    }
    
    nativeLog("Engine stopped.");
    running_ = false;
}

void P2PNode::connectToPeer(const std::string& peer_id) {
    if (!running_) {
        nativeLog("ERROR: Cannot connect - engine not running");
        return;
    }
    
    nativeLog("UI requested connection to " + peer_id);
    if (session_manager_) {
        session_manager_->connectToPeer(peer_id);
    }
}

void P2PNode::addPeer(const std::string& peer_id, const std::string& ip, int port) {
    if (!running_) {
        nativeLog("ERROR: Cannot add peer - engine not running");
        return;
    }
    
    std::string network_id = ip + ":" + std::to_string(port);
    nativeLog("Adding peer manually: " + peer_id + " at " + network_id);
    if (session_manager_) {
        session_manager_->addPeer(peer_id, network_id);
    }
}

void P2PNode::sendMessageToPeer(const std::string& peer_id, const std::string& message) {
    if (!running_) {
        nativeLog("ERROR: Cannot send message - engine not running");
        return;
    }
    
    nativeLog("Sending message to " + peer_id);
    if (session_manager_) {
        session_manager_->sendMessageToPeer(peer_id, message);
    }
}

std::vector<std::string> P2PNode::getDiscoveredPeers() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    return discovered_peers_;
}

std::string P2PNode::getLocalPublicKey() const {
    if (!session_manager_) return "";
    auto key = session_manager_->get_local_static_public_key();
    std::stringstream ss;
    for (uint8_t b : key) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return ss.str();
}

void P2PNode::addPeerPublicKey(const std::string& peer_id, const std::string& public_key_hex) {
    if (!session_manager_) return;
    
    std::vector<uint8_t> key;
    for (size_t i = 0; i < public_key_hex.length(); i += 2) {
        std::string byteString = public_key_hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        key.push_back(byte);
    }
    
    session_manager_->register_peer_nk_key(peer_id, key);
    nativeLog("Added public key for peer: " + peer_id);
}

bool P2PNode::setProxyRole(const std::string& role, std::string* error) {
#if ENABLE_PROXY_MODULE
    if (!session_manager_) {
        if (error) *error = "session manager not initialized";
        return false;
    }

    proxy::ProxyEndpoint* ep = session_manager_->get_proxy_endpoint();
    if (!ep) {
        if (error) *error = "proxy endpoint not available";
        return false;
    }

    proxy::ProxySettings s = ep->settings();
    std::string r = role;
    for (auto& c : r) c = static_cast<char>(::tolower(c));

    if (r == "off" || r == "0" || r == "false") {
        s.enable_gateway = false;
        s.enable_client = false;
        s.enable_test_echo = false;
    } else if (r == "gateway" || r == "exit") {
        s.enable_gateway = true;
        s.enable_client = false;
        s.enable_test_echo = false;
    } else if (r == "client") {
        s.enable_gateway = false;
        s.enable_client = true;
        // Leave test_echo as-is unless explicitly disabled.
    } else if (r == "both") {
        s.enable_gateway = true;
        s.enable_client = true;
        s.enable_test_echo = false;
    } else {
        if (error) *error = "unknown role (expected off|gateway|exit|client|both)";
        return false;
    }

    session_manager_->configure_proxy(s);
    return true;
#else
    (void)role;
    if (error) *error = "proxy module not compiled";
    return false;
#endif
}

std::string P2PNode::getProxySettingsSummary(std::string* error) const {
#if ENABLE_PROXY_MODULE
    if (!session_manager_) {
        if (error) *error = "session manager not initialized";
        return "proxy: unavailable";
    }

    proxy::ProxyEndpoint* ep = session_manager_->get_proxy_endpoint();
    if (!ep) {
        if (error) *error = "proxy endpoint not available";
        return "proxy: unavailable";
    }

    const proxy::ProxySettings s = ep->settings();
    std::string out = "proxy: gateway=";
    out += (s.enable_gateway ? "on" : "off");
    out += " client=";
    out += (s.enable_client ? "on" : "off");
    out += " test_echo=";
    out += (s.enable_test_echo ? "on" : "off");
    return out;
#else
    if (error) *error = "proxy module not compiled";
    return "proxy: not compiled";
#endif
}

