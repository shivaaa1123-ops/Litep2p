#pragma once

#include <string>
#include <memory>
#include <vector>
#include <mutex>
#include <functional>
#include <unordered_map>

class SessionManager;

/**
 * @brief P2P Node wrapper - follows JNI bridge pattern
 * 
 * The engine (SessionManager) handles everything:
 * - Discovery startup and management
 * - Thread management  
 * - Finite state machine
 * - Connection sequencing
 * - All logging
 * 
 * This class just calls the engine functions.
 */
class P2PNode {
public:
    P2PNode();
    ~P2PNode();
    
    // Start engine - would call SessionManager::start() if compiled on Android
    bool start(int port, const std::string& peer_id, const std::string& comms_mode);
    
    // Stop engine
    void stop();
    
    // Connection
    void connectToPeer(const std::string& peer_id);
    void addPeer(const std::string& peer_id, const std::string& ip, int port);
    
    // Send message
    void sendMessageToPeer(const std::string& peer_id, const std::string& message);

    // Noise Protocol Key Management
    std::string getLocalPublicKey() const;
    void addPeerPublicKey(const std::string& peer_id, const std::string& public_key_hex);

    // Proxy module controls (no-ops if proxy module not compiled).
    // role: off|gateway|exit|client|both
    bool setProxyRole(const std::string& role, std::string* error = nullptr);
    std::string getProxySettingsSummary(std::string* error = nullptr) const;
    
    bool isRunning() const { return running_; }
    std::string getPeerId() const { return peer_id_; }
    std::string getLastReceivedMessage() const;
    
    // Get list of discovered peers (thread-safe)
    std::vector<std::string> getDiscoveredPeers() const;

    // Desktop UI integration (optional)
    // These callbacks may be invoked from engine threads.
    void setPeerEventCallbacks(
        std::function<void(const std::string& peer_id)> on_discovered,
        std::function<void(const std::string& peer_id)> on_connected,
        std::function<void(const std::string& peer_id)> on_disconnected);

    void setMessageEventCallback(
        std::function<void(const std::string& peer_id, const std::string& message)> on_message);

    void clearEventCallbacks();

private:
    bool running_;
    std::string peer_id_;
    std::unique_ptr<SessionManager> session_manager_;
    
    mutable std::mutex message_mutex_;
    std::string last_received_message_;
    void updateLastReceivedMessage(const std::string& message);

    mutable std::mutex peers_mutex_;
    std::vector<std::string> discovered_peers_;

    // Track peer existence/connection state to emit events.
    std::unordered_map<std::string, bool> peer_connected_state_;

    // Callbacks for desktop UI (protected by callbacks_mutex_)
    mutable std::mutex callbacks_mutex_;
    std::function<void(const std::string&)> on_peer_discovered_cb_;
    std::function<void(const std::string&)> on_peer_connected_cb_;
    std::function<void(const std::string&)> on_peer_disconnected_cb_;
    std::function<void(const std::string&, const std::string&)> on_message_cb_;
};
