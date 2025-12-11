#ifndef SECURE_SESSION_H
#define SECURE_SESSION_H

#include "noise_protocol.h"
#include <string>
#include <memory>
#include <map>
#include <mutex>

// SecureSession wraps NoiseSession for easy integration with SessionManager
// Handles Noise handshakes transparently and encrypts all messages

class SecureSession {
public:
    SecureSession(const std::string& peer_id, NoiseSession::Role role);
    ~SecureSession();

    // Initialize handshake and return first message to send
    std::string start_handshake();

    // Process handshake message from peer
    // Returns response to send back, or empty if handshake complete
    std::string process_handshake(const std::string& message);

    // Check if handshake is complete and session is ready
    bool is_ready() const;

    // Send a message (automatically encrypted)
    std::string send_message(const std::string& plaintext);

    // Receive a message (automatically decrypted)
    std::string receive_message(const std::string& ciphertext);

    // Get peer ID
    const std::string& get_peer_id() const { return m_peer_id; }

    // Get session status
    std::string get_status() const;

private:
    std::string m_peer_id;
    std::unique_ptr<NoiseSession> m_noise_session;
    bool m_handshake_initiated;
};

// SecureSessionManager manages multiple SecureSession instances
class SecureSessionManager {
public:
    SecureSessionManager();
    ~SecureSessionManager();

    // Get or create a secure session with a peer
    std::shared_ptr<SecureSession> get_or_create_session(
        const std::string& peer_id, 
        NoiseSession::Role role
    );

    // Remove a session
    void remove_session(const std::string& peer_id);

    // Get existing session
    std::shared_ptr<SecureSession> get_session(const std::string& peer_id);

    // Check if session exists and is ready
    bool is_session_ready(const std::string& peer_id);

    // Clear all sessions
    void clear_all();

private:
    std::map<std::string, std::shared_ptr<SecureSession>> m_sessions;
    mutable std::mutex m_mutex;
};

#endif // SECURE_SESSION_H
