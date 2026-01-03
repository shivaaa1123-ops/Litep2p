#ifndef SECURE_SESSION_H
#define SECURE_SESSION_H

#include "noise_nk.h"
#include "noise_key_store.h"
#include <string>
#include <memory>
#include <map>
#include <mutex>
#include <vector>

// SecureSession wraps Noise NK sessions for integration with SessionManager
// Handles Noise handshakes transparently and encrypts all messages

class SecureSession {
public:
    SecureSession(const std::string& peer_id,
                  NoiseNKSession::Role role,
                  NoiseNKManager* manager,
                  NoiseKeyStore* key_store);
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

    // Get role
    NoiseNKSession::Role get_role() const { return m_role; }

    // True if this session has already sent the first initiator handshake message.
    // Used to distinguish valid responder responses from simultaneous-initiation glare.
    bool handshake_initiated() const { return m_handshake_initiated; }

    // Get session status
    std::string get_status() const;

private:
    std::shared_ptr<NoiseNKSession> ensure_session();
    static std::string vector_to_string(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> string_to_vector(const std::string& data);

    std::string m_peer_id;
    NoiseNKSession::Role m_role;
    NoiseNKManager* m_noise_manager;
    NoiseKeyStore* m_key_store;
    mutable std::shared_ptr<NoiseNKSession> m_noise_session;
    bool m_handshake_initiated;
};

// SecureSessionManager manages multiple SecureSession instances
class SecureSessionManager {
public:
    SecureSessionManager();
    ~SecureSessionManager();

    void set_noise_backend(NoiseNKManager* manager, NoiseKeyStore* key_store);

    // Get or create a secure session with a peer
    std::shared_ptr<SecureSession> get_or_create_session(
        const std::string& peer_id, 
        NoiseNKSession::Role role
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
    SecureSessionManager(const SecureSessionManager&) = delete;
    SecureSessionManager& operator=(const SecureSessionManager&) = delete;

    std::map<std::string, std::shared_ptr<SecureSession>> m_sessions;
    NoiseNKManager* m_noise_manager;
    NoiseKeyStore* m_key_store;
    mutable std::mutex m_mutex;
};

#endif // SECURE_SESSION_H
