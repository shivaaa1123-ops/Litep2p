#ifndef NOISE_PROTOCOL_H
#define NOISE_PROTOCOL_H

#include <string>
#include <cstdint>
#include <memory>
#include <vector>

// Noise Protocol NN implementation
// Suitable for P2P discovery and communication without pre-shared keys
// Provides:
// - ECDH key exchange (using Curve25519)
// - Forward secrecy (ephemeral keys)
// - Authenticated encryption (ChaCha20-Poly1305)
// - Replay protection via nonces

class NoiseSession {
public:
    enum class Role {
        INITIATOR,
        RESPONDER
    };

    enum class State {
        INITIALIZED,
        HANDSHAKE_PENDING,
        HANDSHAKE_COMPLETE,
        FAILED
    };

    // Constructor - creates a new Noise session
    // role: INITIATOR (client) or RESPONDER (server)
    // local_static_key: 32-byte static public key (can be derived from peer ID)
    NoiseSession(Role role, const std::string& local_static_key);
    
    ~NoiseSession();

    // Handshake phase
    // Returns the message to send to peer (handshake_message)
    // Returns empty string on error
    std::string initiate_handshake();
    
    // Process incoming handshake message from peer
    // Returns response message to send back (or empty if final message)
    // Returns empty string on error
    std::string process_handshake_message(const std::string& message);

    // Check if handshake is complete
    bool is_handshake_complete() const { return m_state == State::HANDSHAKE_COMPLETE; }

    // Encrypt a message using the established session key
    // Only valid after handshake is complete
    std::string encrypt_message(const std::string& plaintext);

    // Decrypt a message using the established session key
    std::string decrypt_message(const std::string& ciphertext);

    // Get current state
    State get_state() const { return m_state; }

    // Get error message if handshake failed
    std::string get_error() const { return m_error; }

    // Reset session for new handshake
    void reset();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
    Role m_role;
    State m_state;
    std::string m_error;
    uint64_t m_nonce_counter; // For replay protection

    // Internal state tracking
    void set_state(State state) { m_state = state; }
    void set_error(const std::string& error) { m_error = error; m_state = State::FAILED; }
};

// Utility functions
namespace noise_utils {
    // Generate a static keypair (32-byte private, 32-byte public)
    // Derived from peer ID or random
    std::string generate_static_keypair(std::string& out_private_key);
    
    // Get public key from private key (Curve25519)
    std::string get_public_key(const std::string& private_key);
    
    // Generate random ephemeral keypair
    std::pair<std::string, std::string> generate_ephemeral_keypair();
}

#endif // NOISE_PROTOCOL_H
