#ifndef NOISE_NK_H
#define NOISE_NK_H

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <map>
#include <mutex>

/**
 * Noise NK Pattern Implementation
 * 
 * Pattern: NK (Static Key Known by Initiator)
 * - Initiator knows peer's static public key beforehand
 * - Responder authenticates with their static private key
 * - Provides mutual authentication and forward secrecy
 * - Defense against MITM on untrusted networks
 * 
 * Handshake Flow:
 *   -> e                        (Initiator ephemeral)
 *   <- e, ee, es                (Responder ephemeral, DH with initiator's eph, DH with initiator's static - AUTHENTICATION!)
 *   -> se                       (Initiator DH with responder's static - confirmation)
 *
 * Noise Protocol Spec: https://noiseprotocol.org/noise.html
 */

class NoiseNKSession {
public:
    enum class Role {
        INITIATOR,  // Knows peer's static key
        RESPONDER   // Proves identity with static key
    };

    enum class State {
        NEW,           // Just created
        HANDSHAKE_1,   // Sent/received first message (e)
        HANDSHAKE_2,   // Sent/received second message (e, ee, es)
        HANDSHAKE_3,   // Sent/received third message (se) - COMPLETE
        READY,         // Can send/receive application data
        FAILED         // Handshake failed, cannot recover
    };

    NoiseNKSession(
        const std::string& peer_id,
        Role role,
        const std::vector<uint8_t>& peer_ephemeral_or_static_pk,  // Peer's key (initiator's ephemeral for responder, responder's static for initiator)
        const std::vector<uint8_t>& local_static_pk,              // Our static public key
        const std::vector<uint8_t>& local_static_sk = {}          // Our static secret key (only needed for responder)
    );

    ~NoiseNKSession() = default;

    /**
     * Start handshake (for initiator)
     * Returns first handshake message (contains ephemeral public key + encrypted payload)
     */
    std::vector<uint8_t> start_handshake();

    /**
     * Process handshake message
     * msg: handshake message from peer
     * Returns: response message (empty if already complete or failed)
     */
    std::vector<uint8_t> process_handshake(const std::vector<uint8_t>& msg);

    /**
     * Encrypt application data (after handshake complete)
     * plaintext: data to encrypt
     * Returns: ciphertext with authentication tag
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);

    /**
     * Decrypt application data (after handshake complete)
     * ciphertext: data to decrypt (with authentication tag)
     * Returns: plaintext (empty on authentication failure)
     */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);

    /**
     * Check if handshake is complete and session is ready
     */
    bool is_ready() const { return m_state == State::READY; }

    /**
     * Get current handshake state
     */
    State get_state() const { return m_state; }

    /**
     * Get peer ID
     */
    const std::string& get_peer_id() const { return m_peer_id; }

    /**
     * Get role (initiator or responder)
     */
    Role get_role() const { return m_role; }

    /**
     * Check if this is initiator
     */
    bool is_initiator() const { return m_role == Role::INITIATOR; }

    /**
     * Get session ID (for logging/debugging)
     */
    const std::string& get_session_id() const { return m_session_id; }

private:
    // Session metadata
    std::string m_peer_id;
    std::string m_session_id;
    Role m_role;
    State m_state;

    // Static keys (32 bytes each, Curve25519)
    std::vector<uint8_t> m_responder_static_pk;  // Responder's static public key
    std::vector<uint8_t> m_responder_static_sk;  // Responder's static secret key (only for responder role)

    // Ephemeral keys (generated fresh per handshake)
    std::vector<uint8_t> m_local_ephemeral_sk;   // Our ephemeral secret key (32 bytes)
    std::vector<uint8_t> m_local_ephemeral_pk;   // Our ephemeral public key (32 bytes)
    std::vector<uint8_t> m_peer_ephemeral_pk;    // Peer's ephemeral public key (32 bytes)

    // Session symmetric keys (derived from ECDH)
    std::vector<uint8_t> m_send_key;             // Our send key (32 bytes for ChaCha20)
    std::vector<uint8_t> m_recv_key;             // Our receive key (32 bytes for ChaCha20)
    std::vector<uint8_t> m_send_nonce;           // Send nonce (12 bytes for ChaCha20-Poly1305)
    std::vector<uint8_t> m_recv_nonce;           // Receive nonce (12 bytes for ChaCha20-Poly1305)

    // Message counters for nonce generation (prevent reuse)
    uint32_t m_send_counter;
    uint32_t m_recv_counter;

    // Handshake state machine
    int m_handshake_step;  // 0, 1, 2, 3

    // Helper methods
    std::vector<uint8_t> generate_ephemeral_keypair();
    void perform_dh(const std::vector<uint8_t>& secret_key, const std::vector<uint8_t>& public_key, std::vector<uint8_t>& result);
    void derive_keys();
    void increment_nonce(std::vector<uint8_t>& nonce);

    // Noise protocol helpers
    std::vector<uint8_t> chacha20poly1305_encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> chacha20poly1305_decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& ciphertext);
};

/**
 * Manages Noise NK sessions with peers
 * - Creates initiator/responder sessions
 * - Stores and retrieves sessions by peer ID
 * - Manages peer static public keys
 */
class NoiseNKManager {
public:
    NoiseNKManager();
    ~NoiseNKManager() = default;

    /**
     * Register or update peer's static public key
     * Must be done before initiating handshake with peer
     * In production: exchange keys via QR code, NFC, or initial setup
     */
    void register_peer_key(const std::string& peer_id, const std::vector<uint8_t>& static_pk);

    /**
     * Get peer's registered static public key
     * Returns empty vector if not found
     */
    std::vector<uint8_t> get_peer_key(const std::string& peer_id) const;

    /**
     * Set our local static private key
     * Only needed once at startup
     * Generate with generate_static_keypair() or load from storage
     */
    void set_local_static_key(const std::vector<uint8_t>& static_sk, const std::vector<uint8_t>& static_pk);

    /**
     * Get our local static public key
     * Share this with peers via discovery/QR code
     */
    std::vector<uint8_t> get_local_static_pk() const;

    /**
     * Create initiator session (we know peer's static key)
     */
    std::shared_ptr<NoiseNKSession> create_initiator_session(const std::string& peer_id);

    /**
     * Create responder session (we prove identity with our static key)
     */
    std::shared_ptr<NoiseNKSession> create_responder_session(const std::string& peer_id);

    /**
     * Get existing session by peer ID
     * Returns nullptr if not found
     */
    std::shared_ptr<NoiseNKSession> get_session(const std::string& peer_id) const;

    /**
     * Get or create session (handles both initiator and responder cases)
     * If session exists, return it. Otherwise create responder session.
     */
    std::shared_ptr<NoiseNKSession> get_or_create_session(const std::string& peer_id, NoiseNKSession::Role role);

    /**
     * Remove session (after completion or failure)
     */
    void remove_session(const std::string& peer_id);

    /**
     * Clear all sessions
     */
    void clear_sessions();

    /**
     * Generate static keypair for this peer
     * Call once at first startup, save to secure storage
     */
    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generate_static_keypair();

    /**
     * Debug: list all known peers
     */
    std::vector<std::string> get_known_peers() const;

private:
    mutable std::mutex m_sessions_mutex;
    mutable std::mutex m_keys_mutex;

    // Active sessions with peers
    std::map<std::string, std::shared_ptr<NoiseNKSession>> m_sessions;

    // Known peer static public keys (loaded from storage)
    std::map<std::string, std::vector<uint8_t>> m_peer_keys;

    // Our local static keys
    std::vector<uint8_t> m_local_static_sk;  // Secret key (32 bytes)
    std::vector<uint8_t> m_local_static_pk;  // Public key (32 bytes)
};

#endif // NOISE_NK_H
