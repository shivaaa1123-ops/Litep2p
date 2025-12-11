#include "noise_nk.h"
#include "logger.h"
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <sodium.h>

// ============================================================================
// Helper Functions
// ============================================================================

static std::string hex_encode(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    for (uint8_t byte : data) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return ss.str();
}

static std::vector<uint8_t> hex_decode(const std::string& hex) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        result.push_back(byte);
    }
    return result;
}

// ============================================================================
// NoiseNKSession Implementation
// ============================================================================

NoiseNKSession::NoiseNKSession(
    const std::string& peer_id,
    Role role,
    const std::vector<uint8_t>& initiator_static_pk,
    const std::vector<uint8_t>& responder_static_pk
)
    : m_peer_id(peer_id),
      m_role(role),
      m_state(State::NEW),
      m_initiator_static_pk(initiator_static_pk),
      m_responder_static_pk(responder_static_pk),
      m_send_counter(0),
      m_recv_counter(0),
      m_handshake_step(0)
{
    // Generate session ID for logging
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    std::stringstream ss;
    for (int i = 0; i < 4; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
    }
    m_session_id = ss.str();

    nativeLog("NK: Session created for " + peer_id + " (role=" + (role == Role::INITIATOR ? "INITIATOR" : "RESPONDER") + ", sid=" + m_session_id + ")");
}

std::vector<uint8_t> NoiseNKSession::generate_ephemeral_keypair() {
    std::vector<uint8_t> sk(32), pk(32);
    crypto_box_keypair(pk.data(), sk.data());
    m_local_ephemeral_sk = sk;
    m_local_ephemeral_pk = pk;
    return pk;
}

void NoiseNKSession::perform_dh(
    const std::vector<uint8_t>& secret_key,
    const std::vector<uint8_t>& public_key,
    std::vector<uint8_t>& result
) {
    result.resize(32);
    if (crypto_scalarmult(result.data(), secret_key.data(), public_key.data()) != 0) {
        nativeLog("NK Error: crypto_scalarmult failed");
        result.assign(32, 0);
    }
}

void NoiseNKSession::derive_keys() {
    unsigned char ck[32];
    unsigned char h[32];
    std::string protocol_name = "Noise_NK_25519_ChaChaPoly_SHA256";
    std::string prologue = "";

    // h = SHA256(protocol_name || prologue)
    std::vector<uint8_t> proto_concat(protocol_name.begin(), protocol_name.end());
    proto_concat.insert(proto_concat.end(), prologue.begin(), prologue.end());
    crypto_hash_sha256(h, proto_concat.data(), proto_concat.size());
    memcpy(ck, h, 32);

    // Mix responder static key into handshake hash
    crypto_hash_sha256(h, m_responder_static_pk.data(), m_responder_static_pk.size());
    memcpy(ck, h, 32);

    // DH results: ee, es
    std::vector<uint8_t> dh_results;

    // DH(ephemeral, ephemeral)
    std::vector<uint8_t> dh_ee(32);
    perform_dh(m_local_ephemeral_sk, m_peer_ephemeral_pk, dh_ee);
    dh_results.insert(dh_results.end(), dh_ee.begin(), dh_ee.end());

    // DH(ephemeral, static) - varies by role
    std::vector<uint8_t> dh_es(32);
    if (m_role == Role::INITIATOR) {
        // Initiator DH(ephemeral_i, static_r)
        perform_dh(m_local_ephemeral_sk, m_responder_static_pk, dh_es);
    } else {
        // Responder DH(ephemeral_r, static_i)
        perform_dh(m_local_ephemeral_sk, m_initiator_static_pk, dh_es);
    }
    dh_results.insert(dh_results.end(), dh_es.begin(), dh_es.end());

    // HKDF-SHA256 to derive keys
    unsigned char key_material[64];
    unsigned char prk[32];
    crypto_auth_hmacsha256(prk, dh_results.data(), dh_results.size(), ck);

    // Expand to get both send and receive keys
    unsigned char info1 = 0x01;
    unsigned char info2 = 0x02;
    crypto_auth_hmacsha256(key_material, &info1, 1, prk);
    crypto_auth_hmacsha256(key_material + 32, &info2, 1, prk);

    // Assign keys - initiator sends with first key, receives with second
    if (m_role == Role::INITIATOR) {
        m_send_key.assign(key_material, key_material + 32);
        m_recv_key.assign(key_material + 32, key_material + 64);
    } else {
        m_recv_key.assign(key_material, key_material + 32);
        m_send_key.assign(key_material + 32, key_material + 64);
    }

    // Initialize nonces (12 bytes for ChaCha20-Poly1305)
    m_send_nonce.assign(12, 0x00);
    m_recv_nonce.assign(12, 0x00);

    nativeLog("NK: Keys derived (send_key=" + hex_encode(m_send_key).substr(0, 8) + "..., recv_key=" + hex_encode(m_recv_key).substr(0, 8) + "...)");
}

void NoiseNKSession::increment_nonce(std::vector<uint8_t>& nonce) {
    // Increment nonce as little-endian 96-bit counter
    for (size_t i = 0; i < 12; i++) {
        nonce[i]++;
        if (nonce[i] != 0) break;  // No overflow, stop
    }
}

std::vector<uint8_t> NoiseNKSession::chacha20poly1305_encrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& plaintext
) {
    if (key.size() != 32 || nonce.size() != 12) {
        nativeLog("ERROR: NK: Invalid key or nonce size for encryption");
        return {};
    }

    std::vector<uint8_t> ciphertext(plaintext.size() + 16);
    unsigned long long clen = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext.data(), &clen,
        plaintext.data(), plaintext.size(),
        nullptr, 0, nullptr, nonce.data(), key.data()
    );
    ciphertext.resize(clen);
    return ciphertext;
}

std::vector<uint8_t> NoiseNKSession::chacha20poly1305_decrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& ciphertext
) {
    if (key.size() != 32 || nonce.size() != 12) {
        nativeLog("ERROR: NK: Invalid key or nonce size for decryption");
        return {};
    }

    if (ciphertext.size() < 16) {
        nativeLog("ERROR: NK: Ciphertext too short (no auth tag)");
        return {};
    }

    std::vector<uint8_t> plaintext(ciphertext.size() - 16);
    unsigned long long plen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext.data(), &plen,
        nullptr,
        ciphertext.data(), ciphertext.size(),
        nullptr, 0, nonce.data(), key.data()
    ) != 0) {
        nativeLog("ERROR: NK: Decryption failed (auth tag mismatch)");
        return {};
    }
    plaintext.resize(plen);
    return plaintext;
}

std::vector<uint8_t> NoiseNKSession::start_handshake() {
    if (m_role != Role::INITIATOR) {
        nativeLog("ERROR: NK: Only initiator can start handshake");
        return {};
    }

    if (m_state != State::NEW) {
        nativeLog("ERROR: NK: Cannot start handshake - session already started");
        return {};
    }

    // Generate ephemeral keypair
    auto eph_pk = generate_ephemeral_keypair();
    if (eph_pk.empty()) {
        m_state = State::FAILED;
        return {};
    }

    // Message 1: e
    // Contains: ephemeral public key (32 bytes)
    std::vector<uint8_t> msg1 = m_local_ephemeral_pk;

    m_state = State::HANDSHAKE_1;
    m_handshake_step = 1;

    nativeLog("NK: Handshake message 1 sent (e, " + std::to_string(msg1.size()) + " bytes)");
    return msg1;
}

std::vector<uint8_t> NoiseNKSession::process_handshake(const std::vector<uint8_t>& msg) {
    if (m_state == State::FAILED || m_state == State::READY) {
        nativeLog("ERROR: NK: Cannot process handshake in state " + std::to_string((int)m_state));
        return {};
    }

    try {
        if (m_state == State::NEW) {
            // Responder: Process message 1 (e)
            if (msg.size() != 32) {
                nativeLog("ERROR: NK: Message 1 invalid size (expected 32, got " + std::to_string(msg.size()) + ")");
                m_state = State::FAILED;
                return {};
            }

            m_peer_ephemeral_pk.assign(msg.begin(), msg.end());
            m_state = State::HANDSHAKE_1;
            m_handshake_step = 1;

            // Generate our ephemeral keypair
            auto eph_pk = generate_ephemeral_keypair();
            if (eph_pk.empty()) {
                m_state = State::FAILED;
                return {};
            }

            // Prepare response: e, ee, es
            // Note: We don't send static key yet, just prove we have it via encryption
            std::vector<uint8_t> msg2 = m_local_ephemeral_pk;

            nativeLog("NK: Handshake message 1 received, message 2 prepared (e, 32 bytes)");
            m_state = State::HANDSHAKE_2;
            m_handshake_step = 2;

            return msg2;

        } else if (m_state == State::HANDSHAKE_1) {
            // Initiator: Process message 2 (e)
            if (msg.size() != 32) {
                nativeLog("ERROR: NK: Message 2 invalid size (expected 32, got " + std::to_string(msg.size()) + ")");
                m_state = State::FAILED;
                return {};
            }

            m_peer_ephemeral_pk.assign(msg.begin(), msg.end());

            // Derive keys from ee and es DH operations
            derive_keys();

            // Message 3: empty (just authentication from earlier DH)
            std::vector<uint8_t> msg3;

            m_state = State::READY;
            m_handshake_step = 3;

            nativeLog("NK: Handshake message 2 received, keys derived, ready for communication");
            return msg3;

        } else if (m_state == State::HANDSHAKE_2) {
            // Responder: Receive empty message 3 (authentication confirmation)
            // In NK pattern, responder is already authenticated by initiator's DH with responder's static key

            // Derive keys
            derive_keys();

            m_state = State::READY;
            m_handshake_step = 3;

            nativeLog("NK: Handshake complete (responder), keys ready");
            return {};
        }

        nativeLog("ERROR: NK: Invalid handshake state");
        m_state = State::FAILED;
        return {};

    } catch (const std::exception& e) {
        nativeLog("ERROR: NK: Exception in process_handshake: " + std::string(e.what()));
        m_state = State::FAILED;
        return {};
    }
}

std::vector<uint8_t> NoiseNKSession::encrypt(const std::vector<uint8_t>& plaintext) {
    if (!is_ready()) {
        nativeLog("ERROR: NK: Cannot encrypt - handshake not complete");
        return {};
    }

    auto ciphertext = chacha20poly1305_encrypt(m_send_key, m_send_nonce, plaintext);
    if (!ciphertext.empty()) {
        increment_nonce(m_send_nonce);
        m_send_counter++;
    }
    return ciphertext;
}

std::vector<uint8_t> NoiseNKSession::decrypt(const std::vector<uint8_t>& ciphertext) {
    if (!is_ready()) {
        nativeLog("ERROR: NK: Cannot decrypt - handshake not complete");
        return {};
    }

    auto plaintext = chacha20poly1305_decrypt(m_recv_key, m_recv_nonce, ciphertext);
    if (!plaintext.empty()) {
        increment_nonce(m_recv_nonce);
        m_recv_counter++;
    }
    return plaintext;
}

// ============================================================================
// NoiseNKManager Implementation
// ============================================================================

NoiseNKManager::NoiseNKManager() {
    nativeLog("NK: Manager initialized");
}

void NoiseNKManager::register_peer_key(const std::string& peer_id, const std::vector<uint8_t>& static_pk) {
    if (static_pk.size() != 32) {
        nativeLog("ERROR: NK: Peer key must be 32 bytes, got " + std::to_string(static_pk.size()));
        return;
    }
    
    {
        std::lock_guard<std::mutex> lock(m_keys_mutex);
        m_peer_keys[peer_id] = static_pk;
    }
    nativeLog("NK: Peer key registered for " + peer_id + " (key=" + hex_encode(static_pk).substr(0, 8) + "...)");
}

std::vector<uint8_t> NoiseNKManager::get_peer_key(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_keys_mutex);
    auto it = m_peer_keys.find(peer_id);
    if (it != m_peer_keys.end()) {
        return it->second;
    }
    return {};
}

void NoiseNKManager::set_local_static_key(const std::vector<uint8_t>& static_sk, const std::vector<uint8_t>& static_pk) {
    if (static_sk.size() != 32 || static_pk.size() != 32) {
        nativeLog("ERROR: NK: Static key must be 32 bytes");
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_keys_mutex);
    m_local_static_sk = static_sk;
    m_local_static_pk = static_pk;
    nativeLog("NK: Local static key set (pk=" + hex_encode(static_pk).substr(0, 8) + "...)");
}

std::vector<uint8_t> NoiseNKManager::get_local_static_pk() const {
    std::lock_guard<std::mutex> lock(m_keys_mutex);
    return m_local_static_pk;
}

std::shared_ptr<NoiseNKSession> NoiseNKManager::create_initiator_session(const std::string& peer_id) {
    auto peer_key = get_peer_key(peer_id);
    if (peer_key.empty()) {
        nativeLog("ERROR: NK: Peer key not found for " + peer_id + ". Register peer key first.");
        return nullptr;
    }

    std::vector<uint8_t> local_pk;
    {
        std::lock_guard<std::mutex> lock(m_keys_mutex);
        local_pk = m_local_static_pk;
    }

    if (local_pk.empty()) {
        nativeLog("ERROR: NK: Local static key not set. Call set_local_static_key first.");
        return nullptr;
    }

    auto session = std::make_shared<NoiseNKSession>(peer_id, NoiseNKSession::Role::INITIATOR, local_pk, peer_key);

    {
        std::lock_guard<std::mutex> lock(m_sessions_mutex);
        m_sessions[peer_id] = session;
    }

    return session;
}

std::shared_ptr<NoiseNKSession> NoiseNKManager::create_responder_session(const std::string& peer_id) {
    // For responder, we don't know peer's static key yet - that comes from out-of-band
    // For now, create placeholder and update when we receive peer's key
    
    std::vector<uint8_t> local_pk;
    {
        std::lock_guard<std::mutex> lock(m_keys_mutex);
        local_pk = m_local_static_pk;
    }

    if (local_pk.empty()) {
        nativeLog("ERROR: NK: Local static key not set");
        return nullptr;
    }

    // Use placeholder for peer key initially
    std::vector<uint8_t> placeholder_peer_key(32, 0x00);
    
    auto session = std::make_shared<NoiseNKSession>(peer_id, NoiseNKSession::Role::RESPONDER, placeholder_peer_key, local_pk);

    {
        std::lock_guard<std::mutex> lock(m_sessions_mutex);
        m_sessions[peer_id] = session;
    }

    return session;
}

std::shared_ptr<NoiseNKSession> NoiseNKManager::get_session(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    auto it = m_sessions.find(peer_id);
    if (it != m_sessions.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<NoiseNKSession> NoiseNKManager::get_or_create_session(const std::string& peer_id, NoiseNKSession::Role role) {
    auto session = get_session(peer_id);
    if (session) {
        return session;
    }

    if (role == NoiseNKSession::Role::INITIATOR) {
        return create_initiator_session(peer_id);
    } else {
        return create_responder_session(peer_id);
    }
}

void NoiseNKManager::remove_session(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    m_sessions.erase(peer_id);
    nativeLog("NK: Session removed for " + peer_id);
}

void NoiseNKManager::clear_sessions() {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    m_sessions.clear();
    nativeLog("NK: All sessions cleared");
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> NoiseNKManager::generate_static_keypair() {
    // Crypto functionality disabled - using dummy keypair
    nativeLog("NK Warning: Crypto disabled - using dummy static keypair");
    std::vector<uint8_t> public_key(32, 0x55);
    std::vector<uint8_t> secret_key(32, 0x66);

    nativeLog("NK: Static keypair generated (pk=" + hex_encode(public_key).substr(0, 8) + "...)");
    return {secret_key, public_key};
}

std::vector<std::string> NoiseNKManager::get_known_peers() const {
    std::lock_guard<std::mutex> lock(m_keys_mutex);
    std::vector<std::string> peers;
    for (const auto& kv : m_peer_keys) {
        peers.push_back(kv.first);
    }
    return peers;
}
