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

[[maybe_unused]] static std::vector<uint8_t> hex_decode(const std::string& hex) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        const std::string byte_string = hex.substr(i, 2);
        const uint8_t byte = static_cast<uint8_t>(strtol(byte_string.c_str(), nullptr, 16));
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
    const std::vector<uint8_t>& peer_ephemeral_or_static_pk,
    const std::vector<uint8_t>& local_static_pk,
    const std::vector<uint8_t>& local_static_sk
)
    : m_peer_id(peer_id),
      m_role(role),
      m_state(State::NEW),
      m_responder_static_pk(role == Role::INITIATOR ? peer_ephemeral_or_static_pk : local_static_pk),
      m_responder_static_sk(role == Role::RESPONDER ? local_static_sk : std::vector<uint8_t>{}),
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

    LOG_DEBUG("NK: Session created for " + peer_id + " (role=" + (role == Role::INITIATOR ? "INITIATOR" : "RESPONDER") + ", sid=" + m_session_id + ")");
}

std::vector<uint8_t> NoiseNKSession::generate_ephemeral_keypair() {
    int init_res = sodium_init();
    if (init_res < 0) {
        return {};
    }

    unsigned char sk_buf[crypto_box_SECRETKEYBYTES];
    unsigned char pk_buf[crypto_box_PUBLICKEYBYTES];

    int res = crypto_box_keypair(pk_buf, sk_buf);
    
    if (res != 0) {
        return {};
    }
    
    m_local_ephemeral_sk.assign(sk_buf, sk_buf + crypto_box_SECRETKEYBYTES);
    m_local_ephemeral_pk.assign(pk_buf, pk_buf + crypto_box_PUBLICKEYBYTES);
    return m_local_ephemeral_pk;
}

void NoiseNKSession::perform_dh(
    const std::vector<uint8_t>& secret_key,
    const std::vector<uint8_t>& public_key,
    std::vector<uint8_t>& result
) {
    result.resize(32);
    if (crypto_scalarmult(result.data(), secret_key.data(), public_key.data()) != 0) {
        LOG_DEBUG("NK Error: crypto_scalarmult failed");
        result.assign(32, 0);
    }
}

void NoiseNKSession::derive_keys() {
    LOG_DEBUG("NK_DEBUG: derive_keys() START");
    unsigned char ck[32];
    unsigned char h[32];
    std::string protocol_name = "Noise_NK_25519_ChaChaPoly_SHA256";
    std::string prologue = "";

    // h = SHA256(protocol_name || prologue)
    std::vector<uint8_t> proto_concat(protocol_name.begin(), protocol_name.end());
    proto_concat.insert(proto_concat.end(), prologue.begin(), prologue.end());
    crypto_hash_sha256(h, proto_concat.data(), proto_concat.size());
    memcpy(ck, h, 32);
    LOG_DEBUG("NK_DEBUG: derive_keys() - protocol hash done");

    // Mix responder static key into handshake hash
    LOG_DEBUG("NK_DEBUG: derive_keys() - m_responder_static_pk size=" + std::to_string(m_responder_static_pk.size()));
    if (m_responder_static_pk.empty()) {
        LOG_DEBUG("NK_DEBUG ERROR: m_responder_static_pk is EMPTY!");
        return;
    }
    crypto_hash_sha256(h, m_responder_static_pk.data(), m_responder_static_pk.size());
    memcpy(ck, h, 32);
    LOG_DEBUG("NK_DEBUG: derive_keys() - responder static pk mixed");

    // DH results: ee, es
    std::vector<uint8_t> dh_results;

    // DH(ephemeral, ephemeral)
    LOG_DEBUG("NK_DEBUG: derive_keys() - m_local_ephemeral_sk size=" + std::to_string(m_local_ephemeral_sk.size()) + ", m_peer_ephemeral_pk size=" + std::to_string(m_peer_ephemeral_pk.size()));
    std::vector<uint8_t> dh_ee(32);
    perform_dh(m_local_ephemeral_sk, m_peer_ephemeral_pk, dh_ee);
    LOG_DEBUG("NK_DEBUG: derive_keys() - DH_ee done");
    dh_results.insert(dh_results.end(), dh_ee.begin(), dh_ee.end());

    // DH(ephemeral_initiator, static_responder) - same calculation for both roles
    // In NK pattern: es = DH(e_i, s_r) where e_i is initiator's ephemeral, s_r is responder's static
    std::vector<uint8_t> dh_es(32);
    if (m_role == Role::INITIATOR) {
        // Initiator: DH(e_i.sk, s_r.pk) - we have our ephemeral secret, peer's static public
        LOG_DEBUG("NK_DEBUG: derive_keys() - INITIATOR DH_es");
        perform_dh(m_local_ephemeral_sk, m_responder_static_pk, dh_es);
    } else {
        // Responder: DH(s_r.sk, e_i.pk) - we have our static secret, peer's ephemeral public
        // This produces the same shared secret due to DH commutativity
        LOG_DEBUG("NK_DEBUG: derive_keys() - RESPONDER DH_es, m_responder_static_sk size=" + std::to_string(m_responder_static_sk.size()));
        if (m_responder_static_sk.empty()) {
            LOG_DEBUG("NK_DEBUG ERROR: m_responder_static_sk is EMPTY!");
            return;
        }
        perform_dh(m_responder_static_sk, m_peer_ephemeral_pk, dh_es);
    }
    LOG_DEBUG("NK_DEBUG: derive_keys() - DH_es done");
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

    LOG_DEBUG("NK: Keys derived (send_key=" + hex_encode(m_send_key).substr(0, 8) + "..., recv_key=" + hex_encode(m_recv_key).substr(0, 8) + "...)");
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
        LOG_ERROR("ERROR: NK: Invalid key or nonce size for encryption");
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
        LOG_ERROR("ERROR: NK: Invalid key or nonce size for decryption");
        return {};
    }

    if (ciphertext.size() < 16) {
        LOG_ERROR("ERROR: NK: Ciphertext too short (no auth tag)");
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
        LOG_ERROR("ERROR: NK: Decryption failed (auth tag mismatch)");
        return {};
    }
    plaintext.resize(plen);
    return plaintext;
}

std::vector<uint8_t> NoiseNKSession::start_handshake() {
    if (m_role != Role::INITIATOR) {
        LOG_ERROR("ERROR: NK: Only initiator can start handshake");
        return {};
    }

    if (m_state != State::NEW) {
        LOG_ERROR("ERROR: NK: Cannot start handshake - session already started");
        return {};
    }

    // Generate ephemeral keypair
    auto eph_pk = generate_ephemeral_keypair();
    LOG_DEBUG("NK_DEBUG: start_handshake - generate_ephemeral_keypair returned");
    if (eph_pk.empty()) {
        m_state = State::FAILED;
        return {};
    }

    // Message 1: e
    // Contains: ephemeral public key (32 bytes)
    LOG_DEBUG("NK_DEBUG: start_handshake - copying m_local_ephemeral_pk");
    std::vector<uint8_t> msg1 = m_local_ephemeral_pk;
    LOG_DEBUG("NK_DEBUG: start_handshake - m_local_ephemeral_pk copied");

    m_state = State::HANDSHAKE_1;
    m_handshake_step = 1;

    LOG_DEBUG("NK: Handshake message 1 sent (e, " + std::to_string(msg1.size()) + " bytes)");
    return msg1;
}

std::vector<uint8_t> NoiseNKSession::process_handshake(const std::vector<uint8_t>& msg) {
    LOG_DEBUG("NK_DEBUG: process_handshake called. State=" + std::to_string((int)m_state) + ", msg size=" + std::to_string(msg.size()));
    if (m_state == State::FAILED || m_state == State::READY) {
        LOG_ERROR("ERROR: NK: Cannot process handshake in state " + std::to_string((int)m_state));
        return {};
    }

    try {
        if (m_state == State::NEW) {
            LOG_DEBUG("NK_DEBUG: Processing message 1 (Responder)");
            // Responder: Process message 1 (e)
            if (msg.size() != 32) {
                LOG_ERROR("ERROR: NK: Message 1 invalid size (expected 32, got " + std::to_string(msg.size()) + ")");
                m_state = State::FAILED;
                return {};
            }

            m_peer_ephemeral_pk.assign(msg.begin(), msg.end());
            m_state = State::HANDSHAKE_1;
            m_handshake_step = 1;

            LOG_DEBUG("NK_DEBUG: Generating ephemeral keypair");
            // Generate our ephemeral keypair
            auto eph_pk = generate_ephemeral_keypair();
            if (eph_pk.empty()) {
                LOG_DEBUG("NK_DEBUG: Failed to generate ephemeral keypair");
                m_state = State::FAILED;
                return {};
            }
            LOG_DEBUG("NK_DEBUG: Ephemeral keypair generated");

            // Prepare response: e
            std::vector<uint8_t> msg2 = m_local_ephemeral_pk;

            // NK is a 2-message pattern: after responder sends Message 2, 
            // both sides have all the DH values needed to derive keys.
            // Derive keys NOW so responder is READY when Message 2 is sent.
            derive_keys();

            LOG_DEBUG("NK: Handshake message 1 received, message 2 prepared (e, 32 bytes), keys derived - READY");
            m_state = State::READY;
            m_handshake_step = 2;

            return msg2;

        } else if (m_state == State::HANDSHAKE_1) {
            // Initiator: Process message 2 (e)
            if (msg.size() != 32) {
                LOG_ERROR("ERROR: NK: Message 2 invalid size (expected 32, got " + std::to_string(msg.size()) + ")");
                m_state = State::FAILED;
                return {};
            }

            m_peer_ephemeral_pk.assign(msg.begin(), msg.end());

            // Derive keys from ee and es DH operations
            derive_keys();

            m_state = State::READY;
            m_handshake_step = 2;

            LOG_DEBUG("NK: Handshake message 2 received, keys derived, ready for communication");
            // NK is a 2-message pattern - no Message 3 needed
            return {};
        }
        // Note: HANDSHAKE_2 state is no longer used - responder becomes READY immediately after sending msg2

        LOG_ERROR("ERROR: NK: Invalid handshake state");
        m_state = State::FAILED;
        return {};

    } catch (const std::exception& e) {
        LOG_ERROR("ERROR: NK: Exception in process_handshake: " + std::string(e.what()));
        m_state = State::FAILED;
        return {};
    }
}

std::vector<uint8_t> NoiseNKSession::encrypt(const std::vector<uint8_t>& plaintext) {
    std::lock_guard<std::mutex> lock(m_op_mutex);
    if (!is_ready()) {
        LOG_ERROR("ERROR: NK: Cannot encrypt - handshake not complete");
        return {};
    }

    auto ciphertext = chacha20poly1305_encrypt(m_send_key, m_send_nonce, plaintext);
    if (!ciphertext.empty()) {
        // v2 wire format: nonce[12] || ciphertext||tag. The receiver reads the
        // nonce from the frame instead of guessing a synchronized counter, so a
        // single lost/reordered datagram no longer desyncs the stream (v1 bug:
        // one UDP loss permanently broke decryption for the rest of the session).
        std::vector<uint8_t> framed;
        framed.reserve(m_send_nonce.size() + ciphertext.size());
        framed.insert(framed.end(), m_send_nonce.begin(), m_send_nonce.end());
        framed.insert(framed.end(), ciphertext.begin(), ciphertext.end());
        increment_nonce(m_send_nonce);
        m_send_counter++;
        return framed;
    }
    return ciphertext;
}

std::vector<uint8_t> NoiseNKSession::decrypt(const std::vector<uint8_t>& ciphertext,
                                             bool* replay_drop) {
    std::lock_guard<std::mutex> lock(m_op_mutex);
    if (replay_drop) *replay_drop = false;
    if (!is_ready()) {
        LOG_ERROR("ERROR: NK: Cannot decrypt - handshake not complete");
        return {};
    }

    static constexpr size_t kNonceLen = 12;
    static constexpr size_t kTagLen = 16;  // Poly1305 tag
    static constexpr size_t kMinV2 = kNonceLen + kTagLen;

    if (ciphertext.size() >= kMinV2) {
        // v2 frame: explicit nonce prefix + replay window check.
        const std::vector<uint8_t> explicit_nonce(ciphertext.begin(),
                                                  ciphertext.begin() + kNonceLen);
        const std::vector<uint8_t> body(ciphertext.begin() + kNonceLen,
                                        ciphertext.end());
        const uint64_t seq = nonce_counter_le64(explicit_nonce);
        if (accept_recv_seq(seq)) {
            auto plaintext = chacha20poly1305_decrypt(m_recv_key, explicit_nonce, body);
            if (!plaintext.empty()) {
                m_recv_counter++;
                return plaintext;
            }
            // Authenticated decryption failed -> this is a REAL auth failure,
            // not a replay; fall through to the v1 attempt (interop) below.
        } else {
            // The anti-replay window rejected this counter: a duplicate or
            // replay. Tentatively mark so that if no v1 fallback succeeds we
            // report it as a benign drop rather than an auth failure.
            if (replay_drop) *replay_drop = true;
        }
        // Fall through to the v1 attempt so mixed-version peers interoperate.
    }

    // v1 legacy frame: implicit synchronized counter nonce.
    auto plaintext = chacha20poly1305_decrypt(m_recv_key, m_recv_nonce, ciphertext);
    if (!plaintext.empty()) {
        increment_nonce(m_recv_nonce);
        m_recv_counter++;
        if (replay_drop) *replay_drop = false;
    }
    return plaintext;
}

uint64_t NoiseNKSession::nonce_counter_le64(const std::vector<uint8_t>& nonce) {
    // increment_nonce() treats the 96-bit nonce as little-endian starting at
    // byte 0; the low 64 bits dominate for any realistic message volume.
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        if (i < static_cast<int>(nonce.size())) {
            v = (v << 8) | nonce[i];
        }
    }
    return v;
}

bool NoiseNKSession::accept_recv_seq(uint64_t seq) {
    // RFC-6347-style anti-replay window: accept a counter if it is newer than
    // everything seen, or within 64 counters below the newest and not yet used.
    if (!m_seen_any_seq || seq > m_highest_recv_seq) {
        const uint64_t advance = m_seen_any_seq ? (seq - m_highest_recv_seq) : 0;
        if (!m_seen_any_seq) {
            m_recv_window = 0;              // first v2 frame on this session
        } else if (advance >= 64) {
            m_recv_window = 0;              // window slid entirely past old seqs
        } else {
            m_recv_window <<= advance;      // shift bits up, dropping oldest
        }
        m_highest_recv_seq = seq;
        m_recv_window |= 1ULL;              // mark current highest as seen
        m_seen_any_seq = true;
        return true;
    }
    if (seq + 64 <= m_highest_recv_seq) {
        return false;                       // too old — outside the window
    }
    const uint64_t bit = 1ULL << (m_highest_recv_seq - seq);
    if (m_recv_window & bit) {
        return false;                       // duplicate within window
    }
    m_recv_window |= bit;
    return true;
}

// ============================================================================
// Transport key derivation (per-session forward secrecy)
// ============================================================================

bool NoiseNKSession::get_transport_keys(std::vector<uint8_t>& send_key_out,
                                         std::vector<uint8_t>& recv_key_out) const {
    if (m_state != State::READY) return false;
    if (m_send_key.size() < 32 || m_recv_key.size() < 32) return false;

    constexpr char kCtx[] = "litep2p!"; // crypto_kdf_CONTEXTBYTES = 8

    send_key_out.resize(32);
    recv_key_out.resize(32);

    // IMPORTANT: use the SAME subkey id for both directions. The send/recv
    // distinction comes from which Noise key (m_send_key vs m_recv_key) is
    // fed in, not from the subkey id. Noise NK swaps send/recv keys between
    // peers (our send key == peer's recv key), so using different subkey ids
    // here would make the two peers derive mismatched transport keys.
    if (crypto_kdf_derive_from_key(send_key_out.data(), 32, 1, kCtx, m_send_key.data()) != 0) {
        return false;
    }
    if (crypto_kdf_derive_from_key(recv_key_out.data(), 32, 1, kCtx, m_recv_key.data()) != 0) {
        return false;
    }
    return true;
}

// ============================================================================
// NoiseNKManager Implementation
// ============================================================================

NoiseNKManager::NoiseNKManager() {
    LOG_DEBUG("NK: Manager initialized");
}

void NoiseNKManager::register_peer_key(const std::string& peer_id, const std::vector<uint8_t>& static_pk) {
    if (static_pk.size() != 32) {
        LOG_ERROR("ERROR: NK: Peer key must be 32 bytes, got " + std::to_string(static_pk.size()));
        return;
    }
    
    {
        std::lock_guard<std::mutex> lock(m_keys_mutex);
        m_peer_keys[peer_id] = static_pk;
    }
    LOG_DEBUG("NK: Peer key registered for " + peer_id + " (key=" + hex_encode(static_pk).substr(0, 8) + "...)");
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
        LOG_ERROR("ERROR: NK: Static key must be 32 bytes");
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_keys_mutex);
    m_local_static_sk = static_sk;
    m_local_static_pk = static_pk;
    LOG_DEBUG("NK: Local static key set (pk=" + hex_encode(static_pk).substr(0, 8) + "...)");
}

std::vector<uint8_t> NoiseNKManager::get_local_static_pk() const {
    std::lock_guard<std::mutex> lock(m_keys_mutex);
    return m_local_static_pk;
}

std::shared_ptr<NoiseNKSession> NoiseNKManager::create_initiator_session(const std::string& peer_id) {
    auto peer_static_pk = get_peer_key(peer_id);
    if (peer_static_pk.empty()) {
        LOG_ERROR("ERROR: NK: Peer static key not found for " + peer_id + " (register peer key first)");
        return nullptr;
    }

    std::vector<uint8_t> local_pk;
    {
        std::lock_guard<std::mutex> lock(m_keys_mutex);
        local_pk = m_local_static_pk;
    }

    if (local_pk.empty()) {
        LOG_ERROR("ERROR: NK: Local static key not set. Call set_local_static_key first.");
        return nullptr;
    }

    // Initiator: peer_static_pk is responder's static public key, local_pk is our static public key (not used in NK)
    // The initiator doesn't need a static secret key in NK pattern
    auto session = std::make_shared<NoiseNKSession>(peer_id, NoiseNKSession::Role::INITIATOR, peer_static_pk, local_pk);

    {
        std::lock_guard<std::mutex> lock(m_sessions_mutex);
        m_sessions[peer_id] = session;
    }
    
    LOG_DEBUG("NK_DEBUG: create_initiator_session created a session");

    return session;
}

std::shared_ptr<NoiseNKSession> NoiseNKManager::create_responder_session(const std::string& peer_id) {
    std::vector<uint8_t> local_pk, local_sk;
    {
        std::lock_guard<std::mutex> lock(m_keys_mutex);
        local_pk = m_local_static_pk;
        local_sk = m_local_static_sk;
    }

    if (local_pk.empty() || local_sk.empty()) {
        LOG_ERROR("ERROR: NK: Local static keypair not set");
        return nullptr;
    }

    // Get peer's public key from registered keys (this is the initiator's static public key)
    // Note: In standard NK pattern, initiator doesn't have a static key, but we use it for peer identification
    auto peer_key = get_peer_key(peer_id);
    if (peer_key.empty()) {
        LOG_WARN("WARN: NK: Peer key not found for " + peer_id + " - peer identification may fail");
    }
    
    // Responder: local_pk is our static public key, local_sk is our static secret key
    // peer_key is not used in NK pattern DH, but may be used for identification
    auto session = std::make_shared<NoiseNKSession>(peer_id, NoiseNKSession::Role::RESPONDER, peer_key, local_pk, local_sk);

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
        auto s = create_initiator_session(peer_id);
        LOG_DEBUG("NK_DEBUG: get_or_create_session (INITIATOR) completed");
        return s;
    } else {
        return create_responder_session(peer_id);
    }
}

void NoiseNKManager::remove_session(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    m_sessions.erase(peer_id);
    LOG_DEBUG("NK: Session removed for " + peer_id);
}

void NoiseNKManager::clear_sessions() {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    m_sessions.clear();
    LOG_DEBUG("NK: All sessions cleared");
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> NoiseNKManager::generate_static_keypair() {
    if (sodium_init() < 0) {
        LOG_ERROR("ERROR: NK: libsodium initialization failed while generating static keypair");
        return {std::vector<uint8_t>(), std::vector<uint8_t>()};
    }

    std::vector<uint8_t> public_key(crypto_box_PUBLICKEYBYTES, 0x00);
    std::vector<uint8_t> secret_key(crypto_box_SECRETKEYBYTES, 0x00);

    if (crypto_box_keypair(public_key.data(), secret_key.data()) != 0) {
        LOG_ERROR("ERROR: NK: crypto_box_keypair failed while generating static keypair");
        return {std::vector<uint8_t>(), std::vector<uint8_t>()};
    }

    LOG_DEBUG("NK: Static keypair generated (pk=" + hex_encode(public_key).substr(0, 8) + "...)");
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
