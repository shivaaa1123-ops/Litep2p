#include "secure_session.h"
#include "logger.h"
#include <cstdio>

namespace {
constexpr size_t kCurve25519KeySize = 32;
}

SecureSession::SecureSession(const std::string& peer_id,
                             NoiseNKSession::Role role,
                             NoiseNKManager* manager,
                             NoiseKeyStore* key_store)
    : m_peer_id(peer_id),
      m_role(role),
      m_noise_manager(manager),
      m_key_store(key_store),
      m_handshake_initiated(false) {
    if (m_noise_manager == nullptr || m_key_store == nullptr) {
        nativeLog("SecureSession ERROR: Noise backend not configured for peer " + peer_id);
    }
}

SecureSession::~SecureSession() = default;

std::shared_ptr<NoiseNKSession> SecureSession::ensure_session() {
    if (!m_noise_manager) {
        return nullptr;
    }

    if (!m_noise_session) {
        m_noise_session = m_noise_manager->get_or_create_session(m_peer_id, m_role);
        if (!m_noise_session) {
            nativeLog("SecureSession ERROR: Failed to acquire Noise NK session for peer " + m_peer_id);
        }
    }
    return m_noise_session;
}

std::string SecureSession::vector_to_string(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return {};
    }
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

std::vector<uint8_t> SecureSession::string_to_vector(const std::string& data) {
    return std::vector<uint8_t>(data.begin(), data.end());
}

std::string SecureSession::start_handshake() {
    if (m_handshake_initiated) {
        nativeLog("SecureSession: Handshake already initiated for " + m_peer_id);
        return {};
    }

    auto session = ensure_session();
    if (!session) {
        return {};
    }

    m_handshake_initiated = true;
    auto payload = session->start_handshake();
    if (payload.empty()) {
        nativeLog("SecureSession ERROR: Failed to initiate Noise NK handshake for " + m_peer_id);
        return {};
    }

    nativeLog("SecureSession: Handshake initiated for " + m_peer_id +
              " (message size: " + std::to_string(payload.size()) + " bytes)");
    return vector_to_string(payload);
}

std::string SecureSession::process_handshake(const std::string& message) {
    auto session = ensure_session();
    if (!session) {
        return {};
    }

    auto response = session->process_handshake(string_to_vector(message));

    if (session->is_ready()) {
        nativeLog("SecureSession: Handshake complete for " + m_peer_id);
    } else if (response.empty()) {
        nativeLog("SecureSession ERROR: Handshake stalled for " + m_peer_id);
    }

    return vector_to_string(response);
}

bool SecureSession::is_ready() const {
    auto session = m_noise_session;
    if (!session && m_noise_manager) {
        session = m_noise_manager->get_session(m_peer_id);
        if (session) {
            m_noise_session = session;
        }
    }
    return session && session->is_ready();
}

std::string SecureSession::send_message(const std::string& plaintext) {
    auto session = ensure_session();
    if (!session || !session->is_ready()) {
        nativeLog("SecureSession ERROR: Session not ready for send to " + m_peer_id);
        return {};
    }

    auto ciphertext = session->encrypt(string_to_vector(plaintext));
    if (ciphertext.empty() && !plaintext.empty()) {
        nativeLog("SecureSession ERROR: Failed to encrypt message for " + m_peer_id);
        return {};
    }

    return vector_to_string(ciphertext);
}

std::string SecureSession::receive_message(const std::string& ciphertext) {
    auto session = ensure_session();
    if (!session || !session->is_ready()) {
        nativeLog("SecureSession ERROR: Session not ready for receive from " + m_peer_id);
        return {};
    }

    auto plaintext = session->decrypt(string_to_vector(ciphertext));
    if (plaintext.empty() && !ciphertext.empty()) {
        nativeLog("SecureSession ERROR: Failed to decrypt message from " + m_peer_id);
        return {};
    }

    return vector_to_string(plaintext);
}

std::string SecureSession::get_status() const {
    std::string status = "Peer: " + m_peer_id + " | ";

    auto session = m_noise_session;
    if (!session && m_noise_manager) {
        session = m_noise_manager->get_session(m_peer_id);
        if (session) {
            m_noise_session = session;
        }
    }

    if (!session) {
        status += "Status: NOT_INITIALIZED";
    } else {
        switch (session->get_state()) {
            case NoiseNKSession::State::NEW:
                status += "Status: NEW";
                break;
            case NoiseNKSession::State::HANDSHAKE_1:
                status += "Status: HANDSHAKE_STEP_1";
                break;
            case NoiseNKSession::State::HANDSHAKE_2:
                status += "Status: HANDSHAKE_STEP_2";
                break;
            case NoiseNKSession::State::HANDSHAKE_3:
                status += "Status: HANDSHAKE_STEP_3";
                break;
            case NoiseNKSession::State::READY:
                status += "Status: READY";
                break;
            case NoiseNKSession::State::FAILED:
                status += "Status: FAILED";
                break;
        }
    }

    return status;
}

// SecureSessionManager implementation
SecureSessionManager::SecureSessionManager()
    : m_noise_manager(nullptr),
      m_key_store(nullptr) {}

SecureSessionManager::~SecureSessionManager() = default;

void SecureSessionManager::set_noise_backend(NoiseNKManager* manager, NoiseKeyStore* key_store) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_noise_manager = manager;
    m_key_store = key_store;

    if (!m_noise_manager || !m_key_store) {
        return;
    }

    if (m_key_store->has_local_static_key()) {
        auto local_sk = m_key_store->get_local_static_private_key();
        auto local_pk = m_key_store->get_local_static_public_key();
        if (local_sk.size() == kCurve25519KeySize && local_pk.size() == kCurve25519KeySize) {
            m_noise_manager->set_local_static_key(local_sk, local_pk);
        }
    }

    auto peer_ids = m_key_store->get_all_peer_ids();
    for (const auto& id : peer_ids) {
        auto key = m_key_store->get_peer_key(id);
        if (!key.empty()) {
            m_noise_manager->register_peer_key(id, key);
        }
    }
}

std::shared_ptr<SecureSession> SecureSessionManager::get_or_create_session(
    const std::string& peer_id,
    NoiseNKSession::Role role) {

    nativeLog("SSM_DEBUG: get_or_create_session called for " + peer_id);
    std::lock_guard<std::mutex> lock(m_mutex);
    nativeLog("SSM_DEBUG: Acquired lock");

    auto existing = m_sessions.find(peer_id);
    if (existing != m_sessions.end()) {
        nativeLog("SSM_DEBUG: Found existing session");
        return existing->second;
    }

    if (!m_noise_manager || !m_key_store) {
        nativeLog("SecureSessionManager ERROR: Noise backend not configured when requesting session for " + peer_id);
        return nullptr;
    }

    if (!m_key_store->has_local_static_key()) {
        if (!m_key_store->generate_and_store_local_key()) {
            nativeLog("SecureSessionManager ERROR: Failed to generate local static key");
            return nullptr;
        }
    }

    auto local_sk = m_key_store->get_local_static_private_key();
    auto local_pk = m_key_store->get_local_static_public_key();
    if (local_sk.size() != kCurve25519KeySize || local_pk.size() != kCurve25519KeySize) {
        nativeLog("SecureSessionManager ERROR: Local static key invalid size");
        return nullptr;
    }
    m_noise_manager->set_local_static_key(local_sk, local_pk);

    auto peer_key = m_key_store->get_peer_key(peer_id);
    if (peer_key.empty()) {
        nativeLog("SecureSessionManager ERROR: Missing peer static key for session with " + peer_id);
        return nullptr;
    }
    m_noise_manager->register_peer_key(peer_id, peer_key);

    nativeLog("SSM_DEBUG: Creating new SecureSession");
    auto session = std::make_shared<SecureSession>(peer_id, role, m_noise_manager, m_key_store);
    nativeLog("SSM_DEBUG: Emplacing session");
    m_sessions.emplace(peer_id, session);
    nativeLog("SSM_DEBUG: Session created and emplaced");

    return session;
}

void SecureSessionManager::remove_session(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_sessions.erase(peer_id);
    if (m_noise_manager) {
        m_noise_manager->remove_session(peer_id);
    }
}

std::shared_ptr<SecureSession> SecureSessionManager::get_session(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_sessions.find(peer_id);
    if (it != m_sessions.end()) {
        return it->second;
    }
    return nullptr;
}

bool SecureSessionManager::is_session_ready(const std::string& peer_id) {
    auto session = get_session(peer_id);
    return session && session->is_ready();
}

void SecureSessionManager::clear_all() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_sessions.clear();
    if (m_noise_manager) {
        m_noise_manager->clear_sessions();
    }
}
