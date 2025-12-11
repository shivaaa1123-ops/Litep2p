#include "secure_session.h"
#include "logger.h"

SecureSession::SecureSession(const std::string& peer_id, NoiseSession::Role role)
    : m_peer_id(peer_id), m_handshake_initiated(false) {
    m_noise_session = std::make_unique<NoiseSession>(role, peer_id);
}

SecureSession::~SecureSession() = default;

std::string SecureSession::start_handshake() {
    if (m_handshake_initiated) {
        nativeLog("SecureSession: Handshake already initiated for " + m_peer_id);
        return "";
    }

    m_handshake_initiated = true;
    auto message = m_noise_session->initiate_handshake();
    
    if (message.empty()) {
        nativeLog("SecureSession Error: Failed to initiate handshake for " + m_peer_id);
        return "";
    }

    nativeLog("SecureSession: Handshake initiated for " + m_peer_id + 
              " (message size: " + std::to_string(message.length()) + " bytes)");
    return message;
}

std::string SecureSession::process_handshake(const std::string& message) {
    auto response = m_noise_session->process_handshake_message(message);
    
    if (m_noise_session->is_handshake_complete()) {
        nativeLog("SecureSession: Handshake complete for " + m_peer_id);
    } else if (response.empty()) {
        nativeLog("SecureSession Error: Handshake failed for " + m_peer_id + 
                  " - " + m_noise_session->get_error());
    }

    return response;
}

bool SecureSession::is_ready() const {
    return m_noise_session->is_handshake_complete();
}

std::string SecureSession::send_message(const std::string& plaintext) {
    if (!is_ready()) {
        nativeLog("SecureSession Error: Session not ready for " + m_peer_id);
        return "";
    }

    auto ciphertext = m_noise_session->encrypt_message(plaintext);
    if (ciphertext.empty()) {
        nativeLog("SecureSession Error: Failed to encrypt message for " + m_peer_id);
        return "";
    }

    return ciphertext;
}

std::string SecureSession::receive_message(const std::string& ciphertext) {
    if (!is_ready()) {
        nativeLog("SecureSession Error: Session not ready for " + m_peer_id);
        return "";
    }

    auto plaintext = m_noise_session->decrypt_message(ciphertext);
    if (plaintext.empty() && !ciphertext.empty()) {
        nativeLog("SecureSession Error: Failed to decrypt message from " + m_peer_id);
        return "";
    }

    return plaintext;
}

std::string SecureSession::get_status() const {
    std::string status = "Peer: " + m_peer_id + " | ";
    
    if (is_ready()) {
        status += "Status: READY";
    } else {
        status += "Status: HANDSHAKING";
    }

    return status;
}

// SecureSessionManager implementation
SecureSessionManager::SecureSessionManager() = default;
SecureSessionManager::~SecureSessionManager() = default;

std::shared_ptr<SecureSession> SecureSessionManager::get_or_create_session(
    const std::string& peer_id,
    NoiseSession::Role role) {
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_sessions.find(peer_id);
    if (it != m_sessions.end()) {
        return it->second;
    }

    auto session = std::make_shared<SecureSession>(peer_id, role);
    m_sessions[peer_id] = session;
    
    nativeLog("SecureSessionManager: Created new session for " + peer_id);
    return session;
}

void SecureSessionManager::remove_session(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_sessions.erase(peer_id);
    nativeLog("SecureSessionManager: Removed session for " + peer_id);
}

std::shared_ptr<SecureSession> SecureSessionManager::get_session(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_sessions.find(peer_id);
    return (it != m_sessions.end()) ? it->second : nullptr;
}

bool SecureSessionManager::is_session_ready(const std::string& peer_id) {
    auto session = get_session(peer_id);
    return session && session->is_ready();
}

void SecureSessionManager::clear_all() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_sessions.clear();
    nativeLog("SecureSessionManager: Cleared all sessions");
}
