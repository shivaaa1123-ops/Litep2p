#include "noise_key_store.h"
#include "logger.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

// Helper functions
std::string NoiseKeyStore::bytes_to_hex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    for (uint8_t byte : data) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return ss.str();
}

std::vector<uint8_t> NoiseKeyStore::hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        result.push_back(byte);
    }
    return result;
}

NoiseKeyStore::NoiseKeyStore() : m_initialized(false), m_dirty(false) {
    nativeLog("KeyStore: Initialized");
}

bool NoiseKeyStore::initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // In production, this would:
    // 1. Call JNI to read from Android SharedPreferences (encrypted)
    // 2. Load local static key from Android Keystore
    // 3. Load peer keys from SharedPreferences
    
    // For now, assume empty state and keys will be set programmatically
    m_initialized = true;
    nativeLog("KeyStore: Initialized from storage");
    return true;
}

bool NoiseKeyStore::save() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_dirty) {
        return true;  // Nothing to save
    }
    
    // In production, this would:
    // 1. Call JNI to save to Android SharedPreferences (encrypted)
    // 2. Save local static key to Android Keystore
    // 3. Save peer keys to SharedPreferences
    
    m_dirty = false;
    nativeLog("KeyStore: Saved to persistent storage");
    return true;
}

void NoiseKeyStore::set_local_static_key(const std::vector<uint8_t>& private_key, const std::vector<uint8_t>& public_key) {
    if (private_key.size() != 32 || public_key.size() != 32) {
        nativeLog("ERROR: KeyStore: Local keys must be 32 bytes");
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    m_local_private_key = private_key;
    m_local_public_key = public_key;
    m_dirty = true;
    
    nativeLog("KeyStore: Local static key set (pk=" + bytes_to_hex(public_key).substr(0, 8) + "...)");
}

std::vector<uint8_t> NoiseKeyStore::get_local_static_private_key() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_local_private_key;
}

std::vector<uint8_t> NoiseKeyStore::get_local_static_public_key() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_local_public_key;
}

bool NoiseKeyStore::has_local_static_key() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return !m_local_private_key.empty() && !m_local_public_key.empty();
}

bool NoiseKeyStore::generate_and_store_local_key() {
    // This would call JNI to generate key in Android Keystore
    // For now, this is a placeholder - actual generation happens in Java
    nativeLog("KeyStore: generate_and_store_local_key() - implement in Java via JNI");
    return false;
}

void NoiseKeyStore::register_peer_key(const std::string& peer_id, const std::vector<uint8_t>& public_key) {
    if (public_key.size() != 32) {
        nativeLog("ERROR: KeyStore: Peer key must be 32 bytes, got " + std::to_string(public_key.size()));
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    m_peer_keys[peer_id] = public_key;
    m_dirty = true;
    
    nativeLog("KeyStore: Peer key registered for " + peer_id + " (pk=" + bytes_to_hex(public_key).substr(0, 8) + "...)");
}

std::vector<uint8_t> NoiseKeyStore::get_peer_key(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_peer_keys.find(peer_id);
    if (it != m_peer_keys.end()) {
        return it->second;
    }
    return {};
}

bool NoiseKeyStore::has_peer_key(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_peer_keys.find(peer_id) != m_peer_keys.end();
}

void NoiseKeyStore::remove_peer_key(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_peer_keys.erase(peer_id) > 0) {
        m_dirty = true;
        nativeLog("KeyStore: Peer key removed for " + peer_id);
    }
}

std::vector<std::string> NoiseKeyStore::get_all_peer_ids() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> result;
    for (const auto& kv : m_peer_keys) {
        result.push_back(kv.first);
    }
    return result;
}

size_t NoiseKeyStore::get_peer_count() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_peer_keys.size();
}

void NoiseKeyStore::clear_peer_keys() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_peer_keys.empty()) {
        m_peer_keys.clear();
        m_dirty = true;
        nativeLog("KeyStore: All peer keys cleared");
    }
}

std::map<std::string, std::string> NoiseKeyStore::export_peer_keys_hex() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::map<std::string, std::string> result;
    for (const auto& kv : m_peer_keys) {
        result[kv.first] = bytes_to_hex(kv.second);
    }
    return result;
}

bool NoiseKeyStore::import_peer_keys_hex(const std::map<std::string, std::string>& hex_keys) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (const auto& kv : hex_keys) {
        auto key = hex_to_bytes(kv.second);
        if (key.size() != 32) {
            nativeLog("ERROR: KeyStore: Invalid peer key size during import for " + kv.first);
            return false;
        }
        m_peer_keys[kv.first] = key;
    }
    
    m_dirty = true;
    nativeLog("KeyStore: Imported " + std::to_string(hex_keys.size()) + " peer keys");
    return true;
}
