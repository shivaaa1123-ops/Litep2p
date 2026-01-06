#include "noise_key_store.h"
#include "logger.h"
#include "config_manager.h"
#include <sodium.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace {

std::string resolve_keystore_file_path(const std::string& configured_path) {
    // The config value historically was a directory-ish string like "keystore".
    // Support both:
    //  - directory path (append a default file name)
    //  - explicit file path (ends with .json)
    const std::string base = configured_path.empty() ? std::string("keystore") : configured_path;
    std::filesystem::path p(base);

    const bool looks_like_file = p.has_extension() && p.extension() == ".json";
    if (looks_like_file) {
        return p.string();
    }

    return (p / "noise_keystore.json").string();
}

bool ensure_parent_dir(const std::string& file_path) {
    std::error_code ec;
    std::filesystem::path p(file_path);
    const auto parent = p.parent_path();
    if (parent.empty()) return true;
    if (std::filesystem::exists(parent, ec)) return true;
    return std::filesystem::create_directories(parent, ec);
}

} // namespace

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
    std::unique_lock<std::mutex> lock(m_mutex);

    // Resolve persistence file path once.
    if (m_storage_file_path.empty()) {
        const std::string configured = ConfigManager::getInstance().getKeyStorePath();
        m_storage_file_path = resolve_keystore_file_path(configured);
    }

    // Best-effort load.
    bool loaded_anything = false;
    try {
        std::ifstream in(m_storage_file_path);
        if (in.good()) {
            json j;
            in >> j;

            if (j.is_object()) {
                if (auto it = j.find("local_private_key_hex"); it != j.end() && it->is_string()) {
                    m_local_private_key = hex_to_bytes(it->get<std::string>());
                }
                if (auto it = j.find("local_public_key_hex"); it != j.end() && it->is_string()) {
                    m_local_public_key = hex_to_bytes(it->get<std::string>());
                }

                // Validate local keys (must both be 32 bytes).
                if (m_local_private_key.size() != 32 || m_local_public_key.size() != 32) {
                    m_local_private_key.clear();
                    m_local_public_key.clear();
                } else {
                    loaded_anything = true;
                }

                if (auto it = j.find("peer_keys"); it != j.end() && it->is_object()) {
                    for (auto& kv : it->items()) {
                        if (!kv.value().is_string()) continue;
                        auto key = hex_to_bytes(kv.value().get<std::string>());
                        if (key.size() != 32) continue;
                        m_peer_keys[kv.key()] = std::move(key);
                    }
                    if (!m_peer_keys.empty()) {
                        loaded_anything = true;
                    }
                }
            }

            nativeLog(
                "KeyStore: Initialized from storage (path=" + m_storage_file_path + ", peers=" +
                std::to_string(m_peer_keys.size()) + ")"
            );
        } else {
            nativeLog("KeyStore: No existing keystore file; will generate a local static key");
        }
    } catch (const std::exception& e) {
        nativeLog(std::string("ERROR: KeyStore: Failed to load keystore: ") + e.what());
        m_local_private_key.clear();
        m_local_public_key.clear();
        m_peer_keys.clear();
    }

    m_initialized = true;
    m_dirty = false;

    // Ensure local identity exists.
    if (m_local_public_key.empty()) {
        lock.unlock();
        return generate_and_store_local_key();
    }

    // If we loaded something, ensure the file path directory exists and re-save once
    // to normalize format (best-effort).
    lock.unlock();
    if (loaded_anything) {
        save();
    }
    return true;
}

bool NoiseKeyStore::save() {
    std::unique_lock<std::mutex> lock(m_mutex);

    if (!m_initialized) {
        nativeLog("WARN: KeyStore: save() called before initialize(); ignoring");
        return false;
    }

    if (!m_dirty) {
        return true; // Nothing to save
    }

    if (m_storage_file_path.empty()) {
        const std::string configured = ConfigManager::getInstance().getKeyStorePath();
        m_storage_file_path = resolve_keystore_file_path(configured);
    }

    const std::string path = m_storage_file_path;
    const std::string tmp_path = path + ".tmp";

    json j;
    j["version"] = 1;
    j["local_private_key_hex"] = bytes_to_hex(m_local_private_key);
    j["local_public_key_hex"] = bytes_to_hex(m_local_public_key);
    json peers = json::object();
    for (const auto& kv : m_peer_keys) {
        peers[kv.first] = bytes_to_hex(kv.second);
    }
    j["peer_keys"] = std::move(peers);

    // Drop the lock while doing I/O.
    lock.unlock();

    if (!ensure_parent_dir(path)) {
        nativeLog("ERROR: KeyStore: Failed to create keystore directory for " + path);
        return false;
    }

    try {
        {
            std::ofstream out(tmp_path, std::ios::trunc);
            if (!out.is_open()) {
                nativeLog("ERROR: KeyStore: Failed to open keystore file for writing: " + tmp_path);
                return false;
            }
            out << j.dump(2);
            if (!out.good()) {
                nativeLog("ERROR: KeyStore: Failed writing keystore file: " + tmp_path);
                return false;
            }
        }

        std::error_code ec;
        std::filesystem::rename(tmp_path, path, ec);
        if (ec) {
            // Windows-friendly fallback. (Also covers some Android/filesystem quirks.)
            std::filesystem::copy_file(tmp_path, path, std::filesystem::copy_options::overwrite_existing, ec);
            std::filesystem::remove(tmp_path, ec);
        }
    } catch (const std::exception& e) {
        nativeLog(std::string("ERROR: KeyStore: Exception while saving keystore: ") + e.what());
        return false;
    }

    lock.lock();
    m_dirty = false;
    nativeLog("KeyStore: Saved to persistent storage (path=" + path + ")");
    return true;
}

void NoiseKeyStore::set_local_static_key(const std::vector<uint8_t>& private_key, const std::vector<uint8_t>& public_key) {
    if (private_key.size() != 32 || public_key.size() != 32) {
        nativeLog("ERROR: KeyStore: Local keys must be 32 bytes");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_local_private_key = private_key;
        m_local_public_key = public_key;
        m_dirty = true;
    }

    nativeLog("KeyStore: Local static key set (pk=" + bytes_to_hex(public_key).substr(0, 8) + "...)");

    // Best-effort persistence.
    save();
}

std::vector<uint8_t> NoiseKeyStore::get_local_static_private_key() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_local_private_key;
}

std::vector<uint8_t> NoiseKeyStore::get_local_static_public_key() const {
    // nativeLog("KeyStore: Acquiring lock for get_local_static_public_key");
    std::lock_guard<std::mutex> lock(m_mutex);
    // nativeLog("KeyStore: Lock acquired for get_local_static_public_key");
    return m_local_public_key;
}

bool NoiseKeyStore::has_local_static_key() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return !m_local_private_key.empty() && !m_local_public_key.empty();
}

bool NoiseKeyStore::generate_and_store_local_key() {
    if (sodium_init() < 0) {
        nativeLog("ERROR: KeyStore: libsodium initialization failed while generating local key");
        return false;
    }

    std::vector<uint8_t> public_key(crypto_box_PUBLICKEYBYTES, 0x00);
    std::vector<uint8_t> private_key(crypto_box_SECRETKEYBYTES, 0x00);

    if (crypto_box_keypair(public_key.data(), private_key.data()) != 0) {
        nativeLog("ERROR: KeyStore: crypto_box_keypair failed while generating local key");
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_local_public_key = std::move(public_key);
        m_local_private_key = std::move(private_key);
        m_dirty = true;
    }

    nativeLog("KeyStore: Generated new local static keypair");
    return save();
}

void NoiseKeyStore::register_peer_key(const std::string& peer_id, const std::vector<uint8_t>& public_key) {
    if (public_key.size() != 32) {
        nativeLog("ERROR: KeyStore: Peer key must be 32 bytes, got " + std::to_string(public_key.size()));
        return;
    }
    
    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_peer_keys.find(peer_id);
        if (it != m_peer_keys.end() && it->second != public_key) {
            changed = true;
        }
        m_peer_keys[peer_id] = public_key;
        m_dirty = true;
    }

    if (changed) {
        nativeLog(
            "WARN: KeyStore: Peer key changed for " + peer_id + " (pk=" +
            bytes_to_hex(public_key).substr(0, 8) + "...)"
        );
    } else {
        nativeLog("KeyStore: Peer key registered for " + peer_id + " (pk=" + bytes_to_hex(public_key).substr(0, 8) + "...)");
    }

    // Best-effort persistence.
    save();
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
    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        removed = (m_peer_keys.erase(peer_id) > 0);
        if (removed) {
            m_dirty = true;
        }
    }
    if (removed) {
        nativeLog("KeyStore: Peer key removed for " + peer_id);
        save();
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
    bool had_any = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        had_any = !m_peer_keys.empty();
        if (had_any) {
            m_peer_keys.clear();
            m_dirty = true;
        }
    }
    if (had_any) {
        nativeLog("KeyStore: All peer keys cleared");
        save();
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
