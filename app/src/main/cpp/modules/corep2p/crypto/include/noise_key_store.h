#ifndef NOISE_KEY_STORE_H
#define NOISE_KEY_STORE_H

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <cstdint>

/**
 * Secure Key Storage for Noise NK
 * 
 * Handles storage and retrieval of:
 * - Local static private/public keypair
 * - Peer static public keys
 * 
 * In production, keys are stored in:
 * - Android Keystore (hardware-backed when available) for local keys
 * - SharedPreferences (encrypted with Android's EncryptedSharedPreferences) for peer keys
 * 
 * This C++ module provides the base implementation.
 * Actual encryption delegated to JNI bridge for Android Keystore access.
 */

class NoiseKeyStore {
public:
    NoiseKeyStore();
    ~NoiseKeyStore() = default;

    /**
     * Initialize key store from persistent storage
     * Loads saved keys from Android SharedPreferences via JNI
     */
    bool initialize();

    /**
     * Save key store to persistent storage
     * Saves to Android SharedPreferences (encrypted) via JNI
     */
    bool save();

    // =========== Local Static Key Operations ===========

    /**
     * Set local static private key
     * Typically called once at startup with generated or restored key
     * Should be stored in Android Keystore (hardware-backed)
     */
    void set_local_static_key(const std::vector<uint8_t>& private_key, const std::vector<uint8_t>& public_key);

    /**
     * Get local static private key
     * WARNING: Returns in-memory copy. Be careful with handling.
     */
    std::vector<uint8_t> get_local_static_private_key() const;

    /**
     * Get local static public key
     * Safe to share with peers - not secret
     */
    std::vector<uint8_t> get_local_static_public_key() const;

    /**
     * Check if local static key is set
     */
    bool has_local_static_key() const;

    /**
     * Generate new local static keypair
     * Replaces existing key. Saves to storage.
     */
    bool generate_and_store_local_key();

    // =========== Peer Key Operations ===========

    /**
     * Register peer's static public key
     * Must be done before initiating Noise NK handshake
     * Key is stored persistently
     */
    void register_peer_key(const std::string& peer_id, const std::vector<uint8_t>& public_key);

    /**
     * Get peer's static public key
     * Returns empty vector if not found
     */
    std::vector<uint8_t> get_peer_key(const std::string& peer_id) const;

    /**
     * Check if peer key is registered
     */
    bool has_peer_key(const std::string& peer_id) const;

    /**
     * Remove peer key (after peer deletion)
     */
    void remove_peer_key(const std::string& peer_id);

    /**
     * Get all registered peer IDs
     */
    std::vector<std::string> get_all_peer_ids() const;

    /**
     * Get count of registered peers
     */
    size_t get_peer_count() const;

    /**
     * Clear all peer keys (but keep local key)
     */
    void clear_peer_keys();

    // =========== Debug/Export ===========

    /**
     * Export all peer keys as hex-encoded strings
     * For debugging or backup purposes
     */
    std::map<std::string, std::string> export_peer_keys_hex() const;

    /**
     * Import peer keys from hex-encoded strings
     * For restoring from backup
     */
    bool import_peer_keys_hex(const std::map<std::string, std::string>& hex_keys);

private:
    mutable std::mutex m_mutex;

    // Resolved file path used for persistence (best-effort).
    // Note: On Android this should be set to an app-private directory (e.g., filesDir)
    // via ConfigManager so it is writable.
    std::string m_storage_file_path;

    // Local static keys (32 bytes each for Curve25519)
    std::vector<uint8_t> m_local_private_key;
    std::vector<uint8_t> m_local_public_key;

    // Registered peer static public keys
    std::map<std::string, std::vector<uint8_t>> m_peer_keys;

    // Persistence state
    bool m_initialized;
    bool m_dirty;  // True if changes need saving

    // Helper for hex encoding/decoding
    static std::string bytes_to_hex(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);
};

#endif // NOISE_KEY_STORE_H
